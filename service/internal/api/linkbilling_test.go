package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/attrbilling"
	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/oidc"
)

// fakeMarket stands in for the control plane's attribute marketplace. It
// records the bearer every call carried, because the whole point of
// "the inviter pays" is WHOSE token reaches the platform: the payer is
// resolved from it, so a call made with the app's identity would charge
// the wrong account.
type fakeMarket struct {
	*httptest.Server

	mu       sync.Mutex
	bearers  []string
	mints    []mintCall
	refuse   bool          // mint answers 400, as it does for an unfundable set
	grantTTL time.Duration // expiry handed back on a mint (negative = already lapsed)
}

type mintCall struct {
	ClientID   string   `json:"client_id"`
	Attributes []string `json:"attributes"`
	TTLSeconds int64    `json:"ttl_seconds"`
}

// marketCatalogue is the fixture catalogue: two priced gov attributes, a
// free one, and no entry at all for the self-asserted "name" a sharer
// has always been able to require. The assurance strings are the registry's
// own vocabulary, not the IdP's none/provider/gov ladder.
const marketCatalogue = `{"attributes":[
	{"key":"privasys:document_valid","namespace":"privasys","name":"document_valid","assurance":"gov_verified","price_credits":30},
	{"key":"privasys:family_name","namespace":"privasys","name":"family_name","assurance":"gov_verified","price_credits":10},
	{"key":"privasys:nickname","namespace":"privasys","name":"nickname","assurance":"self_asserted","price_credits":0}
]}`

func newFakeMarket(t *testing.T) *fakeMarket {
	t.Helper()
	m := &fakeMarket{grantTTL: time.Hour}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/attributes", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, marketCatalogue)
	})
	mux.HandleFunc("POST /api/v1/attribute-billing-grants/quote", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		var body struct {
			Attributes []string `json:"attributes"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		lines, total := m.price(body.Attributes)
		writeJSON(w, http.StatusOK, map[string]any{"attributes": lines, "total_credits": total})
	})
	mux.HandleFunc("POST /api/v1/attribute-billing-grants", func(w http.ResponseWriter, r *http.Request) {
		m.record(r)
		var call mintCall
		_ = json.NewDecoder(r.Body).Decode(&call)
		m.mu.Lock()
		m.mints = append(m.mints, call)
		n, refuse, ttl := len(m.mints), m.refuse, m.grantTTL
		m.mu.Unlock()
		if refuse {
			http.Error(w, "the chosen attributes are free; no billing grant is needed", http.StatusBadRequest)
			return
		}
		lines, total := m.price(call.Attributes)
		writeJSON(w, http.StatusOK, map[string]any{
			"id":             fmt.Sprintf("grant-%d", n),
			"expires_at":     time.Now().UTC().Add(ttl),
			"quoted_credits": total,
			"max_credits":    total,
			"attributes":     lines,
		})
	})
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

func (m *fakeMarket) record(r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bearers = append(m.bearers, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
}

// price mirrors the marketplace's own resolution so the test asserts
// against real numbers rather than a constant.
func (m *fakeMarket) price(keys []string) ([]map[string]any, int64) {
	var catalogue struct {
		Attributes []struct {
			Key          string `json:"key"`
			Namespace    string `json:"namespace"`
			Assurance    string `json:"assurance"`
			PriceCredits int64  `json:"price_credits"`
		} `json:"attributes"`
	}
	_ = json.Unmarshal([]byte(marketCatalogue), &catalogue)
	lines := make([]map[string]any, 0, len(keys))
	var total int64
	for _, k := range keys {
		for _, a := range catalogue.Attributes {
			if a.Key != k {
				continue
			}
			lines = append(lines, map[string]any{
				"key": a.Key, "namespace": a.Namespace,
				"assurance": a.Assurance, "price_credits": a.PriceCredits,
			})
			total += a.PriceCredits
		}
	}
	return lines, total
}

func (m *fakeMarket) lastBearer(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.bearers) == 0 {
		t.Fatal("marketplace was never called")
	}
	return m.bearers[len(m.bearers)-1]
}

// claimsVerifier stands in for the IdP after a funded disclosure: the
// recipient's token carries the proven attribute as a claim, which is
// the only place a paid attribute is ever read from.
type claimsVerifier struct {
	bySub map[string]map[string]any
}

func (v claimsVerifier) Verify(ctx context.Context, token string) (*oidc.Identity, error) {
	id, err := oidc.DevVerifier{}.Verify(ctx, token)
	if err != nil {
		return nil, err
	}
	id.Claims = v.bySub[id.Sub]
	return id, nil
}

// billedServer is a Drive wired to a fake marketplace, configured with
// the OAuth client its front end signs recipients in with.
func billedServer(t *testing.T) (*httptest.Server, *Server, *fakeMarket) {
	t.Helper()
	ts, srv := newTestServer(t)
	market := newFakeMarket(t)
	srv.InstallConfig(&config.Config{
		Mode:         config.ModeSovereign,
		MgmtBaseURL:  market.URL,
		OIDCClientID: "drive-web",
	})
	return ts, srv, market
}

func createLink(t *testing.T, url, tenantID, nodeID, owner, body string) map[string]any {
	t.Helper()
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", url, tenantID, nodeID), owner, body))
	if code != 201 {
		t.Fatalf("create link: %d %s", code, b)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func previewLink(t *testing.T, url, linkID, secret string) (int, map[string]any) {
	t.Helper()
	// No Authorization header: this is the pre-sign-in call.
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/v1/links/%s/preview", url, linkID),
		strings.NewReader(`{"secret":"`+secret+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	code, b := doReq(t, req)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return code, out
}

// The sharer's own token reaches the marketplace on both the catalogue
// and the quote, and the quote prices the set they actually chose.
func TestAttributeCatalogueAndQuoteUseTheSharersToken(t *testing.T) {
	ts, _, market := billedServer(t)
	const owner = "user-1"

	code, b := doReq(t, bearerReq(t, "GET", ts.URL+"/v1/attributes", owner, ""))
	if code != 200 {
		t.Fatalf("catalogue: %d %s", code, b)
	}
	if !strings.Contains(string(b), "privasys:document_valid") {
		t.Fatalf("catalogue not passed through: %s", b)
	}
	if got := market.lastBearer(t); got != "dev:"+owner+":"+owner+"@privasys.org" {
		t.Fatalf("catalogue carried %q, want the sharer's own token", got)
	}

	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/v1/attributes/quote", owner,
		`{"attributes":["privasys:document_valid","privasys:family_name"]}`))
	if code != 200 {
		t.Fatalf("quote: %d %s", code, b)
	}
	var quote struct {
		TotalCredits int64 `json:"total_credits"`
		Attributes   []struct {
			Key string `json:"key"`
		} `json:"attributes"`
	}
	if err := json.Unmarshal(b, &quote); err != nil {
		t.Fatal(err)
	}
	if quote.TotalCredits != 40 || len(quote.Attributes) != 2 {
		t.Fatalf("quote unexpected: %s", b)
	}
	if got := market.lastBearer(t); got != "dev:"+owner+":"+owner+"@privasys.org" {
		t.Fatalf("quote carried %q, want the sharer's own token", got)
	}
}

// Creating an attribute-gated share mints one billing grant, charged to
// the sharer, for the priced attributes only; the pre-sign-in preview
// then hands that grant to the visitor.
func TestShareLinkMintsABillingGrantForThePricedAttributes(t *testing.T) {
	ts, _, market := billedServer(t)
	const owner = "user-1"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)

	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["document_valid","name"]}`)
	if link["billing_state"] != billingFunded {
		t.Fatalf("billing_state = %v, want funded: %v", link["billing_state"], link)
	}
	if credits, _ := link["billing_credits"].(float64); credits != 30 {
		t.Fatalf("billing_credits = %v, want 30 (only the priced attribute)", link["billing_credits"])
	}
	// The bare name the sharer picked is stored in the catalogue's
	// spelling; the unknown one is kept verbatim and stays free.
	if got := fmt.Sprint(link["required_attributes"]); got != "[privasys:document_valid name]" {
		t.Fatalf("required_attributes = %s", got)
	}
	if got := fmt.Sprint(link["paid_attributes"]); got != "[privasys:document_valid]" {
		t.Fatalf("paid_attributes = %s", got)
	}

	market.mu.Lock()
	mints := append([]mintCall(nil), market.mints...)
	market.mu.Unlock()
	if len(mints) != 1 {
		t.Fatalf("want exactly one grant per invitation, got %d", len(mints))
	}
	if mints[0].ClientID != "drive-web" {
		t.Fatalf("grant bound to client %q", mints[0].ClientID)
	}
	if fmt.Sprint(mints[0].Attributes) != "[privasys:document_valid]" {
		t.Fatalf("grant attributes = %v, want the namespaced priced set", mints[0].Attributes)
	}
	if mints[0].TTLSeconds != int64(linkBillingTTL/time.Second) {
		t.Fatalf("grant ttl = %d", mints[0].TTLSeconds)
	}
	if got := market.lastBearer(t); got != "dev:"+owner+":"+owner+"@privasys.org" {
		t.Fatalf("grant minted with %q, want the sharer's own token", got)
	}

	code, preview := previewLink(t, ts.URL, link["id"].(string), link["secret"].(string))
	if code != 200 {
		t.Fatalf("preview: %d %v", code, preview)
	}
	if preview["billing_grant"] != "grant-1" || preview["billing_state"] != billingFunded {
		t.Fatalf("preview did not carry the grant: %v", preview)
	}
	if fmt.Sprint(preview["required_attributes"]) != "[privasys:document_valid name]" {
		t.Fatalf("preview attributes = %v", preview["required_attributes"])
	}
	// The pre-sign-in surface tells the visitor nothing a redeemer would
	// not already learn.
	if _, leaked := preview["node"]; leaked {
		t.Fatalf("preview leaked the node: %v", preview)
	}
	if _, leaked := preview["tenant_id"]; leaked {
		t.Fatalf("preview leaked the tenant: %v", preview)
	}
}

// A paid attribute is only satisfied by the recipient's verified token.
// Typing it into the redeem body must not work: the sharer paid for a
// proven answer.
func TestPaidAttributeMustBeProvenNotAsserted(t *testing.T) {
	ts, srv, _ := billedServer(t)
	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)
	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["document_valid"]}`)
	redeemURL := fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link["id"])

	code, b := doReq(t, bearerReq(t, "POST", redeemURL, recipient,
		`{"secret":"`+link["secret"].(string)+`","attributes":{"privasys:document_valid":"yes"}}`))
	if code != http.StatusForbidden {
		t.Fatalf("self-asserted paid attribute: want 403, got %d %s", code, b)
	}
	if !strings.Contains(string(b), "privasys:document_valid") {
		t.Fatalf("missing attribute not named: %s", b)
	}

	// The same visitor, now holding a token the IdP disclosed the
	// attribute into, files a request.
	srv.Verifier = claimsVerifier{bySub: map[string]map[string]any{
		recipient: {"document_valid": true},
	}}
	code, b = doReq(t, bearerReq(t, "POST", redeemURL, recipient,
		`{"secret":"`+link["secret"].(string)+`"}`))
	if code != 200 {
		t.Fatalf("proven redeem: %d %s", code, b)
	}
	var rr struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(b, &rr); err != nil {
		t.Fatal(err)
	}
	if rr.Status != "pending" {
		t.Fatalf("status = %q, want pending", rr.Status)
	}
}

// A grant funds one sign-in, so a second recipient needs a fresh one.
func TestRearmMintsAGrantForTheNextRecipient(t *testing.T) {
	ts, _, market := billedServer(t)
	const owner = "user-1"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)
	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["privasys:family_name"]}`)

	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/links/%s/billing-grant", ts.URL, tenantID, link["id"]), owner, ""))
	if code != 200 {
		t.Fatalf("re-arm: %d %s", code, b)
	}
	market.mu.Lock()
	mints := len(market.mints)
	market.mu.Unlock()
	if mints != 2 {
		t.Fatalf("re-arm minted %d grants in total, want 2", mints)
	}
	_, preview := previewLink(t, ts.URL, link["id"].(string), link["secret"].(string))
	if preview["billing_grant"] != "grant-2" {
		t.Fatalf("preview still serves the spent grant: %v", preview)
	}

	// A link with nothing billable has nothing to re-arm.
	free := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["name"]}`)
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/links/%s/billing-grant", ts.URL, tenantID, free["id"]), owner, ""))
	if code != http.StatusBadRequest {
		t.Fatalf("re-arm of a free link: want 400, got %d %s", code, b)
	}
}

// A lapsed promise is withheld rather than handed to a visitor whose
// sign-in it would only fail.
func TestExpiredBillingGrantIsWithheld(t *testing.T) {
	ts, _, market := billedServer(t)
	market.grantTTL = -time.Minute
	const owner = "user-1"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)
	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["privasys:document_valid"]}`)

	_, preview := previewLink(t, ts.URL, link["id"].(string), link["secret"].(string))
	if preview["billing_state"] != billingExpired {
		t.Fatalf("billing_state = %v, want expired: %v", preview["billing_state"], preview)
	}
	if _, served := preview["billing_grant"]; served {
		t.Fatalf("expired grant handed to the visitor: %v", preview)
	}
}

// A share the sharer meant to pay for and could not is no share at all:
// carrying on would leave attributes that look required but are only
// typed in.
func TestShareFailsWhenTheGrantCannotBeMinted(t *testing.T) {
	ts, _, market := billedServer(t)
	market.refuse = true
	const owner = "user-1"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)

	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID), owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["privasys:document_valid"]}`))
	if code != http.StatusBadRequest {
		t.Fatalf("unfundable share: want 400, got %d %s", code, b)
	}
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID), owner, ""))
	if code != 200 {
		t.Fatalf("list links: %d %s", code, b)
	}
	var listed struct {
		Links []linkView `json:"links"`
	}
	if err := json.Unmarshal(b, &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Links) != 0 {
		t.Fatalf("an unfunded link was created anyway: %s", b)
	}
}

// A bare name is resolved against the catalogue only when one provider
// claims it: charging a sharer for another provider's attribute of the
// same name would be worse than leaving it self-asserted.
func TestCanonicaliseAttributesLeavesAmbiguousNamesAlone(t *testing.T) {
	catalogue := []attrbilling.Attribute{
		{Key: "privasys:family_name", Namespace: "privasys", Name: "family_name", PriceCredits: 10},
		{Key: "acme:family_name", Namespace: "acme", Name: "family_name", PriceCredits: 99},
		{Key: "privasys:nickname", Namespace: "privasys", Name: "nickname", PriceCredits: 0},
	}
	attrs, paid := canonicaliseAttributes(catalogue,
		[]string{"family_name", "privasys:family_name", "nickname", "name", "privasys:family_name"})
	if got := fmt.Sprint(attrs); got != "[family_name privasys:family_name privasys:nickname name]" {
		t.Fatalf("attrs = %s", got)
	}
	if got := fmt.Sprint(paid); got != "[privasys:family_name]" {
		t.Fatalf("paid = %s", got)
	}
}

// Namespacing comes from the catalogue and nowhere else.
//
// The canonical referential (auth/shared/canonical-attributes.json) names the
// `privasys:` spelling for the attributes Privasys issues, but Drive must not
// derive from it: it covers one namespace, and a share may require an attribute
// from any approved provider. Reconstructing the key as "privasys:"+name would
// misprice a third-party attribute and invent keys for identity fields the
// registry does not sell. This pins that: the same bare name resolves to
// whatever namespace the catalogue puts it in, and an attribute absent from the
// catalogue gains no namespace at all.
func TestCanonicaliseAttributesTakesNamespacingFromTheCatalogue(t *testing.T) {
	catalogue := []attrbilling.Attribute{
		{Key: "acme:birthdate", Namespace: "acme", Name: "birthdate", PriceCredits: 5},
	}
	attrs, paid := canonicaliseAttributes(catalogue, []string{"birthdate", "document_number"})
	// birthdate is privasys: in the canonical referential; here only acme
	// sells it, and acme is what the sharer is charged for.
	if got := fmt.Sprint(attrs); got != "[acme:birthdate document_number]" {
		t.Fatalf("attrs = %s", got)
	}
	if got := fmt.Sprint(paid); got != "[acme:birthdate]" {
		t.Fatalf("paid = %s", got)
	}
}

// Without a marketplace the feature degrades to what restricted links
// always did (self-asserted attributes, nobody billed) rather than
// failing or quietly billing the app's owner.
func TestUnconfiguredInstanceKeepsAttributesSelfAsserted(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)

	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["document_valid"]}`)
	if link["billing_state"] != billingUnavailable {
		t.Fatalf("billing_state = %v, want unavailable", link["billing_state"])
	}
	if _, paid := link["paid_attributes"]; paid {
		t.Fatalf("nothing can be paid for here: %v", link)
	}
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link["id"]), recipient,
		`{"secret":"`+link["secret"].(string)+`","attributes":{"document_valid":"yes"}}`))
	if code != 200 {
		t.Fatalf("self-asserted redeem: %d %s", code, b)
	}
}

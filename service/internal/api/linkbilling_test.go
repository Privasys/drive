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
	"github.com/Privasys/drive/service/internal/attrref"
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

// marketCatalogue is the fixture catalogue: priced gov attributes, a free
// one, and no entry at all for the self-asserted "name" a sharer has
// always been able to require. The assurance strings are the registry's
// own vocabulary, not the IdP's none/provider/gov ladder.
//
// Every row is named for the field the ENCLAVE meters, which is what
// makes this catalogue insufficient on its own: "privasys:given_name"
// sells the passport reading, and its name is also the name of the
// self-asserted key any holder can type.
const marketCatalogue = `{"attributes":[
	{"key":"privasys:document_valid","namespace":"privasys","name":"document_valid","assurance":"gov_verified","price_credits":30},
	{"key":"privasys:family_name","namespace":"privasys","name":"family_name","assurance":"gov_verified","price_credits":10},
	{"key":"privasys:given_name","namespace":"privasys","name":"given_name","assurance":"gov_verified","price_credits":10000},
	{"key":"privasys:birthdate","namespace":"privasys","name":"birthdate","assurance":"gov_verified","price_credits":20},
	{"key":"privasys:nickname","namespace":"privasys","name":"nickname","assurance":"self_asserted","price_credits":0}
]}`

// canonicalReferential is the subset of auth/shared/canonical-attributes.json
// the link tests exercise: three pairs, a government key with no
// self-asserted twin, a government key the registry sells nothing for, and
// two plain profile fields.
const canonicalReferential = `{"attributes":[
	{"key":"name","label":"Display Name","scope":"profile"},
	{"key":"nickname","label":"Nickname","scope":"profile"},
	{"key":"given_name","label":"First Name","scope":"profile","govKey":"given_name_id"},
	{"key":"family_name","label":"Last Name","scope":"profile","govKey":"family_name_id"},
	{"key":"birthdate","label":"Date of Birth","scope":"identity","assurance":"self_asserted","govKey":"birthdate_id"},
	{"key":"given_name_id","label":"Given Names (ID)","scope":"identity","assurance":"gov_verified","certifiedField":"given_name","marketplace":{"key":"privasys:given_name","billable":true}},
	{"key":"family_name_id","label":"Surname (ID)","scope":"identity","assurance":"gov_verified","certifiedField":"family_name","marketplace":{"key":"privasys:family_name","billable":true}},
	{"key":"birthdate_id","label":"Date of Birth (ID)","scope":"identity","assurance":"gov_verified","certifiedField":"birthdate","marketplace":{"key":"privasys:birthdate","billable":true}},
	{"key":"document_valid","label":"Valid Government ID","scope":"identity","assurance":"gov_verified","marketplace":{"key":"privasys:document_valid","billable":true}},
	{"key":"document_number","label":"Passport Number","scope":"identity","assurance":"gov_verified"}
]}`

// newFakeReferential serves the canonical referential the way the IdP
// does. A separate server from the marketplace on purpose: in production
// the assurance of a key comes from the issuer that mints the claim, and
// the price comes from the control plane, and confusing the two is how
// the bug this fixture pins was written.
func newFakeReferential(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/referential/canonical-attributes.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, canonicalReferential)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// testReferential parses the fixture for the resolution unit tests.
func testReferential(t *testing.T) *attrref.Referential {
	t.Helper()
	ref, err := attrref.Parse([]byte(canonicalReferential))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

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

// billedServer is a Drive wired to a fake marketplace and the issuer's
// referential, configured with the OAuth client its front end signs
// recipients in with.
func billedServer(t *testing.T) (*httptest.Server, *Server, *fakeMarket) {
	t.Helper()
	ts, srv := newTestServer(t)
	market := newFakeMarket(t)
	srv.AttrRef = attrref.New(newFakeReferential(t).URL)
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
	attrs, paid, proven, err := canonicaliseAttributes(testReferential(t), catalogue,
		[]string{"family_name", "privasys:family_name", "nickname", "name", "privasys:family_name"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(attrs); got != "[family_name privasys:family_name privasys:nickname name]" {
		t.Fatalf("attrs = %s", got)
	}
	if got := fmt.Sprint(paid); got != "[privasys:family_name]" {
		t.Fatalf("paid = %s", got)
	}
	// The row the sharer named by key is the passport one, so the claim
	// recorded for it is the certified spelling, not the row's name.
	if proven["privasys:family_name"] != "family_name_id" {
		t.Fatalf("proven = %v", proven)
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
	attrs, paid, proven, err := canonicaliseAttributes(testReferential(t), catalogue,
		[]string{"birthdate", "document_number"})
	if err != nil {
		t.Fatal(err)
	}
	// birthdate is privasys: in the canonical referential; here only acme
	// sells it, and acme is what the sharer is charged for.
	if got := fmt.Sprint(attrs); got != "[acme:birthdate document_number]" {
		t.Fatalf("attrs = %s", got)
	}
	if got := fmt.Sprint(paid); got != "[acme:birthdate]" {
		t.Fatalf("paid = %s", got)
	}
	// A passport field the registry sells no disclosure for is free and
	// still proven: it comes off the token or it does not arrive.
	if proven["document_number"] != "document_number" {
		t.Fatalf("proven = %v", proven)
	}
}

// The whole seam, end to end: the picker's key becomes a paid namespaced
// requirement, and only the certified claim opens it.
func TestGovernmentRequirementSurvivesTheVisitorsOwnSignIn(t *testing.T) {
	ts, srv, _ := billedServer(t)
	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)

	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["birthdate_id"]}`)
	if got := fmt.Sprint(link["required_attributes"]); got != "[privasys:birthdate]" {
		t.Fatalf("required_attributes = %s", got)
	}
	if got := fmt.Sprint(link["paid_attributes"]); got != "[privasys:birthdate]" {
		t.Fatalf("paid_attributes = %s", got)
	}
	redeemURL := fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link["id"])

	// The visitor asks their own wallet for the cheap reading instead.
	srv.Verifier = claimsVerifier{bySub: map[string]map[string]any{
		recipient: {"birthdate": "1990-01-01"},
	}}
	code, b := doReq(t, bearerReq(t, "POST", redeemURL, recipient,
		`{"secret":"`+link["secret"].(string)+`"}`))
	if code != http.StatusForbidden {
		t.Fatalf("self-asserted twin: want 403, got %d %s", code, b)
	}

	// And again after disclosing what the link actually requires.
	srv.Verifier = claimsVerifier{bySub: map[string]map[string]any{
		recipient: {"birthdate": "1990-01-01", "birthdate_id": "1980-02-03"},
	}}
	code, b = doReq(t, bearerReq(t, "POST", redeemURL, recipient,
		`{"secret":"`+link["secret"].(string)+`"}`))
	if code != 200 {
		t.Fatalf("certified redeem: %d %s", code, b)
	}
	// The wallet is told which claim to ask for, since neither the stored
	// spelling nor the bare name would request it.
	_, preview := previewLink(t, ts.URL, link["id"].(string), link["secret"].(string))
	claims, _ := preview["attribute_claims"].(map[string]any)
	if claims["privasys:birthdate"] != "birthdate_id" {
		t.Fatalf("attribute_claims = %v", preview["attribute_claims"])
	}
}

// A sharer with no account to charge cannot require a paid disclosure, and
// must be told so rather than handed a link that asks a visitor to type
// their date of birth into a box.
func TestGovernmentAttributeRefusedWhenNobodyCanBeBilled(t *testing.T) {
	ts, _, _ := billedServer(t)
	const owner = "user-1"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)
	// A sealed-session sharer: the relay asserts the sub and no platform
	// token travels with it, so the marketplace has nobody to bill.
	sealed := func(body string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest("POST",
			fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID), strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Privasys-Sub", owner)
		return doReq(t, req)
	}

	code, b := sealed(`{"mode":"restricted","scope":["read"],"required_attributes":["birthdate_id"]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("unbuyable government requirement: want 400, got %d %s", code, b)
	}
	if !strings.Contains(string(b), "birthdate_id") {
		t.Fatalf("refusal did not name the attribute: %d %s", code, b)
	}
	// The free reading of the same field is still offerable.
	code, b = sealed(`{"mode":"restricted","scope":["read"],"required_attributes":["birthdate"]}`)
	if code != 201 {
		t.Fatalf("self-asserted share refused too: %d %s", code, b)
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

// Picking the free reading of an attribute must not buy the passport one.
//
// The registry row is named for the field the enclave meters, so
// "privasys:given_name" carries the same name as the self-asserted
// "given_name" a holder types into their own wallet. Resolving the chosen
// key by name lands on that row and bills the sharer ten thousand credits
// for a ceremony they neither asked for nor needed.
func TestSelfAssertedKeyNeverResolvesOntoTheGovernmentRow(t *testing.T) {
	catalogue := []attrbilling.Attribute{
		{Key: "privasys:given_name", Namespace: "privasys", Name: "given_name", Assurance: "gov_verified", PriceCredits: 10000},
	}
	attrs, paid, proven, err := canonicaliseAttributes(testReferential(t), catalogue, []string{"given_name"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(attrs); got != "[given_name]" {
		t.Fatalf("attrs = %s, want the self-asserted key kept bare", got)
	}
	if len(paid) != 0 {
		t.Fatalf("paid = %v, want nothing: a typed-in first name costs nobody anything", paid)
	}
	if len(proven) != 0 {
		t.Fatalf("proven = %v, want nothing: this is the reading the visitor asserts", proven)
	}
}

// Picking the passport reading must buy it.
//
// "given_name_id" is not a catalogue key and never was: the registry sells
// it as "privasys:given_name". Stored under its own spelling it matched no
// row, so it was neither namespaced nor paid for, and an unpaid
// requirement is one the visitor types in. The sharer asked for a passport
// check and got a text box.
func TestGovernmentKeyBecomesThePaidNamespacedRequirement(t *testing.T) {
	catalogue := []attrbilling.Attribute{
		{Key: "privasys:given_name", Namespace: "privasys", Name: "given_name", Assurance: "gov_verified", PriceCredits: 10000},
	}
	attrs, paid, proven, err := canonicaliseAttributes(testReferential(t), catalogue, []string{"given_name_id"})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(attrs); got != "[privasys:given_name]" {
		t.Fatalf("attrs = %s, want the registry spelling", got)
	}
	if got := fmt.Sprint(paid); got != "[privasys:given_name]" {
		t.Fatalf("paid = %s, want the sharer billed for the disclosure they chose", got)
	}
	if proven["privasys:given_name"] != "given_name_id" {
		t.Fatalf("proven = %v, want the certified claim recorded", proven)
	}

	// A registry that does not offer the row is not a share to fall back
	// from: the sharer would be left with a requirement anyone can type.
	if _, _, _, err := canonicaliseAttributes(testReferential(t), nil, []string{"given_name_id"}); err == nil {
		t.Fatal("an unbuyable government attribute was accepted")
	}
}

// A link reads exactly the claim it recorded, and no other.
//
// The visitor drives their own sign-in, so they choose which attributes to
// ask their wallet for. Asking for the self-asserted twin of what the link
// requires used to work, because the claim lookup fell back to the bare
// name when the "_id" one was absent: the visitor proved nothing, the
// sharer paid for a ceremony that never happened, and the link opened.
func TestRecordedClaimIsTheOnlyOneRead(t *testing.T) {
	meta := &linkMeta{
		Attrs:       []string{"privasys:birthdate", "name"},
		PaidAttrs:   []string{"privasys:birthdate"},
		ProvenAttrs: map[string]string{"privasys:birthdate": "birthdate_id"},
	}
	// The tamper: a token carrying only the reading the holder typed.
	tampered := &Principal{ID: &oidc.Identity{Claims: map[string]any{"birthdate": "1990-01-01"}}}
	_, missing := linkAttributeEvidence(tampered, meta, meta.ProvenAttrs, map[string]string{"name": "A Visitor"})
	if got := fmt.Sprint(missing); got != "[privasys:birthdate]" {
		t.Fatalf("missing = %s, want the certified date still outstanding", got)
	}

	// The same visitor after disclosing it properly. The self-asserted twin
	// is still on the token and is still not what is read.
	proper := &Principal{ID: &oidc.Identity{Claims: map[string]any{
		"birthdate":    "1990-01-01",
		"birthdate_id": "1980-02-03",
	}}}
	evidence, missing := linkAttributeEvidence(proper, meta, meta.ProvenAttrs, map[string]string{"name": "A Visitor"})
	if len(missing) != 0 {
		t.Fatalf("missing = %v", missing)
	}
	if evidence["privasys:birthdate"] != "1980-02-03" {
		t.Fatalf("evidence = %v, want the certified value", evidence)
	}
	// A typed value for a proven requirement is ignored, not merged.
	_, missing = linkAttributeEvidence(tampered, meta, meta.ProvenAttrs,
		map[string]string{"name": "A Visitor", "privasys:birthdate": "1980-02-03"})
	if got := fmt.Sprint(missing); got != "[privasys:birthdate]" {
		t.Fatalf("missing = %s, want a typed value to buy nothing", got)
	}
}

// A link stored before the claim was recorded keeps its meaning.
//
// Its Meta names the registry row and nothing else, which is ambiguous
// between the two readings of the same field. It is read the safe way: the
// referential maps the row back to the certified claim, so the passport
// date is still what opens it, while a row with no self-asserted twin is
// still found under its bare name.
func TestStoredLinkWithoutRecordedClaimsKeepsTheGovernmentReading(t *testing.T) {
	_, srv, _ := billedServer(t)
	legacy := &linkMeta{
		Attrs:     []string{"privasys:birthdate", "privasys:document_valid"},
		PaidAttrs: []string{"privasys:birthdate", "privasys:document_valid"},
	}
	proven, err := srv.provenClaims(context.Background(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	if proven["privasys:birthdate"] != "birthdate_id" {
		t.Fatalf("proven = %v, want the certified claim", proven)
	}
	if proven["privasys:document_valid"] != "document_valid" {
		t.Fatalf("proven = %v, want document_valid found under its own name", proven)
	}
	typed := &Principal{ID: &oidc.Identity{Claims: map[string]any{
		"birthdate": "1990-01-01", "document_valid": true,
	}}}
	if _, missing := linkAttributeEvidence(typed, legacy, proven, nil); fmt.Sprint(missing) != "[privasys:birthdate]" {
		t.Fatalf("missing = %v, want the self-asserted date rejected", missing)
	}
}

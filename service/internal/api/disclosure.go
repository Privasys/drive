package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"enclave-os-mini/clients/go/spend"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/store"
)

// Attributes a share link needs, approved in the holder's wallet.
//
// When the assistant opens a link that asks for attributes (the user's
// name, say), Drive asks the IdP for them itself: POST /spend/disclosures,
// authenticated by a proof from Drive's spend key and allowed only because
// the user lets Drive act for them. The IdP pushes the user's wallet; they
// approve there, and Drive collects a disclosure+jwt addressed to Drive
// alone, which it verifies and redeems the link with, exactly as it would
// read the same claims off the user's own sign-in. The assistant never sees
// or carries a value.

// disclosureWait is how long open_link holds the call open for the user to
// approve on their phone before answering "awaiting approval".
var disclosureWait = 25 * time.Second

// pendingDisclosure is one request Drive is waiting on, per link and user.
type pendingDisclosure struct {
	id      string
	claimOf map[string]string // link attribute → the claim it is disclosed as
	expires time.Time
}

var pendingDisclosures sync.Map // linkID|sub → *pendingDisclosure

// errNoDisclosure is why Drive cannot ask the wallet itself: no spend key
// (off platform), the user has not let Drive act for them, or their wallet
// cannot receive the request. The browser remains the way in.
var errNoDisclosure = errors.New("cannot ask the user's wallet directly")

func idpBase() string { return spend.IssuerFromEnv(os.Getenv) }

// The IdP round trip and the disclosure check, swappable in tests.
var (
	idpPost        = idpCall
	checkDisclosed = verifyDisclosure
)

// idpCall posts body to the IdP with Drive's app proof added.
func idpCall(ctx context.Context, path string, body map[string]any) (int, map[string]any, error) {
	signer := spendSigner()
	if signer == nil {
		return 0, nil, errNoDisclosure
	}
	u, err := url.Parse(idpBase())
	if err != nil {
		return 0, nil, err
	}
	proof, err := signer.Proof(u.Hostname())
	if err != nil {
		return 0, nil, err
	}
	body["app_id"] = signer.AppID()
	body["proof"] = proof
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idpBase()+path, bytes.NewReader(raw))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, nil
}

// askWallet starts a disclosure for the link's missing attributes.
func (s *Server) askWallet(ctx context.Context, sub string, missing []string, claimOf map[string]string, purpose, billingGrant string) (*pendingDisclosure, error) {
	claims := make([]string, 0, len(missing))
	for _, k := range missing {
		claims = append(claims, claimOf[k])
	}
	body := map[string]any{"sub": sub, "attributes": claims, "purpose": purpose}
	if billingGrant != "" {
		body["billing_grant"] = billingGrant
	}
	code, out, err := idpPost(ctx, "/spend/disclosures", body)
	if err != nil {
		return nil, err
	}
	switch code {
	case http.StatusAccepted:
	case http.StatusForbidden, http.StatusConflict, http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: %v", errNoDisclosure, out["error_description"])
	default:
		return nil, fmt.Errorf("identity provider answered %d: %v", code, out["error_description"])
	}
	id, _ := out["id"].(string)
	if id == "" {
		return nil, errors.New("identity provider returned no request id")
	}
	ttl := 10 * time.Minute
	if n, ok := out["expires_in"].(float64); ok && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	return &pendingDisclosure{id: id, claimOf: claimOf, expires: time.Now().Add(ttl)}, nil
}

// collectDisclosure polls a request until approved or until wait elapses.
// It returns the verified attribute values on approval, nil while still
// pending, and errDisclosureGone once the request no longer exists.
func (s *Server) collectDisclosure(ctx context.Context, sub, id string, wait time.Duration) (map[string]string, error) {
	deadline := time.Now().Add(wait)
	for {
		code, out, err := idpPost(ctx, "/spend/disclosures/"+url.PathEscape(id), map[string]any{})
		if err != nil {
			return nil, err
		}
		switch {
		case code == http.StatusOK && out["status"] == "approved":
			tok, _ := out["disclosure"].(string)
			return checkDisclosed(ctx, tok, sub)
		case code == http.StatusOK:
			// pending
		case code == http.StatusNotFound || code == http.StatusGone:
			return nil, errDisclosureGone
		default:
			return nil, fmt.Errorf("identity provider answered %d: %v", code, out["error_description"])
		}
		if time.Now().Add(2 * time.Second).After(deadline) {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(2 * time.Second):
		}
	}
}

var errDisclosureGone = errors.New("the request expired before the user approved it")

// verifyDisclosure checks a disclosure+jwt: the IdP's signature and issuer,
// addressed to this Drive alone, about this user, unexpired.
func verifyDisclosure(ctx context.Context, tok, sub string) (map[string]string, error) {
	signer := spendSigner()
	if signer == nil {
		return nil, errNoDisclosure
	}
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("disclosure: malformed")
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("disclosure: malformed header")
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if json.Unmarshal(hdr, &h) != nil || h.Typ != "disclosure+jwt" {
		return nil, errors.New("disclosure: not a disclosure")
	}
	id, err := oidc.NewJWKSVerifier(idpBase(), "disclosure:"+signer.AppID()).Verify(ctx, tok)
	if err != nil {
		return nil, fmt.Errorf("disclosure: %w", err)
	}
	if id.Sub != sub {
		return nil, errors.New("disclosure: about someone else")
	}
	out := map[string]string{}
	if attrs, ok := id.Claims["attrs"].(map[string]any); ok {
		for k, v := range attrs {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				out[k] = s
			}
		}
	}
	return out, nil
}

// linkAwaitingApproval is open_link waiting on the user's wallet.
const linkAwaitingApproval = "awaiting-approval"

// openLinkForAssistant redeems a link for the assistant's user, asking their
// wallet for any attributes the link requires. note says why the wallet
// could not be asked, when it could not.
func (s *Server) openLinkForAssistant(ctx context.Context, p *Principal, g *grants.Grant, meta *linkMeta, n *store.Node) (out linkRedeemOutcome, note string, err error) {
	key := g.ID + "|" + p.Sub
	if v, ok := pendingDisclosures.Load(key); ok {
		pd := v.(*pendingDisclosure)
		if time.Now().Before(pd.expires) {
			attrs, cerr := s.collectDisclosure(ctx, p.Sub, pd.id, disclosureWait)
			switch {
			case cerr == nil && attrs == nil:
				return linkRedeemOutcome{Status: linkAwaitingApproval}, "", nil
			case cerr == nil:
				pendingDisclosures.Delete(key)
				out, err := s.redeemWithDisclosure(ctx, p, g, meta, n, attrs, pd.claimOf)
				return out, "", err
			case !errors.Is(cerr, errDisclosureGone):
				return linkRedeemOutcome{}, "", cerr
			}
		}
		pendingDisclosures.Delete(key) // expired: ask afresh below
	}

	out, err = s.redeemLinkFor(ctx, p, g, meta, n, nil)
	if err != nil || out.Status != linkMissingAttrs {
		return out, "", err
	}
	proven, err := s.provenClaims(ctx, meta)
	if err != nil {
		return linkRedeemOutcome{}, "", &linkMarketError{err}
	}
	claimOf := make(map[string]string, len(meta.Attrs))
	for _, k := range meta.Attrs {
		if c, ok := proven[k]; ok && c != "" {
			claimOf[k] = c
		} else {
			claimOf[k] = k
		}
	}
	ownerName := "its owner"
	if t, terr := s.Store.GetTenant(ctx, g.TenantID); terr == nil && strings.TrimSpace(t.Name) != "" {
		ownerName = t.Name
	}
	purpose := fmt.Sprintf("To open %q, shared by %s", n.Name, ownerName)
	grant := ""
	if meta.billingStateOf(time.Now().UTC()) == billingFunded {
		grant = meta.BillingGrant
	}
	pd, aerr := s.askWallet(ctx, p.Sub, out.Missing, claimOf, purpose, grant)
	if aerr != nil {
		return out, aerr.Error(), nil // the browser remains the way in
	}
	pendingDisclosures.Store(key, pd)
	attrs, cerr := s.collectDisclosure(ctx, p.Sub, pd.id, disclosureWait)
	if cerr != nil && !errors.Is(cerr, errDisclosureGone) {
		return linkRedeemOutcome{}, "", cerr
	}
	if attrs == nil {
		return linkRedeemOutcome{Status: linkAwaitingApproval, Missing: out.Missing}, "", nil
	}
	pendingDisclosures.Delete(key)
	out, err = s.redeemWithDisclosure(ctx, p, g, meta, n, attrs, claimOf)
	return out, "", err
}

// redeemWithDisclosure redeems with the wallet-approved values as evidence:
// a proven attribute is read off the disclosure's claims exactly as off a
// sign-in token, and a self-asserted one is presented with its value.
func (s *Server) redeemWithDisclosure(ctx context.Context, p *Principal, g *grants.Grant, meta *linkMeta, n *store.Node, attrs, claimOf map[string]string) (linkRedeemOutcome, error) {
	claims := make(map[string]any, len(attrs))
	for k, v := range attrs {
		claims[k] = v
	}
	presented := map[string]string{}
	for attr, claim := range claimOf {
		if v := attrs[claim]; v != "" {
			presented[attr] = v
		}
	}
	withEvidence := &Principal{Sub: p.Sub, Via: p.Via, ID: &oidc.Identity{Sub: p.Sub, Claims: claims}}
	return s.redeemLinkFor(ctx, withEvidence, g, meta, n, presented)
}

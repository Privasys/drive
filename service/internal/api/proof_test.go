package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/disclosure"
)

// proofIssuer is a stand-in identity verifier: it publishes its key the way
// the real one does and signs disclosures in the same shape.
func proofIssuer(t *testing.T) (string, func(map[string]any) string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var url string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x, y := make([]byte, 32), make([]byte, 32)
		k.X.FillBytes(x)
		k.Y.FillBytes(y)
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": url, "jwks": map[string]any{"keys": []map[string]string{{
			"kty": "EC", "crv": "P-256", "kid": "k1",
			"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y),
		}}}})
	}))
	t.Cleanup(srv.Close)
	url = srv.URL
	mint := func(payload map[string]any) string {
		h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1"})
		p, _ := json.Marshal(payload)
		in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
		d := sha256.Sum256([]byte(in))
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return in + "." + base64.RawURLEncoding.EncodeToString(sig) + "~"
	}
	return url, mint
}

// A paid attribute counts only with a valid proof: a typed value, a "no",
// or someone else's proof leaves it missing, and the sharer is shown the
// proven value, never the token.
func TestPaidAttributeNeedsAValidProof(t *testing.T) {
	ts, srv, _ := billedServer(t)
	const owner, visitor = "user-1", "user-2"
	issuer, mint := proofIssuer(t)
	srv.Proofs = &disclosure.Verifier{Issuers: []string{issuer}}
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)
	link := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","scope":["read"],"required_attributes":["document_valid"]}`)
	redeemURL := fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link["id"])
	body := `{"secret":"` + link["secret"].(string) + `"}`
	proof := func(over map[string]any) string {
		p := map[string]any{"iss": issuer, "sub": visitor, "aud": "drive-web", "claim": "document_valid",
			"value": true, "exp": time.Now().Add(5 * time.Minute).Unix()}
		for k, v := range over {
			p[k] = v
		}
		return mint(p)
	}
	try := func(claim any) (int, string) {
		t.Helper()
		srv.Verifier = claimsVerifier{bySub: map[string]map[string]any{visitor: {"document_valid": claim}}}
		code, b := doReq(t, bearerReq(t, "POST", redeemURL, visitor, body))
		return code, string(b)
	}
	for name, claim := range map[string]any{
		"a typed value":        true,
		"a no":                 proof(map[string]any{"value": false}),
		"someone else's proof": proof(map[string]any{"sub": "user-9"}),
		"another app's proof":  proof(map[string]any{"aud": "elsewhere"}),
	} {
		if code, b := try(claim); code != http.StatusForbidden || !strings.Contains(b, "missing") {
			t.Fatalf("%s: %d %s", name, code, b)
		}
	}
	if code, b := try(proof(nil)); code != 200 || !strings.Contains(b, `"pending"`) {
		t.Fatalf("a valid proof: %d %s", code, b)
	}
}

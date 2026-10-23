package disclosure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testIssuer serves SD-JWT VC issuer metadata for one key and mints proofs
// the way the identity verifier does.
type testIssuer struct {
	*httptest.Server
	key *ecdsa.PrivateKey
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iss := &testIssuer{key: k}
	iss.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		pad := func(b []byte) []byte { out := make([]byte, 32); copy(out[32-len(b):], b); return out }
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": iss.URL,
			"jwks": map[string]any{"keys": []map[string]string{{
				"kty": "EC", "crv": "P-256", "kid": "k1",
				"x": base64.RawURLEncoding.EncodeToString(pad(k.X.Bytes())),
				"y": base64.RawURLEncoding.EncodeToString(pad(k.Y.Bytes())),
			}}},
		})
	}))
	t.Cleanup(iss.Close)
	return iss
}

func (i *testIssuer) mint(t *testing.T, payload map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "typ": "dc+sd-jwt", "kid": "k1"})
	p, _ := json.Marshal(payload)
	in := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, i.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + base64.RawURLEncoding.EncodeToString(sig) + "~"
}

func TestVerify(t *testing.T) {
	iss := newTestIssuer(t)
	other := newTestIssuer(t)
	v := &Verifier{Issuers: []string{iss.URL}}
	want := Expect{Claim: "age_over_18", Subject: "visitor", Audience: "privasys-platform"}
	base := func() map[string]any {
		return map[string]any{
			"iss": iss.URL, "sub": "visitor", "aud": "privasys-platform",
			"claim": "age_over_18", "value": true, "exp": time.Now().Add(5 * time.Minute).Unix(),
		}
	}
	with := func(k string, val any) map[string]any { p := base(); p[k] = val; return p }

	got, err := v.Verify(context.Background(), iss.mint(t, base()), want)
	if err != nil || got != "true" {
		t.Fatalf("a valid proof: %q %v", got, err)
	}
	field, err := v.Verify(context.Background(), iss.mint(t, with("claim", "given_name")),
		Expect{Claim: "given_name", Subject: "visitor", Audience: "privasys-platform"})
	if err != nil || field != "true" {
		t.Fatalf("a field proof: %q %v", field, err)
	}

	for name, tok := range map[string]string{
		"a plain value":         "true",
		"the answer is no":      iss.mint(t, with("value", false)),
		"a failure receipt":     iss.mint(t, with("failure", map[string]bool{"retryable": true})),
		"someone else's proof":  iss.mint(t, with("sub", "another")),
		"another relying party": iss.mint(t, with("aud", "elsewhere")),
		"another claim":         iss.mint(t, with("claim", "document_valid")),
		"long expired":          iss.mint(t, with("exp", time.Now().Add(-time.Hour).Unix())),
		"an untrusted issuer":   other.mint(t, with("iss", other.URL)),
		"a forged issuer name":  other.mint(t, base()),
		"a tampered payload":    tamper(iss.mint(t, base())),
	} {
		if _, err := v.Verify(context.Background(), tok, want); !errors.Is(err, ErrNotProven) {
			t.Errorf("%s was accepted (err %v)", name, err)
		}
	}
}

// tamper swaps the payload for one naming someone else, keeping the
// signature.
func tamper(tok string) string {
	parts := strings.Split(strings.TrimSuffix(tok, "~"), ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["sub"] = "attacker"
	raw, _ = json.Marshal(m)
	return parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2] + "~"
}

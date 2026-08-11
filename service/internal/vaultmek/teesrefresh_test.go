package vaultmek

import (
	"encoding/base64"
	"errors"
	"testing"
)

func grantJWT(t *testing.T, payload string) string {
	t.Helper()
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	return enc(`{"alg":"ES256","typ":"JWT"}`) + "." + enc(payload) + "." + enc("sig")
}

func TestTeesFromGrant(t *testing.T) {
	payload := `{"scope":"apps.privasys.org/x","policy":{"principals":{"owner":{"Oidc":{"issuer":"https://privasys.id","sub":"u1"}},"tees":[{"Tee":{"name":"app:drive / TDX","measurements":[{"Tdx":{"mrtd":"aa","rtmr1":"bb","rtmr2":"cc"}}],"required_oids":[{"oid":"1.3.6.1.4.1.65230.3.2","value":"dd"}]}}]}}}`
	tees, err := TeesFromGrant(grantJWT(t, payload))
	if err != nil {
		t.Fatalf("TeesFromGrant: %v", err)
	}
	if len(tees) != 1 || tees[0].Tee == nil || tees[0].Tee.Name != "app:drive / TDX" {
		t.Fatalf("unexpected tees: %+v", tees)
	}

	// A grant without TEE principals is refused — replacing the tees
	// with an empty set would lock the running app out of the key.
	if _, err := TeesFromGrant(grantJWT(t, `{"policy":{"principals":{"owner":{}}}}`)); err == nil {
		t.Fatal("grant with no tees must be refused")
	}
	if _, err := TeesFromGrant("not-a-jwt"); err == nil {
		t.Fatal("non-JWT grant must be refused")
	}
}

func TestPrincipalMismatch(t *testing.T) {
	if !PrincipalMismatch(errors.New("vaultmek: only 0/2 shares recovered for h: vault error: caller is not in policy.principals")) {
		t.Fatal("principal refusal not recognised")
	}
	if PrincipalMismatch(errors.New("vaultmek: dial x: connection refused")) {
		t.Fatal("transport failure misclassified as principal mismatch")
	}
	if PrincipalMismatch(nil) {
		t.Fatal("nil error misclassified")
	}
}

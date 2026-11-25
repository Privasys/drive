package api

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func jwtWithAud(aud string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." +
		enc([]byte(`{"iss":"https://privasys.id","sub":"s","aud":`+aud+`}`)) + ".sig"
}

func TestIsPlatformToken(t *testing.T) {
	for aud, want := range map[string]bool{
		`"privasys-platform"`:                    true,
		`"privasys-platform-test"`:               true,
		`["app:abc","privasys-platform"]`:        true,
		`["privasys-platform-test"]`:             true,
		`"app:02104572ca2f41e8ae2d24c0294e6f5e"`: false,
		`"privasys-drive"`:                       false,
		`["privasys-drive","app:x"]`:             false,
		`"privasys-platformer"`:                  false,
	} {
		if got := isPlatformToken(jwtWithAud(aud)); got != want {
			t.Errorf("aud %s: got %v, want %v", aud, got, want)
		}
	}
	if isPlatformToken("not-a-jwt") {
		t.Error("garbage is not a platform token")
	}
}

// TestPlatformTokensAreRefused proves Drive never takes a platform token:
// not as the bearer (400 before verification) and not as owner_token in the
// tenant-key body.
func TestPlatformTokensAreRefused(t *testing.T) {
	ts := newFullServer(t, func(s *Server) { s.MEKs = &fakeMEKs{mek: make([]byte, 32)} })
	for _, aud := range []string{`"privasys-platform"`, `["app:x","privasys-platform-test"]`} {
		resp, body := doJSON(t, "GET", ts.URL+"/v1/me", "Bearer "+jwtWithAud(aud), "")
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "platform sign-in token") {
			t.Fatalf("bearer aud %s: want 400, got %d %s", aud, resp.StatusCode, body)
		}
	}
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	resp, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth, `{"grant":"g","owner_token":"anything"}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "owner_token is not accepted") {
		t.Fatalf("owner_token: want 400, got %d %s", resp.StatusCode, body)
	}
}

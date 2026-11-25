package api

import (
	"context"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/oidc"
)

// The user-bearer verifier takes only access tokens, and only for the
// audiences on its list; log-only accepts the rest; an empty list restores
// the default, enforced.
func TestUserBearerAccessTokensAndAudience(t *testing.T) {
	idp := newTestIdP(t)
	v := oidc.NewJWKSVerifier(idp.URL, "privasys-platform-test,app:abc").WithAccessTokens()
	exp := time.Now().Add(time.Hour).Unix()
	access := func(aud string) map[string]any {
		return map[string]any{"iss": idp.URL, "sub": "s", "aud": aud, "typ": "at+jwt", "exp": exp}
	}
	jwt := map[string]any{"typ": "JWT"}
	ok := func(name, tok string, want bool) {
		t.Helper()
		_, err := v.Verify(context.Background(), tok)
		if (err == nil) != want {
			t.Errorf("%s: err=%v, want accepted=%v", name, err, want)
		}
	}

	ok("listed test audience", idp.mint(t, jwt, access("privasys-platform-test")), true)
	ok("app audience", idp.mint(t, jwt, access("app:abc")), true)
	ok("no typ header", idp.mint(t, map[string]any{"typ": nil}, access("app:abc")), true)
	ok("production audience", idp.mint(t, jwt, access("privasys-platform")), false)
	ok("another app", idp.mint(t, jwt, access("app:other")), false)

	notAccess := access("privasys-platform-test")
	delete(notAccess, "typ")
	ok("no typ claim", idp.mint(t, jwt, notAccess), false)
	ok("typed header (form answer)", idp.mint(t, map[string]any{"typ": FormAnswerType}, access("privasys-platform-test")), false)
	approval := access("privasys-platform-test")
	approval["vault_op"] = "x"
	ok("approval token", idp.mint(t, jwt, approval), false)

	v.SetAudience("privasys-platform-test", false) // log-only
	ok("log-only accepts outside the list", idp.mint(t, jwt, access("privasys-platform")), true)
	ok("log-only still refuses a non-access token", idp.mint(t, jwt, notAccess), false)

	v.SetAudience("", true) // back to the default list, enforced
	ok("default enforced again", idp.mint(t, jwt, access("privasys-platform")), false)
	ok("default list", idp.mint(t, jwt, access("app:abc")), true)
}

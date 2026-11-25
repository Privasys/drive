package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseConfigureGrant(t *testing.T) {
	good := map[string][2]string{
		"role=owner; sub=abc":  {"owner", "abc"},
		"role=admin;sub=a-b_c": {"admin", "a-b_c"},
	}
	for in, want := range good {
		r, s, ok := parseConfigureGrant(in)
		if !ok || r != want[0] || s != want[1] {
			t.Errorf("%q: got %q %q %v", in, r, s, ok)
		}
	}
	for _, in := range []string{
		"", "role=owner", "role=viewer; sub=abc", "sub=abc; role=owner",
		"role=owner; sub=", "role=owner; sub=a b", "role=owner; sub=abc; extra=1",
		"role=owner; sub=a=b", "role=Owner; sub=abc",
	} {
		if _, _, ok := parseConfigureGrant(in); ok {
			t.Errorf("%q accepted", in)
		}
	}
}

// The header counts only where the runtime states it; elsewhere configure
// keeps the bearer check, and a forged header gets nowhere.
func TestConfigureGrantOnlyWhenTheRuntimeStatesIt(t *testing.T) {
	var got *Principal
	_, s := newTestServer(t)
	h := s.configureAuth(func(w http.ResponseWriter, r *http.Request, p *Principal) { got = p })
	call := func(header string) int {
		got = nil
		req := httptest.NewRequest(http.MethodPost, "/configure", nil)
		if header != "" {
			req.Header.Set(configureGrantHeader, header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	t.Setenv(configureGrantEnv, "")
	if code := call("role=owner; sub=abc"); got != nil || code != http.StatusUnauthorized {
		t.Fatalf("without the runtime's statement a header must be ignored: code %d, principal %+v", code, got)
	}

	t.Setenv(configureGrantEnv, "1")
	if call("role=owner; sub=abc"); got == nil || got.Sub != "abc" || !got.IsUser() || got.Via != viaConfigureGrant {
		t.Fatalf("stated grant not accepted: %+v", got)
	}
	if err := s.configureAllowed(got); err != nil {
		t.Fatalf("configureAllowed: %v", err)
	}
	if code := call("role=viewer; sub=abc"); got != nil || code != http.StatusUnauthorized {
		t.Fatalf("malformed grant: code %d", code)
	}
	if code := call(""); got != nil || code != http.StatusUnauthorized {
		t.Fatalf("no header falls back to the bearer check: code %d", code)
	}
}

// The runtime states the platform account subject, the same subject space
// the bearer path verifies: configure matches no owner itself (the runtime
// checked the role), and a subject Drive has retired is refused on the
// header path exactly as on the bearer path.
func TestConfigureGrantSubjectIsTheBearerSubject(t *testing.T) {
	_, s := newTestServer(t)
	if _, err := s.Store.RekeySubjects(context.Background(), map[string]string{"owner-account": "owner-new"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv(configureGrantEnv, "1")
	var got *Principal
	h := s.configureAuth(func(w http.ResponseWriter, r *http.Request, p *Principal) { got = p })
	for sub, want := range map[string]bool{"owner-new": true, "owner-account": false} {
		got = nil
		req := httptest.NewRequest(http.MethodPost, "/configure", nil)
		req.Header.Set(configureGrantHeader, "role=owner; sub="+sub)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if (got != nil) != want {
			t.Errorf("sub %s: accepted=%v (code %d), want %v", sub, got != nil, rec.Code, want)
		}
		if got != nil && got.Sub != sub {
			t.Errorf("sub %s: principal names %s", sub, got.Sub)
		}
	}
}

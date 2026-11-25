package main

import "testing"

// The default audience list names ONE platform audience, this
// environment's, and never both.
func TestDefaultAudience(t *testing.T) {
	cases := []struct{ env, want string }{
		{"privasys-platform-test", "privasys-platform-test,app:abc"},
		{"privasys-platform", "privasys-platform,app:abc"},
		{"", "privasys-platform,app:abc"},
		{"something-else", "privasys-platform,app:abc"},
		{"privasys-platform,privasys-platform-test", "privasys-platform,app:abc"},
	}
	for _, c := range cases {
		t.Setenv("OIDC_AUDIENCE", "")
		t.Setenv("PRIVASYS_AUDIENCE", c.env)
		if got := defaultAudience("A-B-C"); got != c.want {
			t.Errorf("PRIVASYS_AUDIENCE=%q: got %q, want %q", c.env, got, c.want)
		}
	}
	t.Setenv("OIDC_AUDIENCE", "x,y")
	if got := defaultAudience("abc"); got != "x,y" {
		t.Errorf("OIDC_AUDIENCE override: got %q", got)
	}
}

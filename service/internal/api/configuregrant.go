package api

import (
	"net/http"
	"os"
	"strings"

	"github.com/Privasys/drive/service/internal/oidc"
)

// The runtime's configure gate (enclave-os-virtual) checks the caller's
// platform bearer for the owner or admin role on this app, withholds the
// bearer from the container, and states the result instead:
//
//	X-Privasys-Configure-Authorized: role=<owner|admin>; sub=<subject>
//
// Only the runtime writes it, and it removes a client-sent copy, but only on
// a runtime that implements it. That runtime says so through its launcher
// (PRIVASYS_CONFIGURE_GRANT=1); anywhere else the header is forgeable and is
// ignored, and configure keeps the bearer check.
const (
	configureGrantHeader = "X-Privasys-Configure-Authorized"
	configureGrantEnv    = "PRIVASYS_CONFIGURE_GRANT"
)

// viaConfigureGrant is a principal the runtime's configure gate vouched for.
const viaConfigureGrant authVia = "configure-grant"

func runtimeStatesConfigureGrant() bool {
	return strings.TrimSpace(os.Getenv(configureGrantEnv)) == "1"
}

// parseConfigureGrant reads the header strictly: exactly role and sub, in
// that order, role owner or admin, sub non-empty and free of separators.
func parseConfigureGrant(v string) (role, sub string, ok bool) {
	parts := strings.Split(v, ";")
	if len(parts) != 2 {
		return "", "", false
	}
	r, okR := strings.CutPrefix(strings.TrimSpace(parts[0]), "role=")
	s, okS := strings.CutPrefix(strings.TrimSpace(parts[1]), "sub=")
	if !okR || !okS || (r != "owner" && r != "admin") {
		return "", "", false
	}
	if s == "" || strings.ContainsAny(s, " \t\r\n;,=\"") {
		return "", "", false
	}
	return r, s, true
}

// configureAuth authenticates the configure route: the runtime's statement
// when the runtime states one, otherwise the bearer check (s.auth).
func (s *Server) configureAuth(next func(http.ResponseWriter, *http.Request, *Principal)) http.Handler {
	fallback := s.auth(next)
	next = s.refuseRetired(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get(configureGrantHeader)
		if !runtimeStatesConfigureGrant() {
			// Not this runtime's statement: whatever a client sent goes.
			r.Header.Del(configureGrantHeader)
			fallback.ServeHTTP(w, r)
			return
		}
		if v == "" {
			fallback.ServeHTTP(w, r)
			return
		}
		role, sub, ok := parseConfigureGrant(v)
		if !ok {
			http.Error(w, "malformed "+configureGrantHeader, http.StatusUnauthorized)
			return
		}
		next(w, r, &Principal{
			Sub: sub, Via: viaConfigureGrant,
			ID: &oidc.Identity{Sub: sub, Roles: []string{role}},
		})
	})
}

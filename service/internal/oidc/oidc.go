// Package oidc verifies bearer tokens from privasys.id.
//
// Production builds plug in a JWKS-backed verifier (golang-jwt/jwt/v5
// + MicahParks/keyfunc); the dev verifier accepts a static shared
// secret so smoke tests can run without a working IDP.
package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Identity is the result of verifying a token.
type Identity struct {
	Sub      string
	Issuer   string
	Audience string
	Email    string
	// Roles carries the platform `roles` claim (audience-filtered by the
	// IdP); the configure-authz check reads the per-app owner/admin roles
	// from here.
	Roles []string
	// SID is the IdP session the token is bound to (the revocation
	// handle for long-lived API keys). Empty for session-less tokens.
	SID string
}

// HasRole reports whether the token carried the given role.
func (id *Identity) HasRole(role string) bool {
	for _, r := range id.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Verifier validates a bearer token and returns the carrier's identity.
type Verifier interface {
	Verify(ctx context.Context, token string) (*Identity, error)
}

// DevVerifier is a stub verifier suitable ONLY for `--dev` and tests.
// It accepts tokens of the form "dev:<sub>:<email>".
type DevVerifier struct{}

func (DevVerifier) Verify(ctx context.Context, token string) (*Identity, error) {
	if !strings.HasPrefix(token, "dev:") {
		return nil, errors.New("oidc: dev verifier expects 'dev:<sub>:<email>'")
	}
	rest := strings.TrimPrefix(token, "dev:")
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) < 1 || parts[0] == "" {
		return nil, fmt.Errorf("oidc: malformed dev token %q", token)
	}
	id := &Identity{Sub: parts[0], Issuer: "dev://privasys.id", Audience: "privasys-drive"}
	if len(parts) == 2 {
		id.Email = parts[1]
	}
	return id, nil
}

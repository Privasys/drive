package vaultmek

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// PrincipalMismatch reports whether a Load/Unwrap error is the vault
// refusing the caller's TEE identity against policy.principals — the
// signature of a measurement change the data owner has not yet
// approved (an app-image or enclave-os upgrade). Distinct from a
// transport or verification failure, which approval cannot fix.
func PrincipalMismatch(err error) bool {
	return err != nil && strings.Contains(err.Error(), "caller is not in policy.principals")
}

// TeesFromGrant extracts the TEE principal set from a key-creation
// grant. The grant is the IdP-signed JWT the control plane mints for
// the data owner; its payload carries the full key policy — including
// the tees profile for the app's CURRENT attested measurement. The
// signature is NOT verified here: the extracted tees are only ever
// submitted through UpdatePolicy, which the vault authorises against
// the key OWNER's bearer — a forged grant grants nothing the owner
// could not already do.
func TeesFromGrant(grant string) ([]vsdk.Principal, error) {
	parts := strings.Split(grant, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("vaultmek: grant is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("vaultmek: decode grant payload: %w", err)
	}
	var claims struct {
		Policy vsdk.KeyPolicy `json:"policy"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("vaultmek: parse grant policy: %w", err)
	}
	if len(claims.Policy.Principals.Tees) == 0 {
		return nil, fmt.Errorf("vaultmek: grant policy carries no TEE principals")
	}
	return claims.Policy.Principals.Tees, nil
}

// RefreshTees replaces principals.tees on the key's policy with the
// grant's tees profile, on EVERY constellation member, authenticated
// as the key owner. This is the owner's measurement approval: after an
// app upgrade the key's pinned profile no longer matches the running
// enclave, and only the data owner may bless the new one (the policy's
// OwnerCan: FieldTees). On a sovereign instance the owner is the
// tenant; on an escrowed instance the org key's owner is the instance
// operator. The rest of the policy is preserved as stored.
func (c *Client) RefreshTees(ctx context.Context, ref Ref, grant, ownerBearer string) error {
	if ownerBearer == "" {
		return fmt.Errorf("vaultmek: measurement approval requires the owner's bearer")
	}
	tees, err := TeesFromGrant(grant)
	if err != nil {
		return err
	}
	var failed []string
	for _, ep := range ref.Endpoints {
		if err := c.refreshTeesOn(ctx, ep, ref, tees, ownerBearer); err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", ep, err))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("vaultmek: measurement approval incomplete: %s", strings.Join(failed, "; "))
	}
	// The stale principal may be cached as a failed load; nothing to
	// evict (only successful loads are cached), but drop any cached MEK
	// for the handle so the next Load re-proves the path end-to-end.
	c.mu.Lock()
	delete(c.meks, ref.Handle)
	c.mu.Unlock()
	return nil
}

func (c *Client) refreshTeesOn(ctx context.Context, endpoint string, ref Ref, tees []vsdk.Principal, ownerBearer string) error {
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	vc, err := c.dialAs(ctx, endpoint, ref.MrenclaveHex, ref.AttServer, tok, ownerBearer)
	if err != nil {
		return err
	}
	defer vc.Close()
	policy, _, err := vc.GetPolicy(ctx, ref.Handle)
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	policy.Principals.Tees = tees
	if _, err := vc.UpdatePolicy(ctx, ref.Handle, policy); err != nil {
		return fmt.Errorf("update policy: %w", err)
	}
	return nil
}

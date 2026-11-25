package vaultmek

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// ErrRestageNeeded means Drive has no record of the key's stored policy, so
// it cannot build a measurement approval for it without reading the policy
// as the owner, which it never does. The key must be re-staged (a new
// generation, whose policy Drive records at creation).
var ErrRestageNeeded = errors.New("vaultmek: re-stage needed: the key's policy is not on record, so its measurement cannot be approved")

// ReadStoredPolicy reads the key's stored policy from every member, as the
// enclave (no person's credential), while the enclave is still one of the
// key's principals: right after a create, an update or a successful load.
// Every member must return byte-identical bytes and the same version.
func (c *Client) ReadStoredPolicy(ctx context.Context, ref Ref) (json.RawMessage, uint32, error) {
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	var (
		policy  json.RawMessage
		version uint32
	)
	for _, ep := range ref.Endpoints {
		vc, err := c.dial(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok)
		if err != nil {
			return nil, 0, fmt.Errorf("vaultmek: stored policy: dial %s: %w", ep, err)
		}
		raw, v, rerr := vc.GetPolicyRaw(ctx, ref.Handle)
		vc.Close()
		if rerr != nil {
			return nil, 0, fmt.Errorf("vaultmek: stored policy: read on %s: %w", ep, rerr)
		}
		if policy == nil {
			policy, version = raw, v
		} else if !bytes.Equal(raw, policy) || v != version {
			return nil, 0, fmt.Errorf("vaultmek: stored policy: the vaults disagree on the policy of %s", ref.Handle)
		}
	}
	if policy == nil {
		return nil, 0, fmt.Errorf("vaultmek: stored policy: the key has no vaults")
	}
	return policy, version, nil
}

// unionTees returns cur with every principal of add that it does not
// already hold appended: a runtime roll ADDS the new measurement next to
// the running one, so the previous build can still open the key until the
// roll is settled and the old one is retired as a separate step.
func unionTees(cur, add []vsdk.Principal) []vsdk.Principal {
	out := append([]vsdk.Principal(nil), cur...)
	seen := map[string]bool{}
	for _, p := range cur {
		b, _ := json.Marshal(p)
		seen[string(b)] = true
	}
	for _, p := range add {
		b, _ := json.Marshal(p)
		if !seen[string(b)] {
			seen[string(b)] = true
			out = append(out, p)
		}
	}
	return out
}

// withPolicy records on a freshly created ref the policy its vaults now
// hold. Best effort: a key whose policy could not be read back is still
// usable, and its policy is recorded at its next successful load.
func (c *Client) withPolicy(ctx context.Context, ref Ref) Ref {
	p, v, err := c.ReadStoredPolicy(ctx, ref)
	if err != nil {
		log.Printf("vaultmek: %s created, but its policy could not be read back yet: %v", ref.Handle, err)
		return ref
	}
	ref.Policy, ref.PolicyVersion = p, v
	return ref
}

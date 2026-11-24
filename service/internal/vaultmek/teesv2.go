package vaultmek

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// A key whose policy asks for binding v2 on UpdatePolicy (a key created on a
// constellation that holds owner operations to a wallet approval) takes a
// measurement approval bound to its exact content: the approval names the
// digest of the new policy, the policy version it replaces and the member set
// of the constellation (wallet-signed-authority-wire-formats.md §5). The
// owner's plain bearer is not enough there, so Drive asks the holder's wallet
// straight away.

// ErrPolicyNotLossless means the key's policy has something the vault
// client's typed policy cannot carry, so Drive cannot rebuild it faithfully.
var ErrPolicyNotLossless = errors.New("vaultmek: approval v2: the key's policy does not survive the typed round trip; refusing to build an update that could drop a restriction")

// TeesApprovalV2 is what a binding-v2 measurement approval is made of.
type TeesApprovalV2 struct {
	// NewPolicy is the key's current policy with principals.tees replaced
	// by the grant's profile: the policy the holder approves and Drive sends.
	NewPolicy vsdk.KeyPolicy
	// NewPolicyJSON is NewPolicy exactly as the update request carries it.
	NewPolicyJSON json.RawMessage
	// Target is PD(NewPolicyJSON).
	Target string
	// PolicyVersion is the version the update replaces.
	PolicyVersion uint32
	// Members are the constellation's member ids, sorted.
	Members []string
	// Identities are the members' GetVaultIdentity answers, for the IdP.
	Identities []vsdk.VaultIdentity
}

// NeedsBindingV2 reports whether an Owner UpdatePolicy on a key with this
// policy takes a binding-v2 approval.
func NeedsBindingV2(p vsdk.KeyPolicy) bool {
	for _, r := range p.Operations {
		updates := false
		for _, op := range r.Ops {
			if op == vsdk.OpUpdatePolicy {
				updates = true
			}
		}
		if !updates {
			continue
		}
		for _, c := range r.Requires {
			if c.OidcStepUp != nil && c.OidcStepUp.Binding == 2 {
				return true
			}
		}
	}
	return false
}

// PrepareTeesApprovalV2 reads the key's policy from every member (they must
// agree), and returns nil when the key does not take binding v2. Otherwise
// it builds the new policy from the grant's tees and gathers the member
// identities the approval binds to.
func (c *Client) PrepareTeesApprovalV2(ctx context.Context, ref Ref, grant string) (*TeesApprovalV2, error) {
	tees, err := TeesFromGrant(grant)
	if err != nil {
		return nil, err
	}
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	var (
		cur     *vsdk.KeyPolicy
		version uint32
		digest  string
		ids     []vsdk.VaultIdentity
	)
	for _, ep := range ref.Endpoints {
		vc, derr := c.dial(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok)
		if derr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: dial %s: %w", ep, derr)
		}
		p, v, perr := vc.GetPolicy(ctx, ref.Handle)
		var (
			id                    vsdk.VaultIdentity
			ierr, rerr, cerr      error
			raw, typed, canonical json.RawMessage
		)
		if perr == nil && NeedsBindingV2(p) {
			id, ierr = vc.GetVaultIdentity(ctx)
			raw, _, rerr = vc.GetPolicyRaw(ctx, ref.Handle)
			// The vault's own canonical form of the typed round trip: it
			// writes back every field at its default, as GetPolicy does, so
			// it equals the stored policy unless the typed form dropped
			// something (formats §5.1).
			if typed, cerr = json.Marshal(p); cerr == nil {
				canonical, _, cerr = vc.CanonicalPolicy(ctx, typed)
			}
		}
		vc.Close()
		if perr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: read policy on %s: %w", ep, perr)
		}
		d, derr := vsdk.PolicyDigest(p)
		if derr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: policy digest on %s: %w", ep, derr)
		}
		if NeedsBindingV2(p) {
			// The new policy is built from the typed policy. Refuse unless
			// the typed round trip is lossless: a field the client does not
			// know would otherwise vanish from the policy the owner approves.
			if rerr != nil {
				return nil, fmt.Errorf("vaultmek: approval v2: read raw policy on %s: %w", ep, rerr)
			}
			if cerr != nil {
				return nil, fmt.Errorf("vaultmek: approval v2: canonicalise policy on %s: %w", ep, cerr)
			}
			stored, serr := vsdk.PolicyDigestJSON(raw)
			if serr != nil {
				return nil, fmt.Errorf("vaultmek: approval v2: stored policy digest on %s: %w", ep, serr)
			}
			canon, cderr := vsdk.PolicyDigestJSON(canonical)
			if cderr != nil {
				return nil, fmt.Errorf("vaultmek: approval v2: canonical policy digest on %s: %w", ep, cderr)
			}
			if stored != canon {
				return nil, fmt.Errorf("%w on %s", ErrPolicyNotLossless, ep)
			}
		}
		if cur == nil {
			cur, version, digest = &p, v, d
		} else if d != digest || v != version {
			return nil, fmt.Errorf("vaultmek: approval v2: the vaults disagree on the policy of %s", ref.Handle)
		}
		if !NeedsBindingV2(p) {
			continue
		}
		if ierr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: identity of %s: %w", ep, ierr)
		}
		ids = append(ids, id)
	}
	if cur == nil || !NeedsBindingV2(*cur) {
		return nil, nil
	}
	np := *cur
	np.Principals.Tees = tees
	raw, err := json.Marshal(np)
	if err != nil {
		return nil, err
	}
	target, err := vsdk.PolicyDigestJSON(raw)
	if err != nil {
		return nil, fmt.Errorf("vaultmek: approval v2: new policy digest: %w", err)
	}
	members := make([]string, 0, len(ids))
	for _, id := range ids {
		members = append(members, strings.ToLower(id.MemberID))
	}
	sort.Strings(members)
	return &TeesApprovalV2{
		NewPolicy: np, NewPolicyJSON: raw, Target: target,
		PolicyVersion: version, Members: members, Identities: ids,
	}, nil
}

// RefreshTeesV2 sends the approved policy update to every member, with the
// holder's approval token as both the owner bearer and the approval, and the
// member set the vault rebuilds the approval's text from.
func (c *Client) RefreshTeesV2(ctx context.Context, ref Ref, a *TeesApprovalV2, approval string) error {
	if approval == "" {
		return fmt.Errorf("vaultmek: a binding-v2 measurement approval needs the holder's approval token")
	}
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	var failed []string
	for _, ep := range ref.Endpoints {
		vc, err := c.dialWith(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok, approval, a.Members)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", ep, err))
			continue
		}
		_, uerr := vc.UpdatePolicy(ctx, ref.Handle, a.NewPolicy, vsdk.ApprovalToken{JWT: approval})
		vc.Close()
		if uerr != nil {
			failed = append(failed, fmt.Sprintf("%s: update policy: %v", ep, uerr))
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("vaultmek: measurement approval incomplete: %s", strings.Join(failed, "; "))
	}
	c.mu.Lock()
	delete(c.meks, ref.Handle)
	c.mu.Unlock()
	return nil
}

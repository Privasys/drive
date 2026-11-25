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
	// Target is PD(NewPolicyJSON), or on an update_policy_from the target
	// that binds both the replaced policy and the new one.
	Target string
	// From is set when every member lists update-policy-from-v1: the
	// approval is an update_policy_from (formats §5.3), binding the policy
	// replaced (CurrentPolicyJSON, the vaults' own serialisation, whose
	// digest is ReplacedPD) as well as the new one.
	From              bool
	CurrentPolicyJSON json.RawMessage
	ReplacedPD        string
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
// agree) as the owner: ownerBearer is the token of the person re-arming,
// which names the account (empty dials as the enclave, which the vault
// answers only while its measurement is still a principal). It returns nil
// when the key does not take binding v2. Otherwise it builds the new policy
// from the grant's tees and gathers the member identities the approval
// binds to.
func (c *Client) PrepareTeesApprovalV2(ctx context.Context, ref Ref, grant, ownerBearer string) (*TeesApprovalV2, error) {
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
		curRaw  json.RawMessage
		curPD   string
	)
	for _, ep := range ref.Endpoints {
		// As the owner: after a measurement change the enclave is no longer
		// a principal of the key, and the vault reads a policy only to one.
		vc, derr := c.dialAs(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok, ownerBearer)
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
			// The policy being replaced, as the vaults serialise it: the
			// "before" an update_policy_from binds (formats §5.3).
			if curRaw == nil {
				curRaw, curPD = raw, stored
			} else if stored != curPD {
				return nil, fmt.Errorf("vaultmek: approval v2: the vaults disagree on the stored policy of %s", ref.Handle)
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
	typed, err := json.Marshal(np)
	if err != nil {
		return nil, err
	}
	// The new policy goes out in the vault's own stored form, every field
	// written, as CanonicalisePolicy returns it: the form the current policy
	// is read in, so the wallet compares like with like and shows only what
	// changes, and the form a vault from v0.44.0 requires. Every member must
	// return the same.
	raw, target, err := c.canonicalNewPolicy(ctx, ref, tok, ownerBearer, typed)
	if err != nil {
		return nil, err
	}
	members := make([]string, 0, len(ids))
	from := len(ids) > 0
	for _, id := range ids {
		members = append(members, strings.ToLower(id.MemberID))
		if !id.Has(vsdk.CapabilityUpdatePolicyFrom) {
			from = false
		}
	}
	sort.Strings(members)
	a := &TeesApprovalV2{
		NewPolicy: np, NewPolicyJSON: raw, Target: target,
		PolicyVersion: version, Members: members, Identities: ids,
	}
	if from {
		// Every member takes update_policy_from: bind the policy replaced
		// too, so the wallet can show a difference it can trust.
		ft, ferr := vsdk.UpdatePolicyFromTarget(curPD, target)
		if ferr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: %w", ferr)
		}
		a.From, a.Target, a.CurrentPolicyJSON, a.ReplacedPD = true, ft, curRaw, curPD
	}
	return a, nil
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
		// The exact bytes the holder approved (PD binds them).
		var uerr error
		if a.From {
			_, uerr = vc.UpdatePolicyRawFrom(ctx, ref.Handle, a.NewPolicyJSON, a.ReplacedPD, vsdk.ApprovalToken{JWT: approval})
		} else {
			_, uerr = vc.UpdatePolicyRaw(ctx, ref.Handle, a.NewPolicyJSON, vsdk.ApprovalToken{JWT: approval})
		}
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

// canonicalNewPolicy asks every member for its canonical form of a new
// policy and returns those bytes with their digest; the members must agree,
// and the digest of the bytes must be the one the vault reports.
func (c *Client) canonicalNewPolicy(ctx context.Context, ref Ref, tok, ownerBearer string, policy json.RawMessage) (json.RawMessage, string, error) {
	var (
		canon json.RawMessage
		pd    string
	)
	for _, ep := range ref.Endpoints {
		vc, err := c.dialAs(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok, ownerBearer)
		if err != nil {
			return nil, "", fmt.Errorf("vaultmek: approval v2: dial %s: %w", ep, err)
		}
		cp, vpd, cerr := vc.CanonicalPolicy(ctx, policy)
		vc.Close()
		if cerr != nil {
			return nil, "", fmt.Errorf("vaultmek: approval v2: canonicalise the new policy on %s: %w", ep, cerr)
		}
		d, derr := vsdk.PolicyDigestJSON(cp)
		if derr != nil || d != strings.ToLower(vpd) {
			return nil, "", fmt.Errorf("vaultmek: approval v2: %s's canonical policy does not match its digest", ep)
		}
		if canon == nil {
			canon, pd = cp, d
		} else if d != pd {
			return nil, "", fmt.Errorf("vaultmek: approval v2: the vaults disagree on the canonical form of the new policy")
		}
	}
	if canon == nil {
		return nil, "", fmt.Errorf("vaultmek: approval v2: the key has no vaults")
	}
	return canon, pd, nil
}

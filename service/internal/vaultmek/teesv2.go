package vaultmek

import (
	"bytes"
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

// PrepareTeesApprovalV2 builds the approval a measurement change takes, from
// the key's policy as Drive last saw its vaults confirm it (ref.Policy), and
// never with a person's credential: every vault call here is the enclave's
// own (CanonicalisePolicy and GetVaultIdentity need no principal). It
// returns nil for a key whose rule does not take binding v2 (the v1
// approval), ErrRestageNeeded when the policy is not on record, and an
// error, never a fallback, when a binding-2 plan cannot be built. The new
// policy is the current one with the grant's measurement ADDED to its tees.
func (c *Client) PrepareTeesApprovalV2(ctx context.Context, ref Ref, grant string) (*TeesApprovalV2, error) {
	if len(ref.Policy) == 0 {
		return nil, ErrRestageNeeded
	}
	var cur vsdk.KeyPolicy
	if err := json.Unmarshal(ref.Policy, &cur); err != nil {
		return nil, fmt.Errorf("vaultmek: approval v2: the recorded policy does not parse: %w", err)
	}
	if !NeedsBindingV2(cur) {
		return nil, nil
	}
	tees, err := TeesFromGrant(grant)
	if err != nil {
		return nil, err
	}
	curPD, err := vsdk.PolicyDigestJSON(ref.Policy)
	if err != nil {
		return nil, fmt.Errorf("vaultmek: approval v2: recorded policy digest: %w", err)
	}
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	// The typed round trip must be lossless: the vaults' stored form of the
	// typed current policy must have the recorded policy's digest, or a
	// field the client does not know would vanish from what the holder
	// approves.
	typedCur, err := json.Marshal(cur)
	if err != nil {
		return nil, err
	}
	_, samePD, err := c.canonicalNewPolicy(ctx, ref, tok, "", typedCur)
	if err != nil {
		return nil, err
	}
	if samePD != curPD {
		return nil, ErrPolicyNotLossless
	}
	np := cur
	np.Principals.Tees = unionTees(cur.Principals.Tees, tees)
	typed, err := json.Marshal(np)
	if err != nil {
		return nil, err
	}
	raw, target, err := c.canonicalNewPolicy(ctx, ref, tok, "", typed)
	if err != nil {
		return nil, err
	}
	var ids []vsdk.VaultIdentity
	for _, ep := range ref.Endpoints {
		vc, derr := c.dial(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok)
		if derr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: dial %s: %w", ep, derr)
		}
		id, ierr := vc.GetVaultIdentity(ctx)
		vc.Close()
		if ierr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: %s: identity: %w", ep, ierr)
		}
		ids = append(ids, id)
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
		PolicyVersion: ref.PolicyVersion, Members: members, Identities: ids,
	}
	if from {
		ft, ferr := vsdk.UpdatePolicyFromTarget(curPD, target)
		if ferr != nil {
			return nil, fmt.Errorf("vaultmek: approval v2: %w", ferr)
		}
		a.From, a.Target, a.CurrentPolicyJSON, a.ReplacedPD = true, ft, ref.Policy, curPD
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

// canonicaliser is the one vault call canonicalNewPolicy needs.
type canonicaliser interface {
	CanonicalPolicy(ctx context.Context, policy json.RawMessage) (json.RawMessage, string, error)
}

// canonicalNewPolicy returns the new policy in the vaults' stored form, with
// its digest, as every member of the key's constellation agrees on it.
func (c *Client) canonicalNewPolicy(ctx context.Context, ref Ref, tok, ownerBearer string, policy json.RawMessage) (json.RawMessage, string, error) {
	open := func(ep string) (canonicaliser, func(), error) {
		vc, err := c.dialAs(ctx, ep, ref.MrenclaveHex, ref.AttServer, tok, ownerBearer)
		if err != nil {
			return nil, nil, err
		}
		return vc, func() { vc.Close() }, nil
	}
	return canonicalAcross(ctx, ref.Endpoints, open, policy)
}

// canonicalAcross asks every member for its stored form of a new policy.
// Every member must return byte-identical bytes, so the digest the holder
// approves is PD of exactly what the update sends.
func canonicalAcross(ctx context.Context, endpoints []string, open func(string) (canonicaliser, func(), error), policy json.RawMessage) (json.RawMessage, string, error) {
	var (
		stored json.RawMessage
		pd     string
	)
	for _, ep := range endpoints {
		cz, closeFn, err := open(ep)
		if err != nil {
			return nil, "", fmt.Errorf("vaultmek: approval v2: dial %s: %w", ep, err)
		}
		cp, d, serr := storedForm(ctx, cz, policy)
		closeFn()
		if serr != nil {
			return nil, "", fmt.Errorf("vaultmek: approval v2: %s: %w", ep, serr)
		}
		if stored == nil {
			stored, pd = cp, d
		} else if !bytes.Equal(cp, stored) {
			return nil, "", fmt.Errorf("vaultmek: approval v2: %s: the vaults return different stored forms of the new policy", ep)
		}
	}
	if stored == nil {
		return nil, "", fmt.Errorf("vaultmek: approval v2: the key has no vaults")
	}
	return stored, pd, nil
}

// storedForm asks one member twice: first for its stored form of the policy,
// then to check those exact bytes as stored form. A vault from v0.44.0
// reports the digest of the policy AS SENT and refuses anything not already
// in stored form; an older one reports the digest of what it returns. On
// both, the second answer must be byte-identical to the first and its digest
// must be PD of those bytes.
func storedForm(ctx context.Context, cz canonicaliser, policy json.RawMessage) (json.RawMessage, string, error) {
	cp, _, err := cz.CanonicalPolicy(ctx, policy)
	if err != nil {
		return nil, "", fmt.Errorf("stored form of the new policy: %w", err)
	}
	again, vpd, err := cz.CanonicalPolicy(ctx, cp)
	if err != nil {
		return nil, "", fmt.Errorf("check of the stored form: %w", err)
	}
	if !bytes.Equal(again, cp) {
		return nil, "", errors.New("the stored form is not stable")
	}
	d, err := vsdk.PolicyDigestJSON(cp)
	if err != nil || d != strings.ToLower(vpd) {
		return nil, "", errors.New("the stored form does not match its digest")
	}
	return cp, d, nil
}

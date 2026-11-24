package vaultmek

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// carriedRenewal reads the policy of the key at src from every one of its
// vaults (they must agree), and returns the renewal that makes a new key
// carry it: the policy verbatim with its version, the source key's type and
// exportable flag (all vaults must agree on them too), the source's billing id
// and a key check over the new key's whole value. A carried policy is the
// key's own, so the owner's approvals and TEE profile ride along instead of
// being re-authored from a fresh grant.
func (c *Client) carriedRenewal(ctx context.Context, src Ref, secret []byte) (vsdk.Renewal, error) {
	tok := src.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	var (
		policy    json.RawMessage
		version   uint32
		digest    string
		billingID string
		info      *vsdk.KeyInfo
	)
	for _, ep := range src.Endpoints {
		vc, err := c.dial(ctx, ep, src.MrenclaveHex, src.AttServer, tok)
		if err != nil {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: dial source %s: %w", ep, err)
		}
		p, v, perr := vc.GetPolicyRaw(ctx, src.Handle)
		var ki vsdk.KeyInfo
		var kerr error
		if perr == nil {
			ki, kerr = vc.GetKeyInfo(ctx, src.Handle)
		}
		if perr == nil && billingID == "" {
			if id, ierr := vc.GetVaultIdentity(ctx); ierr == nil {
				billingID = id.BillingID
			}
		}
		vc.Close()
		if perr != nil {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: read policy on %s: %w", ep, perr)
		}
		d, derr := vsdk.PolicyDigestJSON(p)
		if derr != nil {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: policy digest on %s: %w", ep, derr)
		}
		if kerr != nil {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: read key info on %s: %w", ep, kerr)
		}
		if info == nil {
			info = &ki
		} else if ki.KeyType != info.KeyType || ki.Exportable != info.Exportable {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: source vaults disagree on the type or exportability of %s", src.Handle)
		}
		if policy == nil {
			policy, version, digest = p, v, d
		} else if d != digest || v != version {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: source vaults disagree on the policy of %s", src.Handle)
		}
	}
	if policy == nil {
		return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: the source ref has no vaults")
	}
	if billingID == "" {
		// A vault from before the identity call: its billing id is the
		// implicit one of the SOURCE constellation's issuer and audience,
		// as recorded with the ref (never the target's: these values exist
		// to catch a mistake, and a default would hide it).
		if src.Issuer == "" || src.Audience == "" {
			return vsdk.Renewal{}, fmt.Errorf("vaultmek: carry: the source vaults have no identity and the source issuer or audience is unknown")
		}
		billingID = vsdk.ImplicitBillingID(src.Issuer, src.Audience)
	}
	kc, err := vsdk.NewKeyCheck(secret)
	if err != nil {
		return vsdk.Renewal{}, err
	}
	return vsdk.Renewal{
		Policy: policy, PolicyVersion: version,
		SourceBillingID: billingID, KeyCheck: &kc,
		CarriedExportable: &info.Exportable, CarriedKeyType: info.KeyType,
	}, nil
}

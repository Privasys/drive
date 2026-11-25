package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"strings"

	"github.com/Privasys/drive/service/internal/vaultmek"
)

// The holder approves a Drive upgrade for their key, in their wallet.
//
// After a measurement change the vault accepts the new measurement only
// with the holder's approval. Drive never holds the holder's credential:
// the re-arm answers 409 owner_approval_required with the approval request
// (approvalRequest). The CALLER, which holds the holder's session (web
// front, wallet, CLI), sends it to privasys.id's vault-approval begin with
// that session, the holder taps, the caller collects the approval token and
// re-posts the re-arm with it as approval_token. That token, bound to the
// operation, is the only authority Drive presents to the vaults.

// approvalRequest is the body the caller sends to privasys.id's
// POST /fido2/vault-approval/begin for this key. v2 nil is the v1
// "policy-update" approval (a key whose rule does not take binding 2).
// audience is the key's constellation audience: the approval token must
// carry it for those vaults to accept it.
func approvalRequest(handle, audience string, v2 *vaultmek.TeesApprovalV2) map[string]any {
	in := map[string]any{
		"operation":   "policy-update",
		"handle":      handle,
		"ttl_seconds": 300,
		"context": map[string]any{
			"app_name": "Privasys Drive",
			"key_type": "Your Drive key",
			"source":   "Privasys Drive was updated; approve the new version to keep opening your files.",
		},
	}
	if v2 != nil {
		// Binding v2: the approval is bound to the exact new policy, the
		// version it replaces and the constellation's members; the wallet
		// verifies each member's identity quote and shows the policy.
		in["binding_version"] = 2
		in["operation"] = "update_policy"
		in["target"] = v2.Target
		in["policy_version"] = v2.PolicyVersion
		in["members"] = v2.Members
		in["member_identities"] = v2.Identities
		in["issuer_index"] = 0
		in["new_policy"] = v2.NewPolicyJSON
		// What the approval is for, in words: the wallet shows it as given.
		in["context"].(map[string]any)["summary"] = "Let Privasys Drive open your Drive key with its updated build."
		if v2.From {
			// update_policy_from (formats §5.3): the policy replaced, as the
			// vaults serialise it, so the wallet can show the difference.
			in["operation"] = "update_policy_from"
			in["current_policy"] = v2.CurrentPolicyJSON
		}
	}
	if audience != "" {
		in["audience"] = audience
	}
	return in
}

// isApprovalToken reports whether tok is a vault-approval token: a JWT
// bound to an operation (a vault_op claim). Only such a token is taken as
// approval_token; the vaults verify it in full. Read without verification:
// the answer only refuses.
func isApprovalToken(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return false
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	op, _ := claims["vault_op"].(string)
	return op != ""
}

// teesV2Provider is the binding-v2 measurement approval (vaultmek/teesv2.go):
// vaultmek.Client implements it; a provider without it takes the v1 path.
type teesV2Provider interface {
	PrepareTeesApprovalV2(ctx context.Context, ref vaultmek.Ref, grant string) (*vaultmek.TeesApprovalV2, error)
	RefreshTeesV2(ctx context.Context, ref vaultmek.Ref, a *vaultmek.TeesApprovalV2, approval string) error
}

// policyRecorder reads a key's stored policy back from its vaults, as the
// enclave (vaultmek.Client implements it).
type policyRecorder interface {
	ReadStoredPolicy(ctx context.Context, ref vaultmek.Ref) (json.RawMessage, uint32, error)
}

// recordKeyPolicy stores on the tenant's key ref the policy its vaults hold,
// read back as the enclave (never what Drive meant to send). force re-reads
// it even when one is on record, after an update. Best effort: a failure is
// logged and the record is left as it was; a measurement change on a key
// with no record answers "re-stage needed", never a guess.
func (s *Server) recordKeyPolicy(ctx context.Context, tenantID string, force bool) {
	pr, ok := s.MEKs.(policyRecorder)
	if !ok {
		return
	}
	raw, err := s.Store.TenantMekRef(ctx, tenantID)
	if err != nil || raw == "" {
		return
	}
	ref, err := vaultmek.ParseRef(raw)
	if err != nil || (!force && len(ref.Policy) > 0) {
		return
	}
	p, v, err := pr.ReadStoredPolicy(ctx, ref)
	if err != nil {
		log.Printf("tenantkey: the policy of %s could not be recorded: %v", ref.Handle, err)
		return
	}
	ref.Policy, ref.PolicyVersion = p, v
	if err := s.Store.SetTenantMekRef(ctx, tenantID, vaultmek.RefJSON(ref)); err != nil {
		log.Printf("tenantkey: recording the policy of %s failed: %v", ref.Handle, err)
	}
}

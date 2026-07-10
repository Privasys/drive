package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/store"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// Escrowed-mode recovery gate (Mode A). A recovery is REQUESTED by a
// policy-permitted requester, APPROVED by k distinct approvers, and
// EXECUTED automatically at quorum: the tenant's escrow-wrapped MEK is
// unwrapped under MEK_org in-enclave and a time-bounded tenant-wide
// read grant is minted for the grantee. Everything is audited and the
// audit is disclosed to the affected tenant.
//
// Approval verification is hybrid:
//   - privasys.id issuer: the approval MUST be an operation-bound
//     WebAuthn ceremony token (amr=webauthn) whose vault_op claim binds
//     THIS recovery's digest — a stolen bearer or a captured approval
//     for another recovery is useless.
//   - any other configured issuer (the org's own IdP): a fresh (<5 min)
//     bearer from that issuer whose sub is a permitted approver;
//     single-use per token (jti or token hash), one approval per
//     approver.

// recoveryDigestDomain versions the recovery digest derivation.
const recoveryDigestDomain = "privasys-drive-recovery/v1"

// ceremonyBindingDomain MUST equal the IdP's vaultApprovalDomain — the
// approval token's vault_op is the base64url SHA-256 of the
// newline-joined tuple under this domain.
const ceremonyBindingDomain = "privasys-vault-approval/v1"

// recoveryRequestWindow is how long a pending recovery accepts
// approvals before it lapses.
const recoveryRequestWindow = 24 * time.Hour

// recoveryDigest is the operation digest approvals bind: it commits to
// the recovery id, tenant, grantee and reason, so an approval cannot be
// replayed for a different recovery or a doctored grantee.
func recoveryDigest(rid, tenantID, granteeSub, reason string) string {
	input := fmt.Sprintf("%s\n%s\n%s\n%s\n%s", recoveryDigestDomain, rid, tenantID, granteeSub, reason)
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:])
}

// ceremonyHandle is the app-scoped operation URI the privasys.id
// ceremony binds (IdP operation "app-recovery").
func (s *Server) ceremonyHandle(rid string) string {
	return "app:" + s.Platform.AppIDHex() + ":recover:" + rid
}

// ceremonyBinding recomputes the IdP's operation binding for this
// recovery from the approval token's nonce and exp.
func (s *Server) ceremonyBinding(rid, digestHex, nonce string, exp int64) string {
	input := fmt.Sprintf("%s\n%s\n%s\n%d\n%s\n%d",
		ceremonyBindingDomain, s.ceremonyHandle(rid), digestHex, uint64(0), nonce, exp)
	sum := sha256.Sum256([]byte(input))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// recoveryVerifier lazily builds one JWKS verifier per configured
// recovery issuer (the org's IdP is not necessarily privasys.id).
func (s *Server) recoveryVerifier(issuer string) oidc.Verifier {
	if s.DevMode {
		return s.Verifier // tests use the dev verifier for all issuers
	}
	s.recVerMu.Lock()
	defer s.recVerMu.Unlock()
	if s.recVer == nil {
		s.recVer = map[string]oidc.Verifier{}
	}
	v, ok := s.recVer[issuer]
	if !ok {
		v = oidc.NewJWKSVerifier(issuer, "") // aud varies per org; binding/freshness carry the authority
		s.recVer[issuer] = v
	}
	return v
}

// verifyRecoveryApproval validates one approval token against the
// policy and THIS recovery, returning the approver subject and the
// single-use key for replay protection.
func (s *Server) verifyRecoveryApproval(ctx context.Context, pol *config.RecoveryPolicy, rec *store.Recovery, token string) (sub, jti string, err error) {
	id, verr := s.recoveryVerifier(pol.Issuer).Verify(ctx, token)
	if verr != nil {
		return "", "", fmt.Errorf("approval token: %w", verr)
	}
	if !pol.ApproverAllowed(id.Sub, id.Roles) {
		return "", "", fmt.Errorf("subject %s is not a permitted approver", id.Sub)
	}
	digestHex := recoveryDigest(rec.ID, rec.TenantID, rec.GranteeSub, rec.Reason)

	if pol.Issuer == config.DefaultIssuer && !s.DevMode {
		// privasys.id: require the operation-bound WebAuthn ceremony.
		amr, _ := id.Claims["amr"].([]any)
		hasWebauthn := false
		for _, m := range amr {
			if m == "webauthn" {
				hasWebauthn = true
			}
		}
		if !hasWebauthn {
			return "", "", errors.New("privasys.id approvals require the WebAuthn ceremony (amr=webauthn)")
		}
		vaultOp, _ := id.Claims["vault_op"].(string)
		nonce, _ := id.Claims["nonce"].(string)
		expf, _ := id.Claims["exp"].(float64)
		if vaultOp == "" || nonce == "" || expf == 0 {
			return "", "", errors.New("approval token is missing the operation binding")
		}
		if want := s.ceremonyBinding(rec.ID, digestHex, nonce, int64(expf)); vaultOp != want {
			return "", "", errors.New("approval is bound to a different operation")
		}
		// The binding is single-use: one ceremony, one approval.
		return id.Sub, "op:" + vaultOp, nil
	}

	// External issuer: freshness + single-use stand in for the binding.
	if iatf, ok := id.Claims["iat"].(float64); ok {
		if age := time.Since(time.Unix(int64(iatf), 0)); age > 5*time.Minute || age < -time.Minute {
			return "", "", fmt.Errorf("approval token too old (iat %s ago); mint a fresh one", age.Round(time.Second))
		}
	}
	if j, _ := id.Claims["jti"].(string); j != "" {
		return id.Sub, "jti:" + pol.Issuer + ":" + j, nil
	}
	sum := sha256.Sum256([]byte(token))
	return id.Sub, "tok:" + hex.EncodeToString(sum[:]), nil
}

// requestRecovery files a pending recovery. The requester must be
// permitted by the policy; requesting never counts toward the quorum.
func (s *Server) requestRecovery(ctx context.Context, p *Principal, tenantID, reason, granteeSub string, ttlSeconds int64) (*store.Recovery, int, error) {
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.Mode != config.ModeEscrowed || cfg.Recovery == nil {
		return nil, http.StatusBadRequest, errors.New("recovery is available only on an escrowed instance")
	}
	if !p.IsUser() || p.Via != viaBearer {
		return nil, http.StatusForbidden, errors.New("recovery requests need a full bearer identity")
	}
	if !cfg.Recovery.RequesterAllowed(p.Sub, p.ID.Roles) {
		return nil, http.StatusForbidden, errors.New("subject is not permitted to request recovery")
	}
	if reason == "" || granteeSub == "" {
		return nil, http.StatusBadRequest, errors.New("reason and grantee_sub are required")
	}
	if ttlSeconds <= 0 {
		ttlSeconds = 24 * 3600
	}
	if ttlSeconds > 7*24*3600 {
		return nil, http.StatusBadRequest, errors.New("ttl_seconds exceeds the 7-day maximum")
	}
	if _, err := s.Store.GetTenant(ctx, tenantID); err != nil {
		return nil, storeErrorStatus(err), err
	}
	if wrap, err := s.Store.TenantEscrowWrap(ctx, tenantID); err != nil || wrap == "" {
		return nil, http.StatusConflict, errors.New("tenant has no escrow wrap; nothing to recover")
	}
	nb := make([]byte, 16)
	if _, err := rand.Read(nb); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	rec := &store.Recovery{
		TenantID:    tenantID,
		Reason:      reason,
		GranteeSub:  granteeSub,
		TTLSeconds:  ttlSeconds,
		Nonce:       base64.RawURLEncoding.EncodeToString(nb),
		RequestedBy: p.Sub,
		ExpiresAt:   store.Now().Add(recoveryRequestWindow),
	}
	if err := s.Store.CreateRecovery(ctx, rec); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	_ = s.Store.AppendAudit(ctx, tenantID, "recovery_requested", p.Sub,
		fmt.Sprintf("recovery %s requested: grantee %s, reason: %s", rec.ID, granteeSub, reason))
	return rec, http.StatusCreated, nil
}

// approveRecovery records one approval and executes the recovery when
// the quorum is reached. The approval token is the authority — any
// authenticated caller may deliver it.
func (s *Server) approveRecovery(ctx context.Context, p *Principal, tenantID, recoveryID, approvalToken string) (map[string]any, int, error) {
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.Mode != config.ModeEscrowed || cfg.Recovery == nil {
		return nil, http.StatusBadRequest, errors.New("recovery is available only on an escrowed instance")
	}
	if !p.IsUser() {
		return nil, http.StatusForbidden, errors.New("user principals only")
	}
	rec, err := s.Store.GetRecovery(ctx, tenantID, recoveryID)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	if rec.Status != "pending" {
		return nil, http.StatusConflict, fmt.Errorf("recovery is %s", rec.Status)
	}
	if store.Now().After(rec.ExpiresAt) {
		return nil, http.StatusConflict, errors.New("recovery request has lapsed; file a new one")
	}
	sub, jti, err := s.verifyRecoveryApproval(ctx, cfg.Recovery, rec, approvalToken)
	if err != nil {
		return nil, http.StatusForbidden, err
	}
	if err := s.Store.AddRecoveryApproval(ctx, rec.ID, sub, jti); err != nil {
		if errors.Is(err, store.ErrDuplicateApproval) {
			return nil, http.StatusConflict, errors.New("this approver (or token) has already approved")
		}
		return nil, http.StatusInternalServerError, err
	}
	_ = s.Store.AppendAudit(ctx, tenantID, "recovery_approved", sub,
		fmt.Sprintf("recovery %s approved by %s", rec.ID, sub))

	n, err := s.Store.CountRecoveryApprovals(ctx, rec.ID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	out := map[string]any{"recovery_id": rec.ID, "approvals": n, "quorum": cfg.Recovery.Quorum, "status": "pending"}
	if n < cfg.Recovery.Quorum {
		return out, http.StatusOK, nil
	}
	grantID, err := s.executeRecovery(ctx, rec)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("quorum reached but execution failed: %w", err)
	}
	out["status"] = "executed"
	out["grant_id"] = grantID
	out["grantee_sub"] = rec.GranteeSub
	out["expires_in_seconds"] = rec.TTLSeconds
	return out, http.StatusOK, nil
}

// executeRecovery unwraps the tenant MEK from its escrow wrap under
// MEK_org, seeds the in-memory key cache (so reads work even if the
// tenant's own vault path is gone — the escrow is the DR path) and
// mints the time-bounded tenant-wide read grant. The unwrapped MEK
// never leaves enclave memory.
func (s *Server) executeRecovery(ctx context.Context, rec *store.Recovery) (string, error) {
	wrapB64, err := s.Store.TenantEscrowWrap(ctx, rec.TenantID)
	if err != nil || wrapB64 == "" {
		return "", errors.New("tenant has no escrow wrap")
	}
	wrap, err := base64.RawURLEncoding.DecodeString(wrapB64)
	if err != nil {
		return "", fmt.Errorf("escrow wrap corrupt: %w", err)
	}
	orgMEK, err := s.loadOrgMEK(ctx)
	if err != nil {
		return "", fmt.Errorf("MEK_org unavailable: %w", err)
	}
	escrowKey, err := crypto.DeriveDEK(orgMEK, "escrow/"+rec.TenantID)
	if err != nil {
		return "", err
	}
	tenantMEK, err := crypto.UnwrapKey(escrowKey, wrap)
	if err != nil {
		return "", fmt.Errorf("escrow unwrap: %w", err)
	}
	// Seed the cache under the tenant's key handle so the content path
	// serves reads without the tenant's own vault ref.
	if refJSON, rerr := s.Store.TenantMekRef(ctx, rec.TenantID); rerr == nil && refJSON != "" {
		if ref, perr := vaultmek.ParseRef(refJSON); perr == nil {
			if seeder, ok := s.MEKs.(interface{ Seed(handle string, mek []byte) }); ok {
				seeder.Seed(ref.Handle, tenantMEK)
			}
		}
	}
	exp := store.Now().Add(time.Duration(rec.TTLSeconds) * time.Second)
	g := &grants.Grant{
		TenantID:  rec.TenantID,
		NodeID:    "", // tenant-wide
		Subject:   grants.SubjectUser + rec.GranteeSub,
		Scope:     []grants.Scope{grants.ScopeRead},
		CreatedBy: "recovery:" + rec.ID,
		ExpiresAt: &exp,
		Meta:      rec.Reason,
	}
	if err := s.Grants.Create(ctx, g); err != nil {
		return "", err
	}
	if err := s.Store.MarkRecoveryExecuted(ctx, rec.TenantID, rec.ID, g.ID); err != nil {
		// Lost the execute race: revoke the freshly minted duplicate grant.
		_ = s.Grants.Revoke(ctx, rec.TenantID, g.ID)
		return "", errors.New("recovery already executed")
	}
	approvers, _ := s.Store.ListRecoveryApprovers(ctx, rec.ID)
	_ = s.Store.AppendAudit(ctx, rec.TenantID, "recovery_executed", strings.Join(approvers, ","),
		fmt.Sprintf("recovery %s executed: %s granted read for %ds (grant %s); reason: %s",
			rec.ID, rec.GranteeSub, rec.TTLSeconds, g.ID, rec.Reason))
	return g.ID, nil
}

// recoveryStatus reports a recovery's progress plus what an approver
// needs to run the privasys.id ceremony (handle + digest).
func (s *Server) recoveryStatus(ctx context.Context, p *Principal, tenantID, recoveryID string) (map[string]any, int, error) {
	if !p.IsUser() {
		return nil, http.StatusForbidden, errors.New("user principals only")
	}
	rec, err := s.Store.GetRecovery(ctx, tenantID, recoveryID)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	n, _ := s.Store.CountRecoveryApprovals(ctx, rec.ID)
	approvers, _ := s.Store.ListRecoveryApprovers(ctx, rec.ID)
	quorum := 0
	if cfg := s.CurrentConfig(); cfg != nil && cfg.Recovery != nil {
		quorum = cfg.Recovery.Quorum
	}
	return map[string]any{
		"recovery_id":     rec.ID,
		"tenant_id":       rec.TenantID,
		"status":          rec.Status,
		"reason":          rec.Reason,
		"grantee_sub":     rec.GranteeSub,
		"ttl_seconds":     rec.TTLSeconds,
		"requested_by":    rec.RequestedBy,
		"approvals":       n,
		"approvers":       approvers,
		"quorum":          quorum,
		"grant_id":        rec.GrantID,
		"expires_at":      rec.ExpiresAt,
		"ceremony_handle": s.ceremonyHandle(rec.ID),
		"digest_hex":      recoveryDigest(rec.ID, rec.TenantID, rec.GranteeSub, rec.Reason),
	}, http.StatusOK, nil
}

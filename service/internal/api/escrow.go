package api

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// context is used by the method signatures below.
var _ = context.Background

// loadOrgMEK reconstructs MEK_org (the escrowed instance's BYOK master
// key) in-enclave from the configured vault reference. MEK_org is a
// RawShare; the attested build holds ExportKey and reconstructs it, and
// the vault releases the shares only to the promoted measurement.
func (s *Server) loadOrgMEK(ctx context.Context) ([]byte, error) {
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.Mode != config.ModeEscrowed || cfg.OrgMEKRef == "" {
		return nil, errors.New("not an escrowed instance")
	}
	if s.MEKs == nil {
		return nil, errors.New("no vault client to load MEK_org")
	}
	ref, err := vaultmek.ParseRef(cfg.OrgMEKRef)
	if err != nil {
		return nil, err
	}
	return s.MEKs.Load(ctx, ref)
}

// escrowWrapTenant escrow-wraps a tenant's MEK under MEK_org and stores
// the wrap, recording an audit event disclosed to the tenant. The wrap
// is AEAD under a key derived from MEK_org (never MEK_org directly), so
// a compromise of the wrap alone reveals nothing without MEK_org, which
// is released only to the promoted build.
func (s *Server) escrowWrapTenant(ctx context.Context, tenantID string, tenantMEK []byte, actor string) error {
	orgMEK, err := s.loadOrgMEK(ctx)
	if err != nil {
		return err
	}
	escrowKey, err := crypto.DeriveDEK(orgMEK, "escrow/"+tenantID)
	if err != nil {
		return err
	}
	wrap, err := crypto.WrapKey(escrowKey, tenantMEK)
	if err != nil {
		return err
	}
	if err := s.Store.SetTenantEscrowWrap(ctx, tenantID, base64.RawURLEncoding.EncodeToString(wrap)); err != nil {
		return err
	}
	// Disclosed to the tenant: their key is escrow-recoverable under the
	// instance's attested recovery policy.
	_ = s.Store.AppendAudit(ctx, tenantID, "escrow_wrapped", actor,
		"tenant MEK escrow-wrapped under MEK_org (recoverable via the instance recovery policy)")
	return nil
}

// handleRecoverTenant files an escrowed-mode recovery request (the
// enforcement gate lives in recovery.go: policy-checked requester,
// k-of-n approver quorum, hybrid approval verification, MEK_org unwrap
// and a time-bounded tenant-wide read grant, all audited + disclosed).
func (s *Server) handleRecoverTenant(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		Reason     string `json:"reason"`
		GranteeSub string `json:"grantee_sub"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	rec, status, err := s.requestRecovery(r.Context(), p, r.PathValue("tenantID"), req.Reason, req.GranteeSub, req.TTLSeconds)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, status, map[string]any{
		"recovery_id":     rec.ID,
		"status":          rec.Status,
		"ceremony_handle": s.ceremonyHandle(rec.ID),
		"digest_hex":      recoveryDigest(rec.ID, rec.TenantID, rec.GranteeSub, rec.Reason),
		"expires_at":      rec.ExpiresAt,
	})
}

// handleApproveRecovery records one approval (the approval token is the
// authority) and executes at quorum.
func (s *Server) handleApproveRecovery(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		ApprovalToken string `json:"approval_token"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	out, status, err := s.approveRecovery(r.Context(), p, r.PathValue("tenantID"), r.PathValue("recoveryID"), req.ApprovalToken)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, status, out)
}

// handleRecoveryStatus reports a recovery's progress.
func (s *Server) handleRecoveryStatus(w http.ResponseWriter, r *http.Request, p *Principal) {
	out, status, err := s.recoveryStatus(r.Context(), p, r.PathValue("tenantID"), r.PathValue("recoveryID"))
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, status, out)
}

// handleAudit returns the tenant's append-only security audit (escrow,
// recovery). Disclosure: a tenant reads its own audit so recovery of
// its data is never silent.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.Store.ListAudit(r.Context(), tenantID, since, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{
			"seq": a.Seq, "event": a.Event, "actor": a.Actor,
			"detail": a.Detail, "at": a.At,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"audit": out})
}

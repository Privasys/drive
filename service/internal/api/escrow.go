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

// handleRecoverTenant is the escrowed-mode recovery action. The
// non-sensitive scaffold (escrowed config, escrow-wrap at provision,
// disclosure audit) is in place; the enforcement gate — the k-of-n
// approver-quorum verification, WebAuthn step-up, MEK_org unwrap, and
// the time-bounded read grant — is built deliberately as a paired,
// reviewed step, so this returns 501 until then.
func (s *Server) handleRecoverTenant(w http.ResponseWriter, r *http.Request, p *Principal) {
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.Mode != config.ModeEscrowed {
		httpError(w, http.StatusBadRequest, errors.New("recovery is available only on an escrowed instance"))
		return
	}
	writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error": "the recover_tenant enforcement gate (approver quorum + step-up + unwrap + grant) is not yet enabled",
		"code":  "recovery_gate_pending",
	})
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

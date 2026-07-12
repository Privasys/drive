package api

import (
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/manifest"
)

type purgeTenantRequest struct {
	TenantID string `json:"tenant_id"`
	Reason   string `json:"reason"`
}

// toolPurgeTenant permanently removes a tenant: sealed chunks (best
// effort), then the index rows (nodes, members, grants and link requests
// cascade). It exists for tenants that became unreachable — typically an
// identity rotation on a sovereign instance, where by design nobody can
// unlock the data any more — and for offboarding. It is a role:config
// tool: the enclave-os manager enforces the instance operator (app
// owner/admin) on every reachable path, mirroring /configure. The purge
// is recorded in the append-only audit log, which survives the tenant.
func (s *Server) toolPurgeTenant(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.configureAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	var req purgeTenantRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.TenantID == "" || req.Reason == "" {
		httpError(w, http.StatusBadRequest, errors.New("tenant_id and reason are required"))
		return
	}
	if _, err := s.Store.GetTenant(r.Context(), req.TenantID); err != nil {
		writeStoreError(w, err)
		return
	}

	// Best-effort chunk cleanup. The tenant MEK may itself be gone (an
	// expired vault token on a rotated identity cannot be re-armed), in
	// which case the DEK is underivable and the sealed chunks are
	// deleted only from the index; they are unreadable either way.
	files, err := s.Store.ListTenantFiles(r.Context(), req.TenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	chunksDeleted := 0
	if mek, merr := s.tenantMEK(r.Context(), req.TenantID); merr == nil {
		if dek, derr := crypto.DeriveDEK(mek, req.TenantID); derr == nil {
			if bk, berr := s.backendFor(r.Context(), req.TenantID); berr == nil {
				for _, n := range files {
					if n.WrappedCEK != nil {
						if manifest.Delete(r.Context(), bk, dek, req.TenantID, n.ID, n.WrappedCEK) == nil {
							chunksDeleted++
						}
					}
				}
			}
		}
	}

	// Audit before the delete so the trail always exists; audit rows are
	// append-only and keyed by tenant id, not FK-bound.
	_ = s.Store.AppendAudit(r.Context(), req.TenantID, "tenant_purged", p.Sub, req.Reason)

	if err := s.Store.DeleteTenant(r.Context(), req.TenantID); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "purged",
		"tenant_id":      req.TenantID,
		"files":          len(files),
		"chunks_deleted": chunksDeleted,
	})
}

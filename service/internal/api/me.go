package api

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/Privasys/drive/service/internal/store"
)

// personalMu serialises personal-tenant creation so a burst of first
// requests from a fresh login cannot mint duplicates (single-writer
// service; a DB-level uniqueness constraint can replace this if the
// service ever scales out).
var personalMu sync.Mutex

type meTenantJSON struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// handleMe returns the caller's identity and tenant memberships. This
// is the wallet's first call after login.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("user principals only"))
		return
	}
	tms, err := s.Store.TenantsOf(r.Context(), p.Sub)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]meTenantJSON, 0, len(tms))
	for _, tm := range tms {
		out = append(out, meTenantJSON{
			ID: tm.Tenant.ID, Kind: string(tm.Tenant.Kind),
			Name: tm.Tenant.Name, Role: string(tm.Role),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub": p.Sub, "email": p.ID.Email, "tenants": out,
	})
}

// ensurePersonalTenant gets or creates the caller's personal
// (User-kind) tenant. Idempotent. Shared by the REST handler and the
// my_drive manifest tool.
func (s *Server) ensurePersonalTenant(ctx context.Context, p *Principal) (t *store.Tenant, created bool, status int, err error) {
	if !p.IsUser() {
		return nil, false, http.StatusForbidden, errors.New("user principals only")
	}
	personalMu.Lock()
	defer personalMu.Unlock()

	if t, err := s.Store.PersonalTenantOf(ctx, p.Sub); err == nil {
		return t, false, http.StatusOK, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, http.StatusInternalServerError, err
	}
	name := p.ID.Email
	if name == "" {
		name = p.Sub
	}
	t = &store.Tenant{Kind: store.TenantUser, Name: name}
	if err := s.Store.CreateTenant(ctx, t, p.Sub); err != nil {
		return nil, false, http.StatusInternalServerError, err
	}
	return t, true, http.StatusCreated, nil
}

// handleEnsurePersonalTenant gets or creates the caller's personal
// (User-kind) tenant. Idempotent: the first call after login creates
// it (201), every later call returns the same tenant (200).
func (s *Server) handleEnsurePersonalTenant(w http.ResponseWriter, r *http.Request, p *Principal) {
	t, _, status, err := s.ensurePersonalTenant(r.Context(), p)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, status, t)
}

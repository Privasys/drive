package api

import (
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/store"
)

// Member management for enterprise tenants (workspaces). Members are
// identified by their Privasys ID sub — the platform holds no names or
// email addresses; display resolution is a wallet/Contacts concern.

type memberView struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
}

// handleListMembers returns a tenant's members. Any member may look.
func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	ms, err := s.Store.ListMembers(r.Context(), tenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out := make([]memberView, 0, len(ms))
	for _, m := range ms {
		out = append(out, memberView{Sub: m.UserSub, Role: string(m.Role)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": out})
}

type setMemberRoleRequest struct {
	Role string `json:"role"`
}

// handleSetMemberRole changes an existing member's role (admin+). The
// last owner can never be demoted.
func (s *Server) handleSetMemberRole(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	sub := r.PathValue("sub")
	if !p.IsUser() || !s.canAdmin(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req setMemberRoleRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	cur, err := s.Store.MemberRoleOf(r.Context(), tenantID, sub)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cur == store.RoleOwner && store.MemberRole(req.Role) != store.RoleOwner {
		owners, cerr := s.Store.CountOwners(r.Context(), tenantID)
		if cerr != nil {
			httpError(w, http.StatusInternalServerError, cerr)
			return
		}
		if owners <= 1 {
			httpError(w, http.StatusConflict, errors.New("a workspace needs at least one owner"))
			return
		}
	}
	if err := s.Store.AddMember(r.Context(), &store.Member{
		TenantID: tenantID, UserSub: sub, Role: store.MemberRole(req.Role),
	}); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRemoveMember drops a member (admin+, or a member removing
// themselves — leaving the workspace). The last owner cannot leave.
func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	sub := r.PathValue("sub")
	self := p.IsUser() && p.Sub == sub
	if !p.IsUser() || (!self && !s.canAdmin(r.Context(), tenantID, p.Sub)) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	cur, err := s.Store.MemberRoleOf(r.Context(), tenantID, sub)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if cur == store.RoleOwner {
		owners, cerr := s.Store.CountOwners(r.Context(), tenantID)
		if cerr != nil {
			httpError(w, http.StatusInternalServerError, cerr)
			return
		}
		if owners <= 1 {
			httpError(w, http.StatusConflict, errors.New("a workspace needs at least one owner"))
			return
		}
	}
	if err := s.Store.RemoveMember(r.Context(), tenantID, sub); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

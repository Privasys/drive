package api

import (
	"errors"
	"net/http"
)

type moveNodeRequest struct {
	ParentID string `json:"parent_id"` // "" moves to the tenant root
}

// handleMoveNode reparents a file or folder. Write permission on the
// tenant is required; the store rejects cycles and name collisions.
func (s *Server) handleMoveNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req moveNodeRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.ParentID == nodeID {
		httpError(w, http.StatusBadRequest, errors.New("cannot move a node into itself"))
		return
	}
	if err := s.Store.MoveNode(r.Context(), tenantID, nodeID, req.ParentID, p.Sub); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

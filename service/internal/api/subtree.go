package api

// What a node holds beneath it, so a caller can say what deleting it will
// take with it before starting. The front asks for this to label the
// delete ("Deleting Reports, 240 files"): the wait is a round trip per
// file, so the count is the honest predictor of it.

import (
	"errors"
	"net/http"
)

func (s *Server) handleSubtreeStats(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !s.allowNodeRead(r.Context(), p, tenantID, nodeID) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	// GetNode first, so a missing node answers 404 rather than an
	// all-zero count that reads as "an empty folder".
	if _, err := s.Store.GetNode(r.Context(), tenantID, nodeID); err != nil {
		writeStoreError(w, err)
		return
	}
	stats, err := s.Store.SubtreeStats(r.Context(), tenantID, nodeID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

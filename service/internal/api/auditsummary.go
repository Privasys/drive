package api

import (
	"net/http"
	"time"
)

// auditSummaryEvents are the operator actions whose use the summary reports.
var auditSummaryEvents = []string{"tenant_purged", "subjects_rekeyed"}

// handleAuditSummary is the instance operator's read-only look at the
// operator actions recorded in the append-only audit log, across tenants:
// counts, the first characters of each affected tenant id, the number of
// distinct actors (never who), and how far back the log reaches. The volume
// drain is not audited, so it does not appear here.
func (s *Server) handleAuditSummary(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.operatorAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	rows, actors, oldest, err := s.Store.AuditSummary(r.Context(), auditSummaryEvents)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	counts := map[string]int{}
	for _, e := range rows {
		counts[e.Event]++
	}
	var since any
	if !oldest.IsZero() {
		since = oldest.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"counts": counts, "events": rows, "distinct_actors": actors,
		"log_reaches_back_to": since,
	})
}

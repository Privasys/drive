package api

import (
	"errors"
	"net/http"
)

// Operator tools for moving Drive to its own per-app subjects (role:config,
// like purge_tenant: the enclave-os manager enforces the instance operator).
//
// The order: list_subjects; ask the IdP for Drive's subject of each
// (POST /admin/subjects/for with Drive's client id); rekey_subjects with that
// mapping; then switch Drive's client to its own subjects at the IdP. Until
// the switch, sign-ins still carry the account id, so do the two together.

type rekeyRequest struct {
	Mapping map[string]string `json:"mapping"`
	Reason  string            `json:"reason"`
}

func (s *Server) toolListSubjects(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.configureAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	subs, err := s.Store.ListSubjects(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subjects": subs, "count": len(subs)})
}

func (s *Server) toolRekeySubjects(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.configureAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	var req rekeyRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Mapping) == 0 || req.Reason == "" {
		httpError(w, http.StatusBadRequest, errors.New("mapping and reason are required"))
		return
	}
	counts, err := s.Store.RekeySubjects(r.Context(), req.Mapping)
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}
	// The instance's recovery policy names people too.
	if cfg := s.CurrentConfig(); cfg != nil && cfg.Recovery != nil {
		next := *cfg
		rec := *cfg.Recovery
		rec.Approvers = remapSubjects(rec.Approvers, req.Mapping)
		rec.Requesters = remapSubjects(rec.Requesters, req.Mapping)
		next.Recovery = &rec
		if err := s.SetConfig(&next); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	_ = s.Store.AppendAudit(r.Context(), "", "subjects_rekeyed", p.Sub, req.Reason)
	writeJSON(w, http.StatusOK, map[string]any{"status": "rekeyed", "identifiers": len(req.Mapping), "rows": counts})
}

// remapSubjects rewrites the identifiers in subs that the mapping renames.
func remapSubjects(subs []string, mapping map[string]string) []string {
	if len(subs) == 0 {
		return subs
	}
	out := make([]string, len(subs))
	for i, sub := range subs {
		if nu, ok := mapping[sub]; ok {
			out[i] = nu
		} else {
			out[i] = sub
		}
	}
	return out
}

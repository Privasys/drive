package api

import (
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/config"
)

// handleHealth is process liveness: 200 whenever the service is up. The
// manager's container health check probes this, so it must not signal
// configuration state (that is what /readiness is for).
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleReadiness is the manifest's readiness_path: 503 until the
// instance is configured, 200 after.
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if s.CurrentConfig() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "awaiting_config"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

// appStatusDoc is the tolerant status document the platform reconciler
// parses from status_path (state/activity/message/progress).
type appStatusDoc struct {
	State    string `json:"state"`
	Activity string `json:"activity,omitempty"`
	Message  string `json:"message,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Version  string `json:"version,omitempty"`
}

func (s *Server) statusDoc() appStatusDoc {
	doc := appStatusDoc{Version: s.Version}
	if cfg := s.CurrentConfig(); cfg != nil {
		doc.State = "ready"
		doc.Activity = "serving"
		doc.Mode = string(cfg.Mode)
		doc.Message = "Drive is configured (" + string(cfg.Mode) + " mode) and serving."
	} else {
		doc.State = "awaiting_config"
		doc.Activity = "awaiting configuration"
		doc.Message = "Waiting for the owner to set the operating mode via the configure tool."
	}
	return doc
}

// handleStatus is the manifest's status_path (unauthenticated GET — it
// exposes no tenant data, only readiness).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.statusDoc())
}

// handleStatusTool is the role:status manifest tool (authenticated POST).
func (s *Server) handleStatusTool(w http.ResponseWriter, r *http.Request, _ *Principal) {
	writeJSON(w, http.StatusOK, s.statusDoc())
}

type configureRequest struct {
	Mode              config.Mode `json:"mode"`
	QuotaDefaultBytes int64       `json:"quota_default_bytes"`
}

// handleConfigure is the role:config manifest tool. The enclave-os
// manager enforces the configure-authz standard (owner/admin role) on
// every externally reachable path, including direct RA-TLS; the app
// must not re-check the role because proxied configure calls do not
// carry the user's bearer verbatim.
func (s *Server) handleConfigure(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.configureAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	var req configureRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	cfg := &config.Config{Mode: req.Mode, QuotaDefaultBytes: req.QuotaDefaultBytes}
	if err := cfg.Validate(); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// The mode is immutable once set: it is the attested promise the
	// instance made to its tenants (sovereign = no operator unlock path,
	// ever). Defaults may change; the mode may not.
	if cur := s.CurrentConfig(); cur != nil && cur.Mode != cfg.Mode {
		httpError(w, http.StatusConflict, errors.New("operating mode is immutable once set (current: "+string(cur.Mode)+")"))
		return
	}
	if err := s.SetConfig(cfg); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "configured", "mode": cfg.Mode})
}

// configureAllowed requires an authenticated user principal (app grants
// can never configure). The owner/admin role itself is enforced by the
// enclave-os runtime in front of the app; the residual localhost
// surface inside the TD is a fleet-level concern, not per-app.
func (s *Server) configureAllowed(p *Principal) error {
	if !p.IsUser() {
		return errors.New("app grants cannot configure the instance")
	}
	// Sealed-transport identity carries no roles, so it can never be an
	// owner/admin — reject it here as belt-and-braces (the enclave-os
	// runtime already withholds X-Privasys-Sub from configure).
	if p.Via == viaSealed {
		return errors.New("sealed-transport sessions cannot configure the instance")
	}
	return nil
}

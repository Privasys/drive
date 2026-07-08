package api

import (
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/config"
)

// handleHealth is the manifest's readiness_path: 503 until the instance
// is configured, 200 after. (Process liveness is GET /v1/healthz.)
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.CurrentConfig() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "awaiting_config"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
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
// manager enforces the configure-authz standard upstream on every
// configure call; this in-app check is defence in depth for the direct
// RA-TLS path.
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

// configureAllowed implements the configure-authz standard: the caller's
// platform bearer must carry the per-app owner or admin role
// (privasys-platform:app:<app-id-hex>:owner|admin). App-grant principals
// can never configure. DevMode (dev verifier, no platform roles) skips
// the role check.
func (s *Server) configureAllowed(p *Principal) error {
	if !p.IsUser() {
		return errors.New("app grants cannot configure the instance")
	}
	if s.DevMode {
		return nil
	}
	hexID := s.Platform.AppIDHex()
	if hexID == "" {
		// Fail closed: without the platform app identity we cannot name
		// the owner role, so nobody configures.
		return errors.New("configure requires the platform app identity (PRIVASYS_APP_ID)")
	}
	if p.ID.HasRole("privasys-platform:app:"+hexID+":owner") ||
		p.ID.HasRole("privasys-platform:app:"+hexID+":admin") {
		return nil
	}
	return errors.New("caller lacks the app owner/admin role")
}

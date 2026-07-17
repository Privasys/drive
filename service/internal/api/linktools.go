package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

// Share-link manifest tools: the same link lifecycle the web UI drives
// over REST, exposed as tools so wallets and agents can share, request
// and decide without a browser (plan §6's share_link_create). Each tool
// decodes its addressed form, then delegates to the REST handler with
// the path values injected — one implementation, two surfaces.

func delegateWithBody(w http.ResponseWriter, r *http.Request, p *Principal,
	pathValues map[string]string, body any,
	h func(http.ResponseWriter, *http.Request, *Principal)) {
	raw, err := json.Marshal(body)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.Body = io.NopCloser(bytes.NewReader(raw))
	r2.ContentLength = int64(len(raw))
	for k, v := range pathValues {
		r2.SetPathValue(k, v)
	}
	h(w, r2, p)
}

// toolShareLinkCreate mints a share link on a node (owner/admin).
func (s *Server) toolShareLinkCreate(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		NodeID   string `json:"node_id"`
		createLinkRequest
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p,
		map[string]string{"tenantID": req.TenantID, "nodeID": req.NodeID},
		req.createLinkRequest, s.handleCreateLink)
}

// toolRedeemLink redeems a link for the caller: open links grant
// immediately; restricted links file an access request carrying the
// presented attributes (which notify the sharer's wallet and are never
// persisted here).
func (s *Server) toolRedeemLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		LinkID string `json:"link_id"`
		redeemLinkRequest
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p,
		map[string]string{"linkID": req.LinkID},
		req.redeemLinkRequest, s.handleRedeemLink)
}

// toolDecideLinkRequest approves or denies a pending access request
// (owner/admin); the requester's wallet is notified of the outcome.
func (s *Server) toolDecideLinkRequest(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID  string `json:"tenant_id"`
		RequestID string `json:"request_id"`
		Decision  string `json:"decision"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p,
		map[string]string{"tenantID": req.TenantID, "reqID": req.RequestID, "decision": req.Decision},
		struct{}{}, s.handleDecideLinkRequest)
}

// toolListLinkRequests lists a tenant's access requests (owner/admin).
func (s *Server) toolListLinkRequests(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Status   string `json:"status"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	if req.Status != "" {
		q := r2.URL.Query()
		q.Set("status", req.Status)
		r2.URL.RawQuery = q.Encode()
	}
	s.handleListLinkRequests(w, r2, p)
}

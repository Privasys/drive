package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Share links let an owner hand out access to a node without knowing who
// the recipient is (Privasys holds no names or email addresses). A link
// carries a random secret in its URL fragment; the service stores only
// the secret's hash. Two modes:
//
//   - open        the recipient authenticates (wallet, or passkey once the
//                 sealed transport supports it) and redeems the link, which
//                 mints them a per-recipient read grant.
//   - restricted  redeeming files an access request carrying the attributes
//                 the recipient presented; the owner approves each one (or,
//                 later, a saved wallet contact auto-matches). Only on
//                 approval is a grant minted.
//
// The link itself is a `link`-subject grant whose Meta holds this JSON.
// Because decryption happens inside the enclave from the tenant MEK, a
// redeemed link needs nothing more than an ordinary subject grant for the
// existing download path to serve the file.

type linkMeta struct {
	SecretHash string `json:"secret_hash"` // hex(SHA-256(secret bytes)), constant-time verified
	// Secret keeps the raw-url-b64 fragment secret so the OWNER can re-copy
	// the full link later ("Active links"). The index already lives in
	// plaintext inside the enclave on the sealed volume, so this adds no
	// exposure beyond what node names have; it is only ever returned on the
	// owner-gated list endpoint. Absent on links minted before it existed.
	Secret string   `json:"secret,omitempty"`
	Mode   string   `json:"mode"`            // open | restricted
	Attrs  []string `json:"attrs,omitempty"` // restricted: required attributes
	Label  string   `json:"label,omitempty"` // owner's note
}

const (
	linkModeOpen       = "open"
	linkModeRestricted = "restricted"
)

// --- Owner: create / list -------------------------------------------------

type createLinkRequest struct {
	Mode               string   `json:"mode"`                // open | restricted
	Scope              []string `json:"scope"`               // default ["read"]
	RequiredAttributes []string `json:"required_attributes"` // restricted
	ExpiresUnix        int64    `json:"expires_unix,omitempty"`
	Label              string   `json:"label,omitempty"`
}

type createLinkResponse struct {
	ID                 string   `json:"id"`
	Secret             string   `json:"secret"` // returned exactly once
	Mode               string   `json:"mode"`
	Scope              []string `json:"scope"`
	NodeID             string   `json:"node_id"`
	RequiredAttributes []string `json:"required_attributes,omitempty"`
	ExpiresAt          *string  `json:"expires_at,omitempty"`
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if _, err := s.Store.GetNode(r.Context(), tenantID, nodeID); err != nil {
		writeStoreError(w, err)
		return
	}
	var req createLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = linkModeOpen
	}
	if mode != linkModeOpen && mode != linkModeRestricted {
		httpError(w, http.StatusBadRequest, errors.New("mode must be open or restricted"))
		return
	}
	scope := normaliseLinkScope(req.Scope)
	if mode == linkModeRestricted && len(req.RequiredAttributes) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("restricted links need at least one required attribute"))
		return
	}

	secretBytes, err := crypto.RandomKey()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	sum := sha256.Sum256(secretBytes)
	meta := linkMeta{SecretHash: hex.EncodeToString(sum[:]), Secret: secret, Mode: mode, Label: req.Label}
	if mode == linkModeRestricted {
		meta.Attrs = req.RequiredAttributes
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}

	g := &grants.Grant{
		TenantID:  tenantID,
		NodeID:    nodeID,
		Subject:   grants.SubjectLink,
		Scope:     scope,
		CreatedBy: p.Sub,
		Meta:      string(metaJSON),
	}
	var expIso *string
	if req.ExpiresUnix > 0 {
		t := time.Unix(req.ExpiresUnix, 0).UTC()
		g.ExpiresAt = &t
		iso := t.Format(time.RFC3339)
		expIso = &iso
	}
	if err := s.Grants.Create(r.Context(), g); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, createLinkResponse{
		ID:                 g.ID,
		Secret:             secret,
		Mode:               mode,
		Scope:              scopeStrings(scope),
		NodeID:             nodeID,
		RequiredAttributes: meta.Attrs,
		ExpiresAt:          expIso,
	})
}

type linkView struct {
	ID                 string   `json:"id"`
	Mode               string   `json:"mode"`
	Scope              []string `json:"scope"`
	Label              string   `json:"label,omitempty"`
	RequiredAttributes []string `json:"required_attributes,omitempty"`
	CreatedAt          string   `json:"created_at"`
	ExpiresAt          *string  `json:"expires_at,omitempty"`
	Revoked            bool     `json:"revoked"`
	// Secret lets the owner re-copy the full link; empty for links minted
	// before secrets were kept. This endpoint is canShare-gated.
	Secret string `json:"secret,omitempty"`
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	gs, err := s.Grants.ListForNode(r.Context(), tenantID, nodeID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]linkView, 0)
	for _, g := range gs {
		if g.Subject != grants.SubjectLink {
			continue
		}
		var meta linkMeta
		_ = json.Unmarshal([]byte(g.Meta), &meta)
		lv := linkView{
			ID: g.ID, Mode: meta.Mode, Scope: scopeStrings(g.Scope),
			Label: meta.Label, RequiredAttributes: meta.Attrs,
			CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339),
			Revoked:   g.RevokedAt != nil,
			Secret:    meta.Secret,
		}
		if g.ExpiresAt != nil {
			iso := g.ExpiresAt.UTC().Format(time.RFC3339)
			lv.ExpiresAt = &iso
		}
		out = append(out, lv)
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// --- Recipient: resolve / redeem -----------------------------------------

type redeemLinkRequest struct {
	Secret     string            `json:"secret"`
	Attributes map[string]string `json:"attributes,omitempty"` // restricted: presented profile
}

// loadLink fetches an active `link` grant and constant-time-verifies the
// presented secret against the stored hash.
func (s *Server) loadLink(ctx context.Context, linkID, secret string) (*grants.Grant, *linkMeta, error) {
	g, err := s.Grants.Get(ctx, linkID)
	if err != nil {
		return nil, nil, err
	}
	if g.Subject != grants.SubjectLink || !g.IsActive(time.Now().UTC()) {
		return nil, nil, store.ErrNotFound
	}
	var meta linkMeta
	if err := json.Unmarshal([]byte(g.Meta), &meta); err != nil {
		return nil, nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil {
		return nil, nil, errLinkSecret
	}
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(meta.SecretHash)) != 1 {
		return nil, nil, errLinkSecret
	}
	return g, &meta, nil
}

var errLinkSecret = errors.New("invalid or expired link")

func (s *Server) handleResolveLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	linkID := r.PathValue("linkID")
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("sign in to open this link"))
		return
	}
	var req redeemLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	g, meta, err := s.loadLink(r.Context(), linkID, req.Secret)
	if err != nil {
		writeLinkError(w, err)
		return
	}
	n, err := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// Whether this caller already has access (previously redeemed).
	granted := false
	if ag, aerr := s.Grants.ActiveForSubjectOnNode(r.Context(), g.TenantID, g.NodeID, p.Sub); aerr == nil && ag != nil {
		granted = true
	}
	// Restricted: surface any pending request state for this caller.
	requestStatus := ""
	if meta.Mode == linkModeRestricted {
		if lr, lerr := s.Store.PendingLinkRequestFor(r.Context(), g.ID, p.Sub); lerr == nil && lr != nil {
			requestStatus = lr.Status
		}
	}
	ownerName := ""
	if t, terr := s.Store.GetTenant(r.Context(), g.TenantID); terr == nil {
		ownerName = t.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"link_id":             g.ID,
		"mode":                meta.Mode,
		"scope":               scopeStrings(g.Scope),
		"required_attributes": meta.Attrs,
		"tenant_id":           g.TenantID,
		"owner_name":          ownerName,
		"already_granted":     granted,
		"request_status":      requestStatus,
		"node": map[string]any{
			"id": n.ID, "name": n.Name, "kind": string(n.Kind), "size_bytes": n.PlainSize,
		},
	})
}

func (s *Server) handleRedeemLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	linkID := r.PathValue("linkID")
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("sign in to open this link"))
		return
	}
	var req redeemLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	g, meta, err := s.loadLink(r.Context(), linkID, req.Secret)
	if err != nil {
		writeLinkError(w, err)
		return
	}
	n, err := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Idempotent: an existing grant means access is already in place.
	if ag, aerr := s.Grants.ActiveForSubjectOnNode(r.Context(), g.TenantID, g.NodeID, p.Sub); aerr == nil && ag != nil {
		writeJSON(w, http.StatusOK, redeemResult("granted", g, n, ""))
		return
	}

	switch meta.Mode {
	case linkModeOpen:
		if _, err := s.mintSubjectGrant(r.Context(), g.TenantID, g.NodeID, p.Sub, g.Scope, g.ID); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, redeemResult("granted", g, n, ""))
	case linkModeRestricted:
		// Every required attribute must be presented, else no request is
		// filed: a half-empty request would push an undecidable card at
		// the owner. The front tells the visitor what is missing.
		var missing []string
		for _, k := range meta.Attrs {
			if strings.TrimSpace(req.Attributes[k]) == "" {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":              "missing required attributes: " + strings.Join(missing, ", "),
				"missing_attributes": missing,
			})
			return
		}
		// PII boundary (§7.6): the presented attributes ride out to the
		// sharer's wallet in the notification and are NOT persisted —
		// the drive keeps only the sub, scope and timestamps.
		lr := &store.LinkRequest{
			TenantID: g.TenantID, LinkID: g.ID, NodeID: g.NodeID,
			RequesterSub: p.Sub,
			Scope:        joinScopeStrings(g.Scope),
		}
		err := s.Store.CreateLinkRequest(r.Context(), lr)
		if errors.Is(err, store.ErrDuplicateApproval) {
			// Already requested; report the current pending state.
			writeJSON(w, http.StatusOK, redeemResult("pending", g, n, ""))
			return
		}
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		s.Notifier().Fire(g.CreatedBy, "share-request", map[string]any{
			"tenant_id":     g.TenantID,
			"request_id":    lr.ID,
			"node_id":       g.NodeID,
			"node_name":     n.Name,
			"requester_sub": p.Sub,
			"attributes":    req.Attributes,
			"scope":         scopeStrings(g.Scope),
		})
		writeJSON(w, http.StatusOK, redeemResult("pending", g, n, lr.ID))
	default:
		httpError(w, http.StatusInternalServerError, errors.New("unknown link mode"))
	}
}

func redeemResult(status string, g *grants.Grant, n *store.Node, requestID string) map[string]any {
	out := map[string]any{
		"status":    status,
		"tenant_id": g.TenantID,
		"node_id":   g.NodeID,
		"name":      n.Name,
		"kind":      string(n.Kind),
	}
	if requestID != "" {
		out["request_id"] = requestID
	}
	return out
}

// --- Owner: restricted-request review ------------------------------------

type linkRequestView struct {
	ID         string            `json:"id"`
	NodeID     string            `json:"node_id"`
	NodeName   string            `json:"node_name"`
	Requester  string            `json:"requester_sub"`
	Attributes map[string]string `json:"attributes"`
	Scope      []string          `json:"scope"`
	Status     string            `json:"status"`
	CreatedAt  string            `json:"created_at"`
}

func (s *Server) handleListLinkRequests(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	status := r.URL.Query().Get("status")
	rs, err := s.Store.ListLinkRequests(r.Context(), tenantID, status)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]linkRequestView, 0, len(rs))
	for _, lr := range rs {
		var attrs map[string]string
		_ = json.Unmarshal([]byte(lr.Attributes), &attrs)
		name := ""
		if n, nerr := s.Store.GetNode(r.Context(), tenantID, lr.NodeID); nerr == nil {
			name = n.Name
		}
		out = append(out, linkRequestView{
			ID: lr.ID, NodeID: lr.NodeID, NodeName: name, Requester: lr.RequesterSub,
			Attributes: attrs, Scope: scopeStrings(splitScopeStrings(lr.Scope)), Status: lr.Status,
			CreatedAt: lr.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *Server) handleDecideLinkRequest(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	reqID := r.PathValue("reqID")
	decision := r.PathValue("decision")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if decision != "approve" && decision != "deny" {
		httpError(w, http.StatusBadRequest, errors.New("decision must be approve or deny"))
		return
	}
	lr, err := s.Store.GetLinkRequest(r.Context(), tenantID, reqID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if lr.Status != "pending" {
		httpError(w, http.StatusConflict, errors.New("request already decided"))
		return
	}
	nodeName := ""
	if n, nerr := s.Store.GetNode(r.Context(), tenantID, lr.NodeID); nerr == nil {
		nodeName = n.Name
	}
	if decision == "deny" {
		if err := s.Store.DecideLinkRequest(r.Context(), tenantID, reqID, "denied", "", p.Sub); err != nil {
			writeStoreError(w, err)
			return
		}
		s.Notifier().Fire(lr.RequesterSub, "share-decision", map[string]any{
			"tenant_id": tenantID, "request_id": reqID,
			"node_id": lr.NodeID, "node_name": nodeName, "status": "denied",
		})
		writeJSON(w, http.StatusOK, map[string]any{"status": "denied"})
		return
	}
	// Approve: mint the recipient's grant, then record the decision.
	g, err := s.mintSubjectGrant(r.Context(), tenantID, lr.NodeID, lr.RequesterSub, splitScopeStrings(lr.Scope), lr.LinkID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.Store.DecideLinkRequest(r.Context(), tenantID, reqID, "approved", g.ID, p.Sub); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Notifier().Fire(lr.RequesterSub, "share-decision", map[string]any{
		"tenant_id": tenantID, "request_id": reqID,
		"node_id": lr.NodeID, "node_name": nodeName, "status": "approved",
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "grant_id": g.ID})
}

// --- helpers --------------------------------------------------------------

// mintSubjectGrant creates a per-recipient read/write grant on a node,
// noting the originating link in Meta for audit.
func (s *Server) mintSubjectGrant(ctx context.Context, tenantID, nodeID, sub string, scope []grants.Scope, linkID string) (*grants.Grant, error) {
	meta, _ := json.Marshal(map[string]string{"via_link": linkID})
	g := &grants.Grant{
		TenantID:  tenantID,
		NodeID:    nodeID,
		Subject:   grants.SubjectUser + sub,
		Scope:     scope,
		CreatedBy: "link:" + linkID,
		Meta:      string(meta),
	}
	if err := s.Grants.Create(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

func normaliseLinkScope(in []string) []grants.Scope {
	want := map[string]bool{}
	for _, s := range in {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	out := []grants.Scope{grants.ScopeRead}
	if want["write"] {
		out = append(out, grants.ScopeWrite)
	}
	return out
}

func scopeStrings(ss []grants.Scope) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, string(s))
	}
	return out
}

func joinScopeStrings(ss []grants.Scope) string {
	return strings.Join(scopeStrings(ss), ",")
}

func splitScopeStrings(s string) []grants.Scope {
	var out []grants.Scope
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, grants.Scope(p))
		}
	}
	if len(out) == 0 {
		out = []grants.Scope{grants.ScopeRead}
	}
	return out
}

func writeLinkError(w http.ResponseWriter, err error) {
	if errors.Is(err, errLinkSecret) || errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, errLinkSecret)
		return
	}
	httpError(w, http.StatusInternalServerError, err)
}

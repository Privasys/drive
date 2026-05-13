// Package api glues the storage primitives behind the Privasys Drive
// REST surface. The handlers are intentionally thin — every operation
// has a matching public function in the underlying packages so the MCP
// surface (next to it) can call them directly without going through HTTP.
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/export"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/store"
)

// Server bundles the handlers + their dependencies.
type Server struct {
	Store     *store.Store
	Backend   objectstore.Backend
	Grants    *grants.Repo
	Verifier  oidc.Verifier
	MEK       []byte // single tenant MEK for `--dev`. Production: fetched per tenant from vault.
}

// Routes returns the HTTP handler with all REST routes mounted under /v1.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.Handle("POST /v1/tenants", s.auth(s.handleCreateTenant))
	mux.Handle("POST /v1/tenants/{tenantID}/members", s.auth(s.handleAddMember))
	mux.Handle("POST /v1/tenants/{tenantID}/folders", s.auth(s.handleCreateFolder))
	mux.Handle("GET /v1/tenants/{tenantID}/folders/{folderID}", s.auth(s.handleListFolder))
	mux.Handle("GET /v1/tenants/{tenantID}/root", s.auth(s.handleListRoot))
	mux.Handle("POST /v1/tenants/{tenantID}/files", s.auth(s.handleUploadFile))
	mux.Handle("GET /v1/tenants/{tenantID}/files/{fileID}", s.auth(s.handleDownloadFile))
	mux.Handle("DELETE /v1/tenants/{tenantID}/nodes/{nodeID}", s.auth(s.handleDeleteNode))

	mux.Handle("POST /v1/tenants/{tenantID}/nodes/{nodeID}/grants", s.auth(s.handleCreateGrant))
	mux.Handle("DELETE /v1/tenants/{tenantID}/grants/{grantID}", s.auth(s.handleRevokeGrant))
	mux.Handle("GET /v1/tenants/{tenantID}/changes", s.auth(s.handleChanges))
	mux.Handle("POST /v1/tenants/{tenantID}/exports", s.auth(s.handleExport))

	return loggingMiddleware(mux)
}

type ctxKey string

const idKey ctxKey = "id"

func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *oidc.Identity)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		id, err := s.Verifier.Verify(r.Context(), strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
			return
		}
		next(w, r, id)
	})
}

// --- handlers ---------------------------------------------------------

type createTenantRequest struct {
	Kind store.TenantKind `json:"kind"`
	Name string           `json:"name"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	var req createTenantRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Kind == "" {
		req.Kind = store.TenantUser
	}
	t := &store.Tenant{Kind: req.Kind, Name: req.Name}
	if err := s.Store.CreateTenant(r.Context(), t); err != nil {
		writeStoreError(w, err)
		return
	}
	if t.Kind == store.TenantEnterprise {
		_ = s.Store.AddMember(r.Context(), &store.Member{TenantID: t.ID, UserSub: id.Sub, Role: store.RoleOwner})
	}
	writeJSON(w, http.StatusCreated, t)
}

type addMemberRequest struct {
	UserSub string           `json:"user_sub"`
	Role    store.MemberRole `json:"role"`
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	var req addMemberRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.canAdmin(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.Store.AddMember(r.Context(), &store.Member{TenantID: tenantID, UserSub: req.UserSub, Role: req.Role}); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createFolderRequest struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	if !s.canWrite(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createFolderRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hmacKey, err := crypto.DeriveNameHMACKey(s.MEK, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n := &store.Node{
		TenantID: tenantID,
		Kind:     store.NodeFolder,
		Name:     req.Name,
		NameHMAC: crypto.NameHMAC(hmacKey, req.Name),
	}
	if req.ParentID != "" {
		n.ParentID.String = req.ParentID
		n.ParentID.Valid = true
	}
	if err := s.Store.CreateNode(r.Context(), n); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, nodeView(n))
}

func (s *Server) handleListRoot(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	if !s.canRead(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	kids, err := s.Store.ListChildren(r.Context(), tenantID, "")
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mapNodes(kids))
}

func (s *Server) handleListFolder(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	folderID := r.PathValue("folderID")
	if !s.canRead(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	kids, err := s.Store.ListChildren(r.Context(), tenantID, folderID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mapNodes(kids))
}

// handleUploadFile expects the file body in the request body. The
// metadata (parent, name, mime) come from query parameters so the body
// stream is exactly the plaintext.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	if !s.canWrite(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	q := r.URL.Query()
	name := q.Get("name")
	parentID := q.Get("parent_id")
	mime := q.Get("mime")
	if name == "" {
		http.Error(w, "name query parameter required", http.StatusBadRequest)
		return
	}
	dek, err := crypto.DeriveDEK(s.MEK, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	hmacKey, err := crypto.DeriveNameHMACKey(s.MEK, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n := &store.Node{
		TenantID: tenantID,
		Kind:     store.NodeFile,
		Name:     name,
		NameHMAC: crypto.NameHMAC(hmacKey, name),
		MimeHint: mime,
	}
	n.ID = store.NewID()
	if parentID != "" {
		n.ParentID.String = parentID
		n.ParentID.Valid = true
	}
	wr, err := manifest.Write(r.Context(), s.Backend, dek, tenantID, n.ID, mime, 0, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	root, err := hex.DecodeString(wr.Manifest.MerkleRoot)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	n.MerkleRoot = root
	n.WrappedCEK = wr.WrappedCEK
	n.ManifestRef = wr.ManifestKey
	n.PlainSize = wr.Manifest.PlainSize
	if err := s.Store.CreateNode(r.Context(), n); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, nodeView(n))
}

func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	fileID := r.PathValue("fileID")
	if !s.canRead(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n, err := s.Store.GetNode(r.Context(), tenantID, fileID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if n.Kind != store.NodeFile {
		http.Error(w, "not a file", http.StatusBadRequest)
		return
	}
	dek, err := crypto.DeriveDEK(s.MEK, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, rc, err := manifest.Read(r.Context(), s.Backend, dek, tenantID, n.ID, n.WrappedCEK)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rc.Close()
	if n.MimeHint != "" {
		w.Header().Set("Content-Type", n.MimeHint)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(n.PlainSize, 10))
	w.Header().Set("X-Drive-Merkle-Root", hex.EncodeToString(n.MerkleRoot))
	if _, err := io.Copy(w, rc); err != nil {
		// Best-effort: response already started.
		return
	}
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !s.canWrite(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	n, err := s.Store.GetNode(r.Context(), tenantID, nodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if n.Kind == store.NodeFile && n.WrappedCEK != nil {
		dek, err := crypto.DeriveDEK(s.MEK, tenantID)
		if err == nil {
			_ = manifest.Delete(r.Context(), s.Backend, dek, tenantID, n.ID, n.WrappedCEK)
		}
	}
	if err := s.Store.DeleteNode(r.Context(), tenantID, nodeID); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createGrantRequest struct {
	Subject       string         `json:"subject"`
	Scope         []grants.Scope `json:"scope"`
	BindingPubkey string         `json:"binding_pubkey,omitempty"`
	ExpiresUnix   int64          `json:"expires_unix,omitempty"`
	Meta          string         `json:"meta,omitempty"`
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !s.canShare(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createGrantRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Subject == "" {
		http.Error(w, "subject required", http.StatusBadRequest)
		return
	}
	g := &grants.Grant{
		TenantID:      tenantID,
		NodeID:        nodeID,
		Subject:       req.Subject,
		Scope:         req.Scope,
		CreatedBy:     id.Sub,
		BindingPubkey: req.BindingPubkey,
		Meta:          req.Meta,
	}
	if req.ExpiresUnix > 0 {
		t := time.Unix(req.ExpiresUnix, 0).UTC()
		g.ExpiresAt = &t
	}
	if err := s.Grants.Create(r.Context(), g); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	grantID := r.PathValue("grantID")
	if !s.canShare(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.Grants.Revoke(r.Context(), tenantID, grantID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	if !s.canRead(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := s.Store.ListChanges(r.Context(), tenantID, since, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

type exportRequest struct {
	Mode export.Mode `json:"mode"`
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, id *oidc.Identity) {
	tenantID := r.PathValue("tenantID")
	if !s.canRead(r.Context(), tenantID, id.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req exportRequest
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Mode == "" {
		req.Mode = export.ModePlaintext
	}
	dek, err := crypto.DeriveDEK(s.MEK, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="drive-export.zip"`)
	if _, err := export.WriteZip(r.Context(), s.Store, s.Backend, dek, tenantID, req.Mode, w); err != nil {
		// Headers already sent — best effort.
		return
	}
}

// --- access control ---------------------------------------------------

func (s *Server) tenantKind(ctx context.Context, tenantID string) store.TenantKind {
	t, err := s.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return ""
	}
	return t.Kind
}

func (s *Server) canRead(ctx context.Context, tenantID, sub string) bool {
	switch s.tenantKind(ctx, tenantID) {
	case store.TenantUser:
		// User tenants have a single owner: the OIDC sub equals the tenant Name in the dev model.
		// In production, owner mapping comes from the IDP. For now, allow.
		return true
	case store.TenantEnterprise:
		_, err := s.Store.MemberRoleOf(ctx, tenantID, sub)
		return err == nil
	}
	return false
}

func (s *Server) canWrite(ctx context.Context, tenantID, sub string) bool {
	switch s.tenantKind(ctx, tenantID) {
	case store.TenantUser:
		return true
	case store.TenantEnterprise:
		r, err := s.Store.MemberRoleOf(ctx, tenantID, sub)
		if err != nil {
			return false
		}
		return r != store.RoleReader
	}
	return false
}

func (s *Server) canShare(ctx context.Context, tenantID, sub string) bool { return s.canWrite(ctx, tenantID, sub) }
func (s *Server) canAdmin(ctx context.Context, tenantID, sub string) bool {
	r, err := s.Store.MemberRoleOf(ctx, tenantID, sub)
	if err != nil {
		// User tenants: implicit admin for any authenticated caller in dev.
		return s.tenantKind(ctx, tenantID) == store.TenantUser
	}
	return r == store.RoleOwner || r == store.RoleAdmin
}

// --- helpers ----------------------------------------------------------

type nodeJSON struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	ParentID    string `json:"parent_id,omitempty"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	MimeHint    string `json:"mime_hint,omitempty"`
	PlainSize   int64  `json:"size_bytes"`
	MerkleRoot  string `json:"merkle_root_hex,omitempty"`
	ManifestRef string `json:"manifest_ref,omitempty"`
}

func nodeView(n *store.Node) nodeJSON {
	v := nodeJSON{
		ID: n.ID, TenantID: n.TenantID, Kind: string(n.Kind),
		Name: n.Name, MimeHint: n.MimeHint, PlainSize: n.PlainSize,
		ManifestRef: n.ManifestRef,
	}
	if n.ParentID.Valid {
		v.ParentID = n.ParentID.String
	}
	if len(n.MerkleRoot) > 0 {
		v.MerkleRoot = hex.EncodeToString(n.MerkleRoot)
	}
	return v
}

func mapNodes(ns []*store.Node) []nodeJSON {
	out := make([]nodeJSON, 0, len(ns))
	for _, n := range ns {
		out = append(out, nodeView(n))
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func readJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, store.ErrConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, store.ErrInvalidInput):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, store.ErrForbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		_ = fmt.Sprintf("%s %s", r.Method, r.URL.Path) // intentional no-op for now
	})
}

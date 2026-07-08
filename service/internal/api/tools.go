package api

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
)

// toolMaxBytes caps JSON-carried file content (both directions). Larger
// files use the streaming REST endpoints.
const toolMaxBytes = 8 << 20

// Tools returns the manifest-tool invocation surface: the plain-JSON
// POST endpoints the privasys.json tools point at. Each is a thin
// wrapper over the same internals as the REST surface, with identical
// auth (OIDC bearer or AppGrant) and access checks.
func (s *Server) Tools() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /tools/list_root", s.auth(s.toolListRoot))
	mux.Handle("POST /tools/list_folder", s.auth(s.toolListFolder))
	mux.Handle("POST /tools/create_folder", s.auth(s.toolCreateFolder))
	mux.Handle("POST /tools/write_file", s.auth(s.toolWriteFile))
	mux.Handle("POST /tools/read_file", s.auth(s.toolReadFile))
	mux.Handle("POST /tools/delete_node", s.auth(s.toolDeleteNode))
	mux.Handle("POST /tools/changes", s.auth(s.toolChanges))
	return mux
}

func (s *Server) toolListRoot(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	kids, status, err := s.listChildren(r.Context(), p, req.TenantID, "")
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": mapNodes(kids)})
}

func (s *Server) toolListFolder(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		FolderID string `json:"folder_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.FolderID == "" {
		httpError(w, http.StatusBadRequest, errors.New("folder_id required"))
		return
	}
	kids, status, err := s.listChildren(r.Context(), p, req.TenantID, req.FolderID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": mapNodes(kids)})
}

func (s *Server) toolCreateFolder(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		ParentID string `json:"parent_id"`
		Name     string `json:"name"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, status, err := s.createFolder(r.Context(), p, req.TenantID, req.ParentID, req.Name)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(n))
}

func (s *Server) toolWriteFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID      string `json:"tenant_id"`
		ParentID      string `json:"parent_id"`
		Name          string `json:"name"`
		Mime          string `json:"mime"`
		ContentBase64 string `json:"content_base64"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	content, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.New("content_base64 is not valid base64"))
		return
	}
	if len(content) > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("content exceeds the 8 MiB tool cap; use the streaming REST upload"))
		return
	}
	n, status, err := s.uploadFile(r.Context(), p, req.TenantID, req.ParentID, req.Name, req.Mime, bytes.NewReader(content))
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(n))
}

func (s *Server) toolReadFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		FileID   string `json:"file_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, rc, status, err := s.openFile(r.Context(), p, req.TenantID, req.FileID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	defer rc.Close()
	if n.PlainSize > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("file exceeds the 8 MiB tool cap; use the streaming REST download"))
		return
	}
	content, err := io.ReadAll(io.LimitReader(rc, toolMaxBytes+1))
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if len(content) > toolMaxBytes {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("file exceeds the 8 MiB tool cap; use the streaming REST download"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node":            nodeView(n),
		"content_base64":  base64.StdEncoding.EncodeToString(content),
		"merkle_root_hex": hex.EncodeToString(n.MerkleRoot),
	})
}

func (s *Server) toolDeleteNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		NodeID   string `json:"node_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if status, err := s.deleteNode(r.Context(), p, req.TenantID, req.NodeID); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": req.NodeID})
}

func (s *Server) toolChanges(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Since    int64  `json:"since"`
		Limit    int    `json:"limit"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	rows, status, err := s.listChanges(r.Context(), p, req.TenantID, req.Since, req.Limit)
	if err != nil {
		httpError(w, status, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		out = append(out, map[string]any{
			"seq": c.Seq, "node_id": c.NodeID, "op": c.Op,
			"actor": c.Actor, "at": c.At,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"changes": out})
}

// legacyToolCatalog keeps the pre-manifest GET /mcp/v1/tools endpoint
// alive, serving the tool list straight from the image's privasys.json
// (single source of truth) instead of a hand-maintained catalog.
func legacyToolCatalog(manifestPath string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp/v1/tools", func(w http.ResponseWriter, r *http.Request) {
		b, err := os.ReadFile(manifestPath)
		if err != nil {
			httpError(w, http.StatusNotFound, errors.New("manifest not available"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	})
	return mux
}

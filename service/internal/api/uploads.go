package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Chunked uploads for large files. The sealed browser transport carries
// one request body per message, so a big file arrives as an upload
// session: create, PUT sequential parts (each one sealed request), then
// finalize, which streams the staged bytes through the exact same
// chunk/seal path as a single-shot upload. Parts stage on the sealed
// /data volume, so plaintext never touches an unsealed disk. Sessions
// are in-memory (a restart aborts them; the client restarts the upload)
// and stale staging files are swept lazily.

const (
	// uploadPartMax caps one part; the client sends ~4 MiB parts.
	uploadPartMax = 16 << 20
	// uploadMaxAge sweeps abandoned sessions and staging files.
	uploadMaxAge = 24 * time.Hour
)

type uploadSession struct {
	ID       string
	TenantID string
	ParentID string
	Name     string
	Mime     string
	Sub      string // creator; parts and finalize must match
	Declared int64  // declared total size (0 = unknown)
	NoIndex  bool   // explicit exclude-from-index flag
	Next     int    // next expected part index
	Bytes    int64
	Path     string
	Created  time.Time
}

type uploadRegistry struct {
	mu       sync.Mutex
	sessions map[string]*uploadSession
}

func (r *uploadRegistry) init() {
	if r.sessions == nil {
		r.sessions = make(map[string]*uploadSession)
	}
}

func (s *Server) stagingDir() string {
	return filepath.Join(s.StateDir, "uploads")
}

// sweepStaleUploads removes abandoned sessions + staging files. Called
// lazily from create, under the registry lock.
func (s *Server) sweepStaleUploads() {
	cutoff := time.Now().Add(-uploadMaxAge)
	for id, u := range s.uploads.sessions {
		if u.Created.Before(cutoff) {
			_ = os.Remove(u.Path)
			delete(s.uploads.sessions, id)
		}
	}
	entries, err := os.ReadDir(s.stagingDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if info, ierr := e.Info(); ierr == nil && info.ModTime().Before(cutoff) {
			if _, live := s.uploads.sessions[e.Name()]; !live {
				_ = os.Remove(filepath.Join(s.stagingDir(), e.Name()))
			}
		}
	}
}

type createUploadRequest struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
	Mime     string `json:"mime"`
	Size     int64  `json:"size"` // declared plaintext size; 0 = unknown
	Index    *bool  `json:"index,omitempty"` // false excludes from the semantic index
}

func (s *Server) handleCreateUpload(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req createUploadRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if req.Name == "" {
		httpError(w, http.StatusBadRequest, errors.New("name required"))
		return
	}
	if !s.allowNode(r.Context(), p, tenantID, req.ParentID, grants.ScopeWrite) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	// Fast quota check against the declared size; the precise check
	// still happens at finalize inside uploadFile.
	if limit := s.quotaLimit(); limit > 0 {
		used, err := s.Store.TenantUsageBytes(r.Context(), tenantID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		if used >= limit || (req.Size > 0 && used+req.Size > limit) {
			httpError(w, http.StatusRequestEntityTooLarge,
				fmt.Errorf("upload would exceed the tenant storage quota (%d bytes)", limit))
			return
		}
	}
	if err := os.MkdirAll(s.stagingDir(), 0o700); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	u := &uploadSession{
		ID:       store.NewID(),
		TenantID: tenantID,
		ParentID: req.ParentID,
		Name:     req.Name,
		Mime:     req.Mime,
		Sub:      p.Sub,
		Declared: req.Size,
		NoIndex:  req.Index != nil && !*req.Index,
		Created:  time.Now(),
	}
	u.Path = filepath.Join(s.stagingDir(), u.ID)
	if f, err := os.OpenFile(u.Path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	} else {
		f.Close()
	}
	s.uploads.mu.Lock()
	s.uploads.init()
	s.sweepStaleUploads()
	s.uploads.sessions[u.ID] = u
	s.uploads.mu.Unlock()
	writeJSON(w, http.StatusCreated, map[string]any{"id": u.ID})
}

// getUpload fetches + validates a session for the caller.
func (s *Server) getUpload(p *Principal, tenantID, id string) (*uploadSession, error) {
	s.uploads.mu.Lock()
	defer s.uploads.mu.Unlock()
	u := s.uploads.sessions[id]
	if u == nil || u.TenantID != tenantID {
		return nil, store.ErrNotFound
	}
	if u.Sub != p.Sub {
		return nil, store.ErrForbidden
	}
	return u, nil
}

func (s *Server) dropUpload(id string, removeFile bool) {
	s.uploads.mu.Lock()
	u := s.uploads.sessions[id]
	delete(s.uploads.sessions, id)
	s.uploads.mu.Unlock()
	if u != nil && removeFile {
		_ = os.Remove(u.Path)
	}
}

func (s *Server) handleUploadPart(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	uploadID := r.PathValue("uploadID")
	idx, err := strconv.Atoi(r.PathValue("index"))
	if err != nil || idx < 0 {
		httpError(w, http.StatusBadRequest, errors.New("bad part index"))
		return
	}
	u, uerr := s.getUpload(p, tenantID, uploadID)
	if uerr != nil {
		writeStoreError(w, uerr)
		return
	}
	// Parts are strictly sequential: the client uploads one at a time
	// and a retry of the last part is idempotent-safe to reject (the
	// client only retries after a failed response, in which case the
	// append did not commit).
	if idx != u.Next {
		httpError(w, http.StatusConflict,
			fmt.Errorf("expected part %d, got %d", u.Next, idx))
		return
	}
	f, err := os.OpenFile(u.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	nw, err := io.Copy(f, io.LimitReader(r.Body, uploadPartMax+1))
	cerr := f.Close()
	if err != nil || cerr != nil {
		httpError(w, http.StatusInternalServerError, errors.Join(err, cerr))
		return
	}
	if nw > uploadPartMax {
		s.dropUpload(u.ID, true)
		httpError(w, http.StatusRequestEntityTooLarge,
			fmt.Errorf("part exceeds the %d-byte limit", uploadPartMax))
		return
	}
	u.Next++
	u.Bytes += nw
	// Guard runaway sessions against the declared size and the quota.
	if u.Declared > 0 && u.Bytes > u.Declared {
		s.dropUpload(u.ID, true)
		httpError(w, http.StatusRequestEntityTooLarge, errors.New("more bytes than declared"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": u.Bytes, "next": u.Next})
}

func (s *Server) handleFinalizeUpload(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	uploadID := r.PathValue("uploadID")
	u, uerr := s.getUpload(p, tenantID, uploadID)
	if uerr != nil {
		writeStoreError(w, uerr)
		return
	}
	f, err := os.Open(u.Path)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	n, status, err := s.uploadFile(r.Context(), p, u.TenantID, u.ParentID, u.Name, u.Mime, f, u.NoIndex)
	f.Close()
	if err != nil {
		// Keep the session on transient errors so the client may retry
		// finalize; drop it on client errors.
		if status < http.StatusInternalServerError {
			s.dropUpload(u.ID, true)
		}
		httpError(w, status, err)
		return
	}
	s.dropUpload(u.ID, true)
	writeJSON(w, http.StatusCreated, nodeView(n))
}

func (s *Server) handleAbortUpload(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	uploadID := r.PathValue("uploadID")
	if _, uerr := s.getUpload(p, tenantID, uploadID); uerr != nil {
		writeStoreError(w, uerr)
		return
	}
	s.dropUpload(uploadID, true)
	w.WriteHeader(http.StatusNoContent)
}

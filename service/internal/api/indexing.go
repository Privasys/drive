package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// Semantic-index wiring: the drive is its own RAG store. Files index by
// default; a folder marked non-searchable excludes its subtree, an
// explicit index=false at upload excludes one file, and non-text types
// skip. The indexer runs in-process; embeddings go to pgvector rows in
// the same DB as the node index.

var (
	indexerOnce sync.Once
	indexerRef  *search.Indexer
)

// indexer lazily builds the singleton background indexer. The embedder
// chain resolves the CURRENT config on every call, so configure changes
// (fleet endpoint) apply without a restart.
func (s *Server) indexer() *search.Indexer {
	indexerOnce.Do(func() {
		indexerRef = &search.Indexer{
			Ops:      indexOps{s.Store},
			Content:  s.indexContent,
			Embedder: &dynamicEmbedder{s: s},
		}
	})
	return indexerRef
}

// indexOps adapts the store to the search.Ops interface.
type indexOps struct{ st *store.Store }

func (o indexOps) SetIndexStatus(ctx context.Context, tenantID, nodeID, status string) error {
	return o.st.SetIndexStatus(ctx, tenantID, nodeID, status)
}

func (o indexOps) HasNoIndexAncestor(ctx context.Context, tenantID, nodeID string) (bool, error) {
	return o.st.HasNoIndexAncestor(ctx, tenantID, nodeID)
}

func (o indexOps) ReplaceEmbeddings(ctx context.Context, tenantID, nodeID string, rows []search.EmbeddingRowInput) error {
	converted := make([]store.EmbeddingRow, len(rows))
	for i, r := range rows {
		converted[i] = store.EmbeddingRow{ChunkIndex: r.ChunkIndex, Content: r.Content, Vector: r.Vector}
	}
	return o.st.ReplaceEmbeddings(ctx, tenantID, nodeID, converted)
}

// indexContent is the indexer's internal plaintext reader (same
// decrypt path as a download, no principal — it reads only what the
// tenant stored).
func (s *Server) indexContent(ctx context.Context, tenantID, nodeID string) (io.ReadCloser, error) {
	n, err := s.Store.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return nil, err
	}
	if n.Kind != store.NodeFile || n.WrappedCEK == nil {
		return nil, errors.New("not an indexable file")
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return nil, err
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	_, rc, err := manifest.Read(ctx, bk, dek, tenantID, n.ID, n.WrappedCEK)
	return rc, err
}

// dynamicEmbedder resolves the fleet-first / local-fallback chain from
// the live config at call time.
type dynamicEmbedder struct{ s *Server }

func (d *dynamicEmbedder) Name() string { return "dynamic" }

func (d *dynamicEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	chain := &search.Chain{}
	if cfg := d.s.CurrentConfig(); cfg != nil && cfg.EmbeddingsBaseURL != "" {
		model := cfg.EmbeddingsModel
		if model == "" {
			model = "nomic-embed-text"
		}
		chain.Embedders = append(chain.Embedders, &search.FleetEmbedder{
			BaseURL: cfg.EmbeddingsBaseURL, Model: model, APIKey: cfg.EmbeddingsAPIKey,
		})
	}
	chain.Embedders = append(chain.Embedders, search.LocalEmbedder{})
	return chain.Embed(ctx, texts)
}

// scheduleIndexing sets the initial status and enqueues a fresh file.
// noIndex marks the file excluded (the explicit upload flag).
func (s *Server) scheduleIndexing(ctx context.Context, n *store.Node, noIndex bool) {
	if noIndex {
		_ = s.Store.SetNoIndex(ctx, n.TenantID, n.ID, true)
		_ = s.Store.SetIndexStatus(ctx, n.TenantID, n.ID, store.IndexSkipped)
		return
	}
	// Without pgvector (SQLite dev, CI) the pipeline is unavailable:
	// leave the status empty rather than promising an index.
	if !s.Store.VectorOK {
		return
	}
	_ = s.Store.SetIndexStatus(ctx, n.TenantID, n.ID, store.IndexPending)
	s.indexer().Enqueue(n.TenantID, n.ID, n.Name, n.MimeHint)
}

// --- Folder / file searchability toggle --------------------------------

type setIndexingRequest struct {
	Enabled bool `json:"enabled"`
}

// handleSetIndexing marks a node (typically a folder) searchable or
// non-searchable. Excluding a folder covers its whole subtree for
// future uploads; existing embeddings under it are dropped for files
// directly excluded (folder-wide retro-purge is a follow-up).
func (s *Server) handleSetIndexing(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req setIndexingRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	n, err := s.Store.GetNode(r.Context(), tenantID, nodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if err := s.Store.SetNoIndex(r.Context(), tenantID, nodeID, !req.Enabled); err != nil {
		writeStoreError(w, err)
		return
	}
	if n.Kind == store.NodeFile {
		if req.Enabled {
			s.scheduleIndexing(r.Context(), n, false)
		} else {
			_ = s.Store.SetIndexStatus(r.Context(), tenantID, nodeID, store.IndexSkipped)
			if s.Store.VectorOK {
				_ = s.Store.ReplaceEmbeddings(r.Context(), tenantID, nodeID, nil)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "indexing": req.Enabled})
}

// --- Semantic search ----------------------------------------------------

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if !s.Store.VectorOK {
		httpError(w, http.StatusNotImplemented, errors.New("semantic search unavailable on this instance"))
		return
	}
	q := r.URL.Query().Get("q")
	if q == "" {
		httpError(w, http.StatusBadRequest, errors.New("q required"))
		return
	}
	topK, _ := strconv.Atoi(r.URL.Query().Get("k"))
	hits, status, err := s.semanticSearch(r.Context(), tenantID, q, topK)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hits": hits})
}

type searchHitJSON struct {
	NodeID     string  `json:"node_id"`
	Name       string  `json:"name"`
	MimeHint   string  `json:"mime_hint,omitempty"`
	ChunkIndex int     `json:"chunk_index"`
	Snippet    string  `json:"snippet"`
	Score      float64 `json:"score"`
}

func (s *Server) semanticSearch(ctx context.Context, tenantID, q string, topK int) ([]searchHitJSON, int, error) {
	emb := &dynamicEmbedder{s: s}
	vecs, err := emb.Embed(ctx, []string{q})
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	hits, err := s.Store.SearchEmbeddings(ctx, tenantID, vecs[0], topK)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	out := make([]searchHitJSON, 0, len(hits))
	for _, h := range hits {
		snippet := h.Content
		if len(snippet) > 400 {
			snippet = snippet[:400] + "…"
		}
		out = append(out, searchHitJSON{
			NodeID: h.NodeID, Name: h.Name, MimeHint: h.MimeHint,
			ChunkIndex: h.ChunkIndex, Snippet: snippet, Score: h.Score,
		})
	}
	return out, http.StatusOK, nil
}

// toolSearchSemantic is the agentic-RAG entry point: a chat session (or
// any grant/bearer-authenticated agent) searches the drive semantically
// and follows up with read_file on the hits.
func (s *Server) toolSearchSemantic(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		Query    string `json:"query"`
		TopK     int    `json:"top_k"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !p.IsUser() || !s.canRead(r.Context(), req.TenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if !s.Store.VectorOK {
		httpError(w, http.StatusNotImplemented, errors.New("semantic search unavailable on this instance"))
		return
	}
	if req.Query == "" {
		httpError(w, http.StatusBadRequest, errors.New("query required"))
		return
	}
	hits, status, err := s.semanticSearch(r.Context(), req.TenantID, req.Query, req.TopK)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hits": hits})
}

var _ = grants.ScopeRead

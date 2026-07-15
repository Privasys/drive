package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// Semantic-index wiring: the drive is its own RAG store. Files index by
// default; a folder marked non-searchable excludes its subtree, an
// explicit index=false at upload excludes one file, and non-text types
// skip. The indexer runs in-process; embeddings go to pgvector rows in
// the same DB as the node index, anchored to a deterministic section
// tree for provenance.

var (
	indexerOnce sync.Once
	indexerRef  *search.Indexer
)

// indexer lazily builds the singleton background indexer. The embedder
// resolves from the CURRENT config on every run, so configure changes
// (fleet endpoint) apply without a restart.
func (s *Server) indexer() *search.Indexer {
	indexerOnce.Do(func() {
		var conv search.Converter
		if c := search.NewSidecarConverter(os.Getenv("DRIVE_DOCLING_SOCKET")); c != nil {
			conv = c
		}
		indexerRef = &search.Indexer{
			Ops:      indexOps{s.Store},
			Content:  s.indexContent,
			Embedder: s.activeEmbedder,
			Convert:  conv,
		}
	})
	return indexerRef
}

// activeEmbedder resolves the embedding backend per §8.4: the
// configured fleet model when one exists (its failures park files
// pending — the lexical space never pollutes a configured deployment),
// the lexical space only until then.
func (s *Server) activeEmbedder() search.Embedder {
	if cfg := s.CurrentConfig(); cfg != nil && cfg.EmbeddingsBaseURL != "" {
		model := cfg.EmbeddingsModel
		if model == "" {
			model = "qwen3-embedding-0.6b"
		}
		return &search.FleetEmbedder{
			BaseURL: cfg.EmbeddingsBaseURL, Model: model, APIKey: cfg.EmbeddingsAPIKey,
		}
	}
	return search.LocalEmbedder{}
}

// indexOps adapts the store to the search.Ops interface.
type indexOps struct{ st *store.Store }

func (o indexOps) SetIndexStatus(ctx context.Context, tenantID, nodeID, status string) error {
	return o.st.SetIndexStatus(ctx, tenantID, nodeID, status)
}

func (o indexOps) HasNoIndexAncestor(ctx context.Context, tenantID, nodeID string) (bool, error) {
	return o.st.HasNoIndexAncestor(ctx, tenantID, nodeID)
}

func (o indexOps) ReplaceSections(ctx context.Context, tenantID, nodeID string, secs []search.SectionSpec) ([]int64, error) {
	converted := make([]store.SectionInput, len(secs))
	for i, sec := range secs {
		converted[i] = store.SectionInput{
			ParentIdx: sec.ParentIdx, Title: sec.Title, Depth: sec.Depth,
			CharStart: sec.CharStart, CharEnd: sec.CharEnd,
		}
	}
	return o.st.ReplaceSections(ctx, tenantID, nodeID, converted)
}

func (o indexOps) ReplaceEmbeddings(ctx context.Context, tenantID, nodeID, space string, rows []search.EmbeddingRowInput) error {
	converted := make([]store.EmbeddingRow, len(rows))
	for i, r := range rows {
		converted[i] = store.EmbeddingRow{
			SectionID: r.SectionID, ChunkIndex: r.ChunkIndex, Content: r.Content,
			CharStart: r.CharStart, CharEnd: r.CharEnd, Vector: r.Vector,
		}
	}
	return o.st.ReplaceEmbeddings(ctx, tenantID, nodeID, space, converted)
}

func (o indexOps) ListPendingIndex(ctx context.Context, limit int) ([][3]string, error) {
	return o.st.ListPendingIndex(ctx, limit)
}

func (o indexOps) SaveConversion(ctx context.Context, tenantID, nodeID, converter, text string) error {
	return o.st.SaveConversion(ctx, tenantID, nodeID, converter, text)
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
				_ = s.Store.ReplaceEmbeddings(r.Context(), tenantID, nodeID, s.activeEmbedder().Space(), nil)
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

// searchHitJSON is the provenance contract of every retrieval result
// (§8.3): enough for a citation chip that deep-links into the file.
type searchHitJSON struct {
	NodeID      string   `json:"node_id"`
	Name        string   `json:"name"`
	MimeHint    string   `json:"mime_hint,omitempty"`
	SectionID   *int64   `json:"section_id,omitempty"`
	SectionPath []string `json:"section_path,omitempty"`
	ChunkIndex  int      `json:"chunk_index"`
	CharStart   int64    `json:"char_start"`
	CharEnd     int64    `json:"char_end"`
	Snippet     string   `json:"snippet"`
	Score       float64  `json:"score"`
}

func (s *Server) semanticSearch(ctx context.Context, tenantID, q string, topK int) ([]searchHitJSON, int, error) {
	emb := s.activeEmbedder()
	vecs, err := emb.Embed(ctx, []string{q}, search.Query)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	hits, err := s.Store.SearchEmbeddings(ctx, tenantID, emb.Space(), vecs[0], topK)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	// Resolve section paths, one ListSections per distinct node.
	paths := map[string]map[int64][]string{}
	out := make([]searchHitJSON, 0, len(hits))
	for _, h := range hits {
		hit := searchHitJSON{
			NodeID: h.NodeID, Name: h.Name, MimeHint: h.MimeHint,
			SectionID: h.SectionID, ChunkIndex: h.ChunkIndex,
			CharStart: h.CharStart, CharEnd: h.CharEnd, Score: h.Score,
		}
		if len(h.Content) > 400 {
			hit.Snippet = h.Content[:400] + "…"
		} else {
			hit.Snippet = h.Content
		}
		if h.SectionID != nil {
			byNode, ok := paths[h.NodeID]
			if !ok {
				byNode = sectionPaths(ctx, s.Store, tenantID, h.NodeID)
				paths[h.NodeID] = byNode
			}
			hit.SectionPath = byNode[*h.SectionID]
		}
		out = append(out, hit)
	}
	return out, http.StatusOK, nil
}

// sectionPaths builds sectionID -> ["Root", "Title", …] for a file.
func sectionPaths(ctx context.Context, st *store.Store, tenantID, nodeID string) map[int64][]string {
	secs, err := st.ListSections(ctx, tenantID, nodeID)
	if err != nil {
		return map[int64][]string{}
	}
	byID := make(map[int64]*store.Section, len(secs))
	for _, sec := range secs {
		byID[sec.ID] = sec
	}
	out := make(map[int64][]string, len(secs))
	for _, sec := range secs {
		var path []string
		for cur := sec; cur != nil; {
			path = append([]string{cur.Title}, path...)
			if cur.ParentID == nil {
				break
			}
			cur = byID[*cur.ParentID]
		}
		out[sec.ID] = path
	}
	return out
}

// --- Doc tree + section retrieval (agentic RAG legs, §8.5) --------------

type sectionJSON struct {
	ID        int64  `json:"id"`
	ParentID  *int64 `json:"parent_id,omitempty"`
	Title     string `json:"title"`
	Depth     int    `json:"depth"`
	CharStart int64  `json:"char_start"`
	CharEnd   int64  `json:"char_end"`
	PageStart *int   `json:"page_start,omitempty"`
	PageEnd   *int   `json:"page_end,omitempty"`
	Summary   string `json:"summary,omitempty"`
}

// handleDocTree returns a file's section tree (titles + anchors +
// summaries when present): the agent's table of contents.
func (s *Server) handleDocTree(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	fileID := r.PathValue("fileID")
	if !s.allowNodeRead(r.Context(), p, tenantID, fileID) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	n, err := s.Store.GetNode(r.Context(), tenantID, fileID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	secs, err := s.Store.ListSections(r.Context(), tenantID, fileID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]sectionJSON, 0, len(secs))
	for _, sec := range secs {
		out = append(out, sectionJSON{
			ID: sec.ID, ParentID: sec.ParentID, Title: sec.Title, Depth: sec.Depth,
			CharStart: sec.CharStart, CharEnd: sec.CharEnd,
			PageStart: sec.PageStart, PageEnd: sec.PageEnd, Summary: sec.Summary,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": n.ID, "name": n.Name, "sections": out,
	})
}

// handleReadSection returns one whole section's text with provenance —
// the retrieval leg after tree navigation.
func (s *Server) handleReadSection(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	fileID := r.PathValue("fileID")
	sectionID, err := strconv.ParseInt(r.PathValue("sectionID"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.New("bad section id"))
		return
	}
	if !s.allowNodeRead(r.Context(), p, tenantID, fileID) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	sec, err := s.Store.GetSection(r.Context(), tenantID, sectionID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if sec.NodeID != fileID {
		httpError(w, http.StatusNotFound, errors.New("section does not belong to this file"))
		return
	}
	// Converted formats (PDF / Office / images) anchor their sections
	// into the stored docling markdown, not the binary original.
	var raw []byte
	if _, converted, cerr := s.Store.GetConversion(r.Context(), tenantID, fileID); cerr == nil {
		raw = []byte(converted)
	} else {
		rc, err := s.indexContent(r.Context(), tenantID, fileID)
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		raw, err = io.ReadAll(io.LimitReader(rc, 8<<20))
		rc.Close()
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	start, end := sec.CharStart, sec.CharEnd
	if start < 0 {
		start = 0
	}
	if end > int64(len(raw)) {
		end = int64(len(raw))
	}
	if start > end {
		start = end
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":    fileID,
		"section_id": sec.ID,
		"title":      sec.Title,
		"char_start": start,
		"char_end":   end,
		"page_start": sec.PageStart,
		"page_end":   sec.PageEnd,
		"text":       string(raw[start:end]),
	})
}

// allowNodeRead is the shared read authorisation (tenant member or
// grant-holder via the share cascade).
func (s *Server) allowNodeRead(ctx context.Context, p *Principal, tenantID, nodeID string) bool {
	if !p.IsUser() {
		return false
	}
	if s.canRead(ctx, tenantID, p.Sub) && s.aclAllows(ctx, tenantID, nodeID, p.Sub) {
		return true
	}
	return s.hasReadShare(ctx, tenantID, nodeID, p.Sub)
}

// --- Manifest tools -------------------------------------------------------

// toolSearchSemantic is the agentic-RAG entry point: a chat session (or
// any grant/bearer-authenticated agent) searches the drive semantically
// and follows up with get_doc_tree / read_section / read_file.
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

// toolDocTree is get_doc_tree for agents.
func (s *Server) toolDocTree(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		FileID   string `json:"file_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	r2.SetPathValue("fileID", req.FileID)
	s.handleDocTree(w, r2, p)
}

// toolReadSection is read_section for agents.
func (s *Server) toolReadSection(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID  string `json:"tenant_id"`
		FileID    string `json:"file_id"`
		SectionID int64  `json:"section_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	r2.SetPathValue("fileID", req.FileID)
	r2.SetPathValue("sectionID", strconv.FormatInt(req.SectionID, 10))
	s.handleReadSection(w, r2, p)
}

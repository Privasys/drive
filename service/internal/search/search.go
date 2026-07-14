// Package search implements the drive's semantic index: eligibility
// rules (searchable by default), deterministic document structure,
// section-anchored chunking, embedding (the confidential-AI fleet when
// configured, a lexical fallback only until then — spaces never mix)
// and the background indexing worker. Everything runs inside the
// attested enclave; embeddings persist next to the node index on the
// sealed volume.
package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Dim is the vector column width (Qwen3-Embedding-0.6B full width).
// Every embedder must produce exactly this many dimensions.
const Dim = 1024

// Versioned, image-baked instruction constants (drive plan §8.4): the
// query instruction shapes scoring but not stored vectors (documents
// embed instruction-free), so it lives here as a measured constant —
// changing it is a new image, a promote-gated release, never a silent
// config edit. Telemetry records the version.
const (
	QueryInstructVersion = "query_instruct/v1"
	// The Qwen3-Embedding retrieval instruction format.
	queryInstruct = "Instruct: Given a search query, retrieve relevant passages that answer the query\nQuery: "

	RerankInstructVersion = "rerank_instruct/v1"
	// Reserved for the §8.4 rerank leg (fleet /v1/rerank).
)

// maxIndexBytes caps how much of a file is read for indexing.
const maxIndexBytes = 4 << 20

// --- Eligibility -----------------------------------------------------

var textExt = map[string]bool{
	".txt": true, ".md": true, ".markdown": true, ".rst": true, ".csv": true,
	".tsv": true, ".json": true, ".yaml": true, ".yml": true, ".toml": true,
	".xml": true, ".html": true, ".htm": true, ".log": true, ".ini": true,
	".go": true, ".rs": true, ".py": true, ".js": true, ".ts": true,
	".tsx": true, ".jsx": true, ".java": true, ".c": true, ".h": true,
	".cpp": true, ".cs": true, ".rb": true, ".sh": true, ".sql": true,
	".css": true, ".tex": true,
}

// convertExt are formats that need a text-conversion step (docling)
// before they can be indexed — recognised but deferred until the
// conversion leg ships.
var convertExt = map[string]bool{
	".pdf": true, ".docx": true, ".doc": true, ".pptx": true,
	".png": true, ".jpg": true, ".jpeg": true, ".webp": true, ".tiff": true,
}

// Eligibility says what the pipeline can do with a file right now.
type Eligibility int

const (
	// NotIndexable — indexing makes no sense for the type (video,
	// archives, binaries). Status: skipped.
	NotIndexable Eligibility = iota
	// NeedsConversion — indexable once the docling conversion leg
	// ships. Status: skipped for now.
	NeedsConversion
	// Indexable — plain text; structure, chunk and embed directly.
	Indexable
)

// Classify determines indexing eligibility from the name and mime hint.
func Classify(name, mime string) Eligibility {
	ext := strings.ToLower(filepath.Ext(name))
	if textExt[ext] || strings.HasPrefix(mime, "text/") ||
		mime == "application/json" || mime == "application/xml" {
		return Indexable
	}
	if convertExt[ext] || mime == "application/pdf" {
		return NeedsConversion
	}
	return NotIndexable
}

// --- Chunking ----------------------------------------------------------

const (
	chunkSize    = 1600
	chunkOverlap = 200
)

// Chunk is one embedded window with its absolute char anchors.
type ChunkSpan struct {
	Text  string
	Start int64 // absolute char offset in the document
	End   int64
}

// ChunkRange splits text[start:end] (absolute offsets) into overlapping
// windows, preferring paragraph and line boundaries near the target
// size. Anchors are absolute so provenance survives.
func ChunkRange(text string, start, end int64) []ChunkSpan {
	if start < 0 {
		start = 0
	}
	if end > int64(len(text)) {
		end = int64(len(text))
	}
	if start >= end {
		return nil
	}
	seg := text[start:end]
	var out []ChunkSpan
	for off := 0; off < len(seg); {
		lim := off + chunkSize
		if lim >= len(seg) {
			span := strings.TrimSpace(seg[off:])
			if span != "" {
				out = append(out, ChunkSpan{Text: span, Start: start + int64(off), End: end})
			}
			break
		}
		window := seg[off:lim]
		cut := strings.LastIndex(window, "\n\n")
		if cut < chunkSize/2 {
			if i := strings.LastIndexByte(window, '\n'); i > chunkSize/2 {
				cut = i
			} else if i := strings.LastIndexByte(window, ' '); i > chunkSize/2 {
				cut = i
			} else {
				cut = len(window)
			}
		}
		span := strings.TrimSpace(seg[off : off+cut])
		if span != "" {
			out = append(out, ChunkSpan{Text: span, Start: start + int64(off), End: start + int64(off+cut)})
		}
		next := off + cut - chunkOverlap
		if next <= off {
			next = off + cut
		}
		off = next
	}
	return out
}

// Chunk splits whole text (compatibility helper for tests).
func Chunk(text string) []string {
	spans := ChunkRange(text, 0, int64(len(text)))
	out := make([]string, 0, len(spans))
	for _, s := range spans {
		out = append(out, s.Text)
	}
	return out
}

// --- Embedders ---------------------------------------------------------

// Mode distinguishes query embedding (instruction-prefixed) from
// document embedding (raw) — the Qwen3 asymmetry.
type Mode int

const (
	Document Mode = iota
	Query
)

// Embedder turns texts into Dim-dimensional vectors within a named
// vector space. Space() identifies everything that determines a STORED
// vector (model, dims, doc-side template, truncation policy); rows and
// queries only ever meet inside one space.
type Embedder interface {
	Embed(ctx context.Context, texts []string, mode Mode) ([][]float32, error)
	Space() string
}

// FleetEmbedder calls an OpenAI-compatible embeddings endpoint on the
// confidential-AI fleet. Documents embed instruction-free; queries get
// the versioned retrieval instruction prefix client-side (the fleet is
// instruction-agnostic).
type FleetEmbedder struct {
	BaseURL string // e.g. https://<instance-host>
	Model   string
	APIKey  string
	Client  *http.Client
}

func (f *FleetEmbedder) Space() string {
	return fmt.Sprintf("%s/%d/doc-noinstr/v1", f.Model, Dim)
}

func (f *FleetEmbedder) Embed(ctx context.Context, texts []string, mode Mode) ([][]float32, error) {
	inputs := texts
	if mode == Query {
		inputs = make([]string, len(texts))
		for i, t := range texts {
			inputs[i] = queryInstruct + t
		}
	}
	body, err := json.Marshal(map[string]any{"model": f.Model, "input": inputs})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(f.BaseURL, "/")+"/v1/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if f.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.APIKey)
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, fmt.Errorf("fleet embeddings: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Data []struct {
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Data) != len(texts) {
		return nil, fmt.Errorf("fleet embeddings: %d vectors for %d inputs", len(out.Data), len(texts))
	}
	vecs := make([][]float32, len(out.Data))
	for i, d := range out.Data {
		if len(d.Embedding) != Dim {
			return nil, fmt.Errorf("fleet embeddings: dimension %d, want %d (pick a %d-dim model)", len(d.Embedding), Dim, Dim)
		}
		vecs[i] = d.Embedding
	}
	return vecs, nil
}

// --- Indexer -----------------------------------------------------------

// Content loads a file's plaintext for indexing (an internal read; the
// caller enforces nothing here — the indexer only ever reads content
// the tenant uploaded).
type Content func(ctx context.Context, tenantID, nodeID string) (io.ReadCloser, error)

// Ops is the persistence surface the indexer needs (implemented by the
// store).
type Ops interface {
	SetIndexStatus(ctx context.Context, tenantID, nodeID, status string) error
	HasNoIndexAncestor(ctx context.Context, tenantID, nodeID string) (bool, error)
	ReplaceSections(ctx context.Context, tenantID, nodeID string, secs []SectionSpec) ([]int64, error)
	ReplaceEmbeddings(ctx context.Context, tenantID, nodeID, space string, rows []EmbeddingRowInput) error
	ListPendingIndex(ctx context.Context, limit int) ([][3]string, error)
}

// SectionSpec mirrors store.SectionInput without importing store.
type SectionSpec struct {
	ParentIdx int
	Title     string
	Depth     int
	CharStart int64
	CharEnd   int64
}

// EmbeddingRowInput mirrors store.EmbeddingRow without importing store.
type EmbeddingRowInput struct {
	SectionID  *int64
	ChunkIndex int
	Content    string
	CharStart  int64
	CharEnd    int64
	Vector     []float32
}

type job struct {
	tenantID, nodeID, name, mime string
}

// Indexer is the background semantic-index worker.
type Indexer struct {
	Ops     Ops
	Content Content
	// Embedder returns the CURRENT embedder, resolved per run so a
	// configure change (fleet endpoint) applies without a restart.
	Embedder func() Embedder
	// Sync makes Process run inline in Enqueue (tests).
	Sync bool

	once  sync.Once
	queue chan job

	mu       sync.Mutex
	attempts map[string]int       // nodeID -> failed attempts
	nextTry  map[string]time.Time // nodeID -> earliest retry
}

const (
	// Status constants mirrored from the store to avoid the import.
	statusProcessing = "processing"
	statusIndexed    = "indexed"
	statusSkipped    = "skipped"
	statusFailed     = "failed"
	statusPending    = "pending"

	sweepInterval = 3 * time.Minute
	maxBackoff    = 30 * time.Minute
)

func (ix *Indexer) start() {
	ix.queue = make(chan job, 256)
	ix.attempts = make(map[string]int)
	ix.nextTry = make(map[string]time.Time)
	go func() {
		for j := range ix.queue {
			ix.process(context.Background(), j)
		}
	}()
	// Retry sweep: files parked pending (fleet down, queue overflow,
	// restart) are re-enqueued with per-node backoff.
	go func() {
		t := time.NewTicker(sweepInterval)
		defer t.Stop()
		for range t.C {
			pend, err := ix.Ops.ListPendingIndex(context.Background(), 50)
			if err != nil {
				continue
			}
			now := time.Now()
			for _, p := range pend {
				ix.mu.Lock()
				ready := now.After(ix.nextTry[p[1]])
				ix.mu.Unlock()
				if !ready {
					continue
				}
				select {
				case ix.queue <- job{tenantID: p[0], nodeID: p[1], name: p[2]}:
				default:
				}
			}
		}
	}()
}

// Enqueue schedules a freshly written file for indexing. Non-blocking:
// when the queue is full the file stays 'pending' and the sweep picks
// it up.
func (ix *Indexer) Enqueue(tenantID, nodeID, name, mime string) {
	if ix == nil {
		return
	}
	j := job{tenantID: tenantID, nodeID: nodeID, name: name, mime: mime}
	if ix.Sync {
		if ix.attempts == nil {
			ix.attempts = make(map[string]int)
			ix.nextTry = make(map[string]time.Time)
		}
		ix.process(context.Background(), j)
		return
	}
	ix.once.Do(ix.start)
	select {
	case ix.queue <- j:
	default:
		log.Printf("search: index queue full, %s stays pending", nodeID)
	}
}

// parkPending leaves the node pending and schedules a backed-off retry
// (transient failures: fleet unreachable, content read hiccup).
func (ix *Indexer) parkPending(ctx context.Context, j job) {
	if err := ix.Ops.SetIndexStatus(ctx, j.tenantID, j.nodeID, statusPending); err != nil {
		log.Printf("search: park %s: %v", j.nodeID, err)
	}
	ix.mu.Lock()
	ix.attempts[j.nodeID]++
	backoff := time.Duration(1<<min(ix.attempts[j.nodeID], 5)) * time.Minute
	if backoff > maxBackoff {
		backoff = maxBackoff
	}
	ix.nextTry[j.nodeID] = time.Now().Add(backoff)
	ix.mu.Unlock()
}

func (ix *Indexer) clearBackoff(nodeID string) {
	ix.mu.Lock()
	delete(ix.attempts, nodeID)
	delete(ix.nextTry, nodeID)
	ix.mu.Unlock()
}

func (ix *Indexer) process(ctx context.Context, j job) {
	setStatus := func(st string) {
		if err := ix.Ops.SetIndexStatus(ctx, j.tenantID, j.nodeID, st); err != nil {
			log.Printf("search: set status %s on %s: %v", st, j.nodeID, err)
		}
	}
	// Re-check the ancestor rule at processing time (a folder may have
	// been marked non-searchable between upload and processing).
	if excluded, err := ix.Ops.HasNoIndexAncestor(ctx, j.tenantID, j.nodeID); err != nil || excluded {
		setStatus(statusSkipped)
		ix.clearBackoff(j.nodeID)
		return
	}
	switch Classify(j.name, j.mime) {
	case Indexable:
		// proceed
	case NeedsConversion:
		// The docling conversion leg is not wired yet; recognised
		// formats wait as skipped rather than failing.
		setStatus(statusSkipped)
		ix.clearBackoff(j.nodeID)
		return
	default:
		setStatus(statusSkipped)
		ix.clearBackoff(j.nodeID)
		return
	}
	setStatus(statusProcessing)

	rc, err := ix.Content(ctx, j.tenantID, j.nodeID)
	if err != nil {
		log.Printf("search: read %s: %v", j.nodeID, err)
		ix.parkPending(ctx, j)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxIndexBytes))
	rc.Close()
	if err != nil {
		ix.parkPending(ctx, j)
		return
	}
	text := string(raw)

	// Deterministic structure first: the doc tree exists even when the
	// embedding leg fails (titles now, summaries later, §8.5).
	secs := BuildSections(j.name, text)
	ids, err := ix.Ops.ReplaceSections(ctx, j.tenantID, j.nodeID, secs)
	if err != nil {
		log.Printf("search: sections %s: %v", j.nodeID, err)
		setStatus(statusFailed)
		return
	}

	// Section-anchored chunking.
	var rows []EmbeddingRowInput
	var chunkTexts []string
	for si, sec := range secs {
		for _, span := range ChunkRange(text, sec.CharStart, sec.CharEnd) {
			id := ids[si]
			rows = append(rows, EmbeddingRowInput{
				SectionID: &id, ChunkIndex: len(rows),
				Content: span.Text, CharStart: span.Start, CharEnd: span.End,
			})
			chunkTexts = append(chunkTexts, span.Text)
		}
	}
	if len(rows) == 0 {
		setStatus(statusIndexed) // empty file: trivially indexed
		ix.clearBackoff(j.nodeID)
		return
	}

	emb := ix.Embedder()
	vecs, err := emb.Embed(ctx, chunkTexts, Document)
	if err != nil {
		// Transient by policy (§8.4): the fleet being down parks the
		// file pending; deferred beats polluted.
		log.Printf("search: embed %s (%s): %v", j.nodeID, emb.Space(), err)
		ix.parkPending(ctx, j)
		return
	}
	for i := range rows {
		rows[i].Vector = vecs[i]
	}
	if err := ix.Ops.ReplaceEmbeddings(ctx, j.tenantID, j.nodeID, emb.Space(), rows); err != nil {
		log.Printf("search: store embeddings %s: %v", j.nodeID, err)
		setStatus(statusFailed)
		return
	}
	setStatus(statusIndexed)
	ix.clearBackoff(j.nodeID)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

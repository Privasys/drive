// Package search implements the drive's semantic index: eligibility
// rules (searchable by default), text chunking, embedding (the
// confidential-AI fleet first, a local CPU fallback when it fails) and
// the background indexing worker. Everything runs inside the attested
// enclave; embeddings persist next to the node index on the sealed
// volume.
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

// Dim is the embedding dimensionality (the pgvector column width).
// Fleet models must produce this many dimensions; the local fallback
// always does.
const Dim = 768

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
	// Indexable — plain text; chunk and embed directly.
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

// Chunk splits text into overlapping windows, preferring paragraph and
// line boundaries near the target size.
func Chunk(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	var out []string
	for start := 0; start < len(text); {
		end := start + chunkSize
		if end >= len(text) {
			out = append(out, strings.TrimSpace(text[start:]))
			break
		}
		// Prefer to break on a paragraph, then a line, then a space.
		window := text[start:end]
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
		out = append(out, strings.TrimSpace(text[start:start+cut]))
		next := start + cut - chunkOverlap
		if next <= start {
			next = start + cut
		}
		start = next
	}
	// Drop empties.
	kept := out[:0]
	for _, c := range out {
		if c != "" {
			kept = append(kept, c)
		}
	}
	return kept
}

// --- Embedders ---------------------------------------------------------

// Embedder turns texts into Dim-dimensional vectors.
type Embedder interface {
	Embed(ctx context.Context, texts []string) ([][]float32, error)
	Name() string
}

// FleetEmbedder calls an OpenAI-compatible embeddings endpoint on the
// confidential-AI fleet.
type FleetEmbedder struct {
	BaseURL string // e.g. https://<instance-host>
	Model   string
	APIKey  string
	Client  *http.Client
}

func (f *FleetEmbedder) Name() string { return "fleet:" + f.Model }

func (f *FleetEmbedder) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	body, err := json.Marshal(map[string]any{"model": f.Model, "input": texts})
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

// Chain tries embedders in order, falling through on error.
type Chain struct {
	Embedders []Embedder
}

func (c *Chain) Name() string { return "chain" }

func (c *Chain) Embed(ctx context.Context, texts []string) ([][]float32, error) {
	var lastErr error
	for _, e := range c.Embedders {
		vecs, err := e.Embed(ctx, texts)
		if err == nil {
			return vecs, nil
		}
		lastErr = fmt.Errorf("%s: %w", e.Name(), err)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no embedder configured")
	}
	return nil, lastErr
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
	ReplaceEmbeddings(ctx context.Context, tenantID, nodeID string, rows []EmbeddingRowInput) error
}

// EmbeddingRowInput mirrors store.EmbeddingRow without importing store.
type EmbeddingRowInput struct {
	ChunkIndex int
	Content    string
	Vector     []float32
}

type job struct {
	tenantID, nodeID, name, mime string
}

// Indexer is the background semantic-index worker.
type Indexer struct {
	Ops      Ops
	Content  Content
	Embedder Embedder
	// Sync makes Process run inline in Enqueue (tests).
	Sync bool

	once  sync.Once
	queue chan job
}

const (
	// Status constants mirrored from the store to avoid the import.
	statusProcessing = "processing"
	statusIndexed    = "indexed"
	statusSkipped    = "skipped"
	statusFailed     = "failed"
)

func (ix *Indexer) start() {
	ix.queue = make(chan job, 256)
	go func() {
		for j := range ix.queue {
			ix.process(context.Background(), j)
		}
	}()
}

// Enqueue schedules a freshly written file for indexing. Non-blocking:
// when the queue is full the file stays 'pending' and a later re-index
// sweep can pick it up.
func (ix *Indexer) Enqueue(tenantID, nodeID, name, mime string) {
	if ix == nil {
		return
	}
	j := job{tenantID: tenantID, nodeID: nodeID, name: name, mime: mime}
	if ix.Sync {
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
		return
	}
	switch Classify(j.name, j.mime) {
	case Indexable:
		// proceed
	case NeedsConversion:
		// The docling conversion leg is not wired yet; recognised
		// formats wait as skipped rather than failing.
		setStatus(statusSkipped)
		return
	default:
		setStatus(statusSkipped)
		return
	}
	setStatus(statusProcessing)

	rc, err := ix.Content(ctx, j.tenantID, j.nodeID)
	if err != nil {
		log.Printf("search: read %s: %v", j.nodeID, err)
		setStatus(statusFailed)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(rc, maxIndexBytes))
	rc.Close()
	if err != nil {
		setStatus(statusFailed)
		return
	}
	chunks := Chunk(string(raw))
	if len(chunks) == 0 {
		setStatus(statusIndexed) // empty file: trivially indexed
		return
	}
	vecs, err := ix.Embedder.Embed(ctx, chunks)
	if err != nil {
		log.Printf("search: embed %s: %v", j.nodeID, err)
		setStatus(statusFailed)
		return
	}
	rows := make([]EmbeddingRowInput, len(chunks))
	for i := range chunks {
		rows[i] = EmbeddingRowInput{ChunkIndex: i, Content: chunks[i], Vector: vecs[i]}
	}
	if err := ix.Ops.ReplaceEmbeddings(ctx, j.tenantID, j.nodeID, rows); err != nil {
		log.Printf("search: store embeddings %s: %v", j.nodeID, err)
		setStatus(statusFailed)
		return
	}
	setStatus(statusIndexed)
}

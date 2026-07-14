package search

import (
	"context"
	"io"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name, mime string
		want       Eligibility
	}{
		{"notes.md", "", Indexable},
		{"main.go", "", Indexable},
		{"data.json", "application/json", Indexable},
		{"letter", "text/plain", Indexable},
		{"deck.pdf", "application/pdf", NeedsConversion},
		{"scan.png", "image/png", NeedsConversion},
		{"report.docx", "", NeedsConversion},
		{"movie.mp4", "video/mp4", NotIndexable},
		{"archive.zip", "application/zip", NotIndexable},
	}
	for _, c := range cases {
		if got := Classify(c.name, c.mime); got != c.want {
			t.Errorf("Classify(%q, %q) = %v, want %v", c.name, c.mime, got, c.want)
		}
	}
}

func TestChunkCoversAndOverlaps(t *testing.T) {
	para := strings.Repeat("alpha beta gamma delta. ", 40) // ~960 chars
	text := para + "\n\n" + para + "\n\n" + para
	chunks := Chunk(text)
	if len(chunks) < 2 {
		t.Fatalf("expected multiple chunks, got %d", len(chunks))
	}
	for _, c := range chunks {
		if len(c) > chunkSize+chunkOverlap {
			t.Fatalf("chunk too large: %d", len(c))
		}
	}
	// The tail of the text must be present.
	if !strings.Contains(chunks[len(chunks)-1], "delta") {
		t.Fatalf("tail lost")
	}
	if Chunk("") != nil {
		t.Fatalf("empty text should yield no chunks")
	}
}

func TestLocalEmbedderDeterministicAndDiscriminative(t *testing.T) {
	e := LocalEmbedder{}
	v1, _ := e.Embed(context.Background(), []string{"the quarterly finance report for acme"})
	v2, _ := e.Embed(context.Background(), []string{"the quarterly finance report for acme"})
	v3, _ := e.Embed(context.Background(), []string{"holiday photos from the beach trip"})
	if len(v1[0]) != Dim {
		t.Fatalf("dim %d", len(v1[0]))
	}
	if cosine(v1[0], v2[0]) < 0.999 {
		t.Fatalf("not deterministic")
	}
	same := cosine(v1[0], v2[0])
	diff := cosine(v1[0], v3[0])
	if diff >= same {
		t.Fatalf("unrelated texts not discriminated: same=%f diff=%f", same, diff)
	}
	// A related query should land closer than an unrelated one.
	q, _ := e.Embed(context.Background(), []string{"finance report"})
	if cosine(q[0], v1[0]) <= cosine(q[0], v3[0]) {
		t.Fatalf("related query not closer")
	}
}

func cosine(a, b []float32) float64 {
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot // inputs are L2-normalised
}

// --- Indexer flow with fakes -------------------------------------------

type fakeOps struct {
	status   map[string]string
	rows     map[string][]EmbeddingRowInput
	excluded map[string]bool
}

func (f *fakeOps) SetIndexStatus(_ context.Context, _, nodeID, status string) error {
	f.status[nodeID] = status
	return nil
}

func (f *fakeOps) HasNoIndexAncestor(_ context.Context, _, nodeID string) (bool, error) {
	return f.excluded[nodeID], nil
}

func (f *fakeOps) ReplaceEmbeddings(_ context.Context, _, nodeID string, rows []EmbeddingRowInput) error {
	f.rows[nodeID] = rows
	return nil
}

func newFakeOps() *fakeOps {
	return &fakeOps{status: map[string]string{}, rows: map[string][]EmbeddingRowInput{}, excluded: map[string]bool{}}
}

func TestIndexerLifecycle(t *testing.T) {
	ops := newFakeOps()
	content := map[string]string{
		"n-text":  "the quarterly finance report shows revenue growth across regions",
		"n-empty": "",
	}
	ix := &Indexer{
		Ops: ops,
		Content: func(_ context.Context, _, nodeID string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(content[nodeID])), nil
		},
		Embedder: LocalEmbedder{},
		Sync:     true,
	}

	// Plain text: indexed with rows.
	ix.Enqueue("t1", "n-text", "report.md", "text/markdown")
	if ops.status["n-text"] != "indexed" || len(ops.rows["n-text"]) == 0 {
		t.Fatalf("text: status=%q rows=%d", ops.status["n-text"], len(ops.rows["n-text"]))
	}

	// Video: skipped, no rows.
	ix.Enqueue("t1", "n-video", "movie.mp4", "video/mp4")
	if ops.status["n-video"] != "skipped" || len(ops.rows["n-video"]) != 0 {
		t.Fatalf("video: status=%q", ops.status["n-video"])
	}

	// Needs conversion (docling leg pending): skipped.
	ix.Enqueue("t1", "n-pdf", "deck.pdf", "application/pdf")
	if ops.status["n-pdf"] != "skipped" {
		t.Fatalf("pdf: status=%q", ops.status["n-pdf"])
	}

	// Under a non-searchable folder: skipped even for text.
	ops.excluded["n-under"] = true
	ix.Enqueue("t1", "n-under", "notes.md", "")
	if ops.status["n-under"] != "skipped" {
		t.Fatalf("excluded: status=%q", ops.status["n-under"])
	}

	// Empty file: trivially indexed, no rows.
	ix.Enqueue("t1", "n-empty", "empty.txt", "text/plain")
	if ops.status["n-empty"] != "indexed" || len(ops.rows["n-empty"]) != 0 {
		t.Fatalf("empty: status=%q rows=%d", ops.status["n-empty"], len(ops.rows["n-empty"]))
	}
}

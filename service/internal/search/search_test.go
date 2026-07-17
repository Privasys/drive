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
	if len(Chunk("")) != 0 {
		t.Fatalf("empty text should yield no chunks")
	}
}

func TestChunkRangeAnchors(t *testing.T) {
	text := "prefix. " + strings.Repeat("body words here. ", 200) + "suffix."
	spans := ChunkRange(text, 8, int64(len(text)))
	if len(spans) < 2 {
		t.Fatalf("want multiple spans, got %d", len(spans))
	}
	for _, sp := range spans {
		if sp.Start < 8 || sp.End > int64(len(text)) || sp.Start >= sp.End {
			t.Fatalf("bad anchors: %d..%d", sp.Start, sp.End)
		}
		// The anchored slice must contain the span text (the span is a
		// trimmed cut of it).
		if !strings.Contains(text[sp.Start:sp.End], strings.Fields(sp.Text)[0]) {
			t.Fatalf("anchor mismatch")
		}
	}
}

func TestBuildSectionsMarkdown(t *testing.T) {
	md := "intro line\n\n# One\nalpha\n\n## One-A\nbeta\n\n# Two\ngamma\n"
	secs := BuildSections("doc.md", md)
	// root + One + One-A + Two
	if len(secs) != 4 {
		t.Fatalf("want 4 sections, got %d: %+v", len(secs), secs)
	}
	if secs[0].ParentIdx != -1 || secs[0].Title != "doc" {
		t.Fatalf("root: %+v", secs[0])
	}
	one, oneA, two := secs[1], secs[2], secs[3]
	if one.Title != "One" || one.ParentIdx != 0 {
		t.Fatalf("one: %+v", one)
	}
	if oneA.Title != "One-A" || oneA.ParentIdx != 1 {
		t.Fatalf("one-a: %+v", oneA)
	}
	if two.Title != "Two" || two.ParentIdx != 0 {
		t.Fatalf("two: %+v", two)
	}
	// "One" runs from its heading to the start of "Two".
	if !strings.Contains(md[one.CharStart:one.CharEnd], "beta") ||
		strings.Contains(md[one.CharStart:one.CharEnd], "gamma") {
		t.Fatalf("one range wrong: %q", md[one.CharStart:one.CharEnd])
	}
	// Fenced code heading is not a section.
	fenced := "# Real\n```\n# not a heading\n```\n"
	if got := BuildSections("f.md", fenced); len(got) != 2 {
		t.Fatalf("fenced: want 2, got %d", len(got))
	}
}

func TestBuildSectionsFallback(t *testing.T) {
	long := strings.Repeat("paragraph text here.\n\n", 800) // ~17k chars
	secs := BuildSections("notes.txt", long)
	if len(secs) < 3 { // root + >=2 parts
		t.Fatalf("want size-based parts, got %d", len(secs))
	}
	if secs[1].Title != "Part 1" || secs[1].ParentIdx != 0 {
		t.Fatalf("part: %+v", secs[1])
	}
	// Small file: single root section.
	if got := BuildSections("s.txt", "tiny"); len(got) != 1 {
		t.Fatalf("small: want 1, got %d", len(got))
	}
}

func TestLocalEmbedderDeterministicAndDiscriminative(t *testing.T) {
	e := LocalEmbedder{}
	v1, _ := e.Embed(context.Background(), []string{"the quarterly finance report for acme"}, Document)
	v2, _ := e.Embed(context.Background(), []string{"the quarterly finance report for acme"}, Document)
	v3, _ := e.Embed(context.Background(), []string{"holiday photos from the beach trip"}, Document)
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
	q, _ := e.Embed(context.Background(), []string{"finance report"}, Query)
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
	status      map[string]string
	secs        map[string][]SectionSpec
	rows        map[string][]EmbeddingRowInput
	space       map[string]string
	excluded    map[string]bool
	conversions map[string]string
	links       map[string][]RawLink
}

func (f *fakeOps) SetIndexStatus(_ context.Context, _, nodeID, status string) error {
	f.status[nodeID] = status
	return nil
}

func (f *fakeOps) HasNoIndexAncestor(_ context.Context, _, nodeID string) (bool, error) {
	return f.excluded[nodeID], nil
}

func (f *fakeOps) ReplaceSections(_ context.Context, _, nodeID string, secs []SectionSpec) ([]int64, error) {
	f.secs[nodeID] = secs
	ids := make([]int64, len(secs))
	for i := range ids {
		ids[i] = int64(i + 1)
	}
	return ids, nil
}

func (f *fakeOps) ReplaceEmbeddings(_ context.Context, _, nodeID, space string, rows []EmbeddingRowInput) error {
	f.rows[nodeID] = rows
	f.space[nodeID] = space
	return nil
}

func (f *fakeOps) ListPendingIndex(_ context.Context, _ int) ([][3]string, error) {
	return nil, nil
}

func (f *fakeOps) SaveConversion(_ context.Context, _, nodeID, converter, text string) error {
	f.conversions[nodeID] = converter + "|" + text
	return nil
}

func (f *fakeOps) ReplaceLinks(_ context.Context, _, nodeID string, links []RawLink) error {
	if f.links == nil {
		f.links = map[string][]RawLink{}
	}
	f.links[nodeID] = links
	return nil
}

func newFakeOps() *fakeOps {
	return &fakeOps{
		status: map[string]string{}, secs: map[string][]SectionSpec{},
		rows: map[string][]EmbeddingRowInput{}, space: map[string]string{},
		excluded: map[string]bool{}, conversions: map[string]string{},
	}
}

func TestIndexerLifecycle(t *testing.T) {
	ops := newFakeOps()
	content := map[string]string{
		"n-text":  "# Report\nthe quarterly finance report shows revenue growth\n\n# Annex\nregional numbers",
		"n-empty": "",
	}
	ix := &Indexer{
		Ops: ops,
		Content: func(_ context.Context, _, nodeID string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(content[nodeID])), nil
		},
		Embedder: func() Embedder { return LocalEmbedder{} },
		Sync:     true,
	}

	// Markdown: sections built + indexed with anchored rows.
	ix.Enqueue("t1", "n-text", "report.md", "text/markdown")
	if ops.status["n-text"] != "indexed" || len(ops.rows["n-text"]) == 0 {
		t.Fatalf("text: status=%q rows=%d", ops.status["n-text"], len(ops.rows["n-text"]))
	}
	if len(ops.secs["n-text"]) != 3 { // root + Report + Annex
		t.Fatalf("sections: %d", len(ops.secs["n-text"]))
	}
	if ops.space["n-text"] != (LocalEmbedder{}).Space() {
		t.Fatalf("space: %q", ops.space["n-text"])
	}
	for _, r := range ops.rows["n-text"] {
		if r.SectionID == nil || r.CharEnd <= r.CharStart {
			t.Fatalf("row missing provenance: %+v", r)
		}
	}

	// Video: skipped, no rows.
	ix.Enqueue("t1", "n-video", "movie.mp4", "video/mp4")
	if ops.status["n-video"] != "skipped" || len(ops.rows["n-video"]) != 0 {
		t.Fatalf("video: status=%q", ops.status["n-video"])
	}

	// Needs conversion with NO converter wired: skipped.
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

// --- Conversion leg (docling) -------------------------------------------

type fakeConverter struct {
	markdown string
	err      error
}

func (f fakeConverter) Convert(context.Context, string, string, []byte) (string, string, error) {
	if f.err != nil {
		return "", "", f.err
	}
	return f.markdown, "docling/test", nil
}

func TestIndexerConvertsNonText(t *testing.T) {
	ops := newFakeOps()
	ix := &Indexer{
		Ops: ops,
		Content: func(context.Context, string, string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("%PDF-1.7 binary bytes")), nil
		},
		Embedder: func() Embedder { return LocalEmbedder{} },
		Convert:  fakeConverter{markdown: "# Deck\nslide one text\n\n# Annex\nslide two text"},
		Sync:     true,
	}
	ix.Enqueue("t1", "n-deck", "deck.pdf", "application/pdf")
	if ops.status["n-deck"] != "indexed" {
		t.Fatalf("converted pdf: status=%q", ops.status["n-deck"])
	}
	if !strings.Contains(ops.conversions["n-deck"], "slide one text") {
		t.Fatalf("conversion not saved: %q", ops.conversions["n-deck"])
	}
	// Sections come from the CONVERTED markdown: root + Deck + Annex.
	if len(ops.secs["n-deck"]) != 3 {
		t.Fatalf("sections from conversion: %d", len(ops.secs["n-deck"]))
	}
	if len(ops.rows["n-deck"]) == 0 {
		t.Fatalf("no embedding rows")
	}

	// Transient sidecar failure parks pending.
	ix.Convert = fakeConverter{err: io.ErrUnexpectedEOF}
	ix.Enqueue("t1", "n-down", "down.pdf", "application/pdf")
	if ops.status["n-down"] != "pending" {
		t.Fatalf("sidecar down: status=%q", ops.status["n-down"])
	}

	// A permanently unconvertible document fails, no retry loop.
	ix.Convert = fakeConverter{err: &PermanentError{Msg: "encrypted pdf"}}
	ix.Enqueue("t1", "n-bad", "bad.pdf", "application/pdf")
	if ops.status["n-bad"] != "failed" {
		t.Fatalf("permanent: status=%q", ops.status["n-bad"])
	}
}

// TestIndexerParksPendingOnEmbedFailure: a failing embedder (fleet
// down) must park the file pending, never write rows.
func TestIndexerParksPendingOnEmbedFailure(t *testing.T) {
	ops := newFakeOps()
	ix := &Indexer{
		Ops: ops,
		Content: func(_ context.Context, _, _ string) (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("some indexable text")), nil
		},
		Embedder: func() Embedder { return failingEmbedder{} },
		Sync:     true,
	}
	ix.Enqueue("t1", "n-fleetdown", "doc.txt", "text/plain")
	if ops.status["n-fleetdown"] != "pending" {
		t.Fatalf("want pending, got %q", ops.status["n-fleetdown"])
	}
	if len(ops.rows["n-fleetdown"]) != 0 {
		t.Fatalf("rows written despite failure")
	}
}

type failingEmbedder struct{}

func (failingEmbedder) Space() string { return "fleet-test/1024/doc-noinstr/v1" }
func (failingEmbedder) Embed(context.Context, []string, Mode) ([][]float32, error) {
	return nil, io.ErrUnexpectedEOF
}

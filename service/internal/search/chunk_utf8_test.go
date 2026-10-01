package search

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// A chunk is stored as text, so it must be whole characters. The windows and
// the overlap step were measured in bytes, so a boundary could land inside a
// multi-byte character and a chunk began with its tail: Postgres refused the
// batch ("invalid byte sequence for encoding UTF8: 0x9d", the last byte of a
// closing curly quote) and the file never indexed. Documents full of curly
// quotes, pound signs and accented names are exactly what people keep here.
func TestChunksAreWholeCharacters(t *testing.T) {
	cases := map[string]string{
		// No space or newline to cut at, so every cut falls back to the window
		// edge: 1,600 bytes is not a multiple of 3, nor is the 200-byte overlap.
		"unbroken multi-byte run": strings.Repeat("”", 3000),
		// Ordinary prose, cut at spaces, with the overlap stepping back into
		// characters of every width.
		"prose": strings.Repeat("The founder’s “Series A” raised £2m in Zürich — naïve? ", 400),
	}
	for name, text := range cases {
		spans := ChunkRange(text, 0, int64(len(text)))
		if len(spans) < 2 {
			t.Fatalf("%s: want several chunks to exercise the boundaries, got %d", name, len(spans))
		}
		for i, s := range spans {
			if !utf8.ValidString(s.Text) {
				t.Fatalf("%s: chunk %d is not valid UTF-8 (starts % x)", name, i, s.Text[:min(4, len(s.Text))])
			}
			// Provenance anchors must point at character boundaries too, or a
			// citation opens the document in the middle of a character.
			for _, at := range []int64{s.Start, s.End} {
				if at < int64(len(text)) && !utf8.RuneStart(text[at]) {
					t.Fatalf("%s: chunk %d anchor %d is inside a character", name, i, at)
				}
			}
		}
	}
}

// A section range that arrives mid-character is snapped, not sliced as given.
func TestChunkRangeSnapsSectionBounds(t *testing.T) {
	text := "ab”cd" // the quote occupies bytes 2..4
	for _, s := range ChunkRange(text, 3, 5) {
		if !utf8.ValidString(s.Text) {
			t.Fatalf("chunk %q is not valid UTF-8", s.Text)
		}
	}
}

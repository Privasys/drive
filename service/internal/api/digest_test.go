package api

import (
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/store"
)

// TestGroundDigest: the digest is grounded, not generated — a model
// citation that is not in the resolved allow-list is stripped, allowed
// ones survive, and the frontmatter records the cited files.
func TestGroundDigest(t *testing.T) {
	s := &Server{}
	conv := &store.Node{ID: "conv-1", Name: "Model pricing review"}
	chips := []resolvedChip{
		{NodeID: "node-a", SectionID: "aa11", Name: "report.md"},
		{NodeID: "node-b", SectionID: "", Name: "notes.md"},
	}
	body := strings.Join([]string{
		"## Key facts",
		"The H100 rate is 7 GBP/hr [extracted](drive://node-a#aa11).",
		"A discount may apply (inferred).",
		"Something hallucinated [extracted](drive://node-z#dead99).",
		"Whole-file cite drive://node-b#.",
	}, "\n")

	got := s.groundDigest(conv, chips, body)

	if !strings.Contains(got, "drive://node-a#aa11") {
		t.Fatal("allowed section citation was dropped")
	}
	if !strings.Contains(got, "drive://node-b#") {
		t.Fatal("allowed whole-file citation was dropped")
	}
	if strings.Contains(got, "node-z") || strings.Contains(got, "dead99") {
		t.Fatalf("hallucinated citation survived:\n%s", got)
	}
	if !strings.Contains(got, "(unverified)") {
		t.Fatal("dropped citation was not marked unverified")
	}
	// Frontmatter records the conversation and both cited files.
	if !strings.HasPrefix(got, "---\n") || !strings.Contains(got, "conversation_id: conv-1") {
		t.Fatalf("frontmatter missing:\n%s", got)
	}
	if !strings.Contains(got, "node-a") || !strings.Contains(got, "node-b") {
		t.Fatalf("files frontmatter incomplete:\n%s", got)
	}
	// Inferred claims (no citation) are preserved verbatim.
	if !strings.Contains(got, "(inferred)") {
		t.Fatal("inferred claim mark was lost")
	}
}

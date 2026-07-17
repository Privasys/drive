package export

import (
	"strings"
	"testing"
)

// TestRewriteObsidianLinks: a drive:// citation to a node in the export
// gains a relative markdown link; an unknown target is left as-is; and
// [[wikilinks]] are untouched (Obsidian resolves them by name).
func TestRewriteObsidianLinks(t *testing.T) {
	pathByID := map[string]string{
		"node-a": "Memory/espresso-machine.md",
		"node-b": "Chat conversations/2026-07-17-review/digest.md",
	}
	body := []byte(strings.Join([]string{
		"See drive://node-a#aa11 for the machine.",
		"Digest at drive://node-b# has more.",
		"Unknown drive://node-z#dead stays raw.",
		"A [[wikilink]] is native.",
	}, "\n"))

	// From a memory file at Memory/coffee.md.
	got := string(rewriteObsidianLinks(body, "Memory/coffee.md", pathByID))

	if !strings.Contains(got, "drive://node-a#aa11 ([open](espresso-machine.md))") {
		t.Fatalf("relative link to sibling missing:\n%s", got)
	}
	if !strings.Contains(got, "([open](../Chat conversations/2026-07-17-review/digest.md))") {
		t.Fatalf("relative link across folders missing:\n%s", got)
	}
	if strings.Contains(got, "node-z") && strings.Contains(got, "[open]") && strings.Contains(got, "node-z#dead ([open]") {
		t.Fatalf("unknown target should not be rewritten:\n%s", got)
	}
	if !strings.Contains(got, "drive://node-z#dead stays raw") {
		t.Fatalf("unknown citation altered:\n%s", got)
	}
	if !strings.Contains(got, "[[wikilink]]") {
		t.Fatalf("wikilink was altered:\n%s", got)
	}
}

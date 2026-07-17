package search

import "testing"

func TestExtractLinks(t *testing.T) {
	text := `---
summary: notes
---
See the H100 rate [extracted](drive://node-a#aa11bb).
Related: [[coffee-preference]] and [[Espresso Note|the espresso one]].
Whole file: drive://node-b#.
Duplicate: drive://node-a#aa11bb and [[coffee-preference]] again.`

	links := ExtractLinks(text)

	var citations, wikilinks int
	seenTargets := map[string]bool{}
	for _, l := range links {
		seenTargets[l.Kind+":"+l.ToNode+l.ToName+l.ToSection] = true
		switch l.Kind {
		case "citation":
			citations++
		case "wikilink":
			wikilinks++
		}
	}
	// Two distinct citations (node-a#aa11bb, node-b#) and two distinct
	// wikilinks (coffee-preference, Espresso Note); duplicates collapse.
	if citations != 2 {
		t.Fatalf("citations = %d, want 2: %+v", citations, links)
	}
	if wikilinks != 2 {
		t.Fatalf("wikilinks = %d, want 2: %+v", wikilinks, links)
	}
	if !seenTargets["citation:node-aaa11bb"] {
		t.Fatalf("missing node-a citation: %+v", links)
	}
	if !seenTargets["wikilink:coffee-preference"] {
		t.Fatalf("missing coffee-preference wikilink: %+v", links)
	}
	// Piped wikilink uses the target, not the alias.
	if !seenTargets["wikilink:Espresso Note"] {
		t.Fatalf("piped wikilink target lost: %+v", links)
	}
}

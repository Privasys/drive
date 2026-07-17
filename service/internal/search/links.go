package search

import "regexp"

// Link extraction (§8.7). At index time the indexer pulls typed edges
// out of a file's markdown: digest citations (drive://<node>#<anchor>)
// and [[wikilinks]] between memory files. Containment is derived from
// the node tree, not extracted here. The store resolves wikilink names
// against Memory/ and persists the rows.

var (
	citationRe = regexp.MustCompile(`drive://([a-zA-Z0-9-]+)#([a-f0-9]*)`)
	wikilinkRe = regexp.MustCompile(`\[\[([^\]|]+)(?:\|[^\]]*)?\]\]`)
)

// ExtractLinks returns the outbound links found in a markdown document.
// Duplicate targets are collapsed. Wikilinks carry only ToName (the
// store resolves them); citations carry ToNode + ToSection.
func ExtractLinks(text string) []RawLink {
	var out []RawLink
	seen := map[string]bool{}
	for _, m := range citationRe.FindAllStringSubmatch(text, -1) {
		key := "c:" + m[1] + "#" + m[2]
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RawLink{Kind: "citation", ToNode: m[1], ToSection: m[2]})
	}
	for _, m := range wikilinkRe.FindAllStringSubmatch(text, -1) {
		name := m[1]
		key := "w:" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, RawLink{Kind: "wikilink", ToName: name})
	}
	return out
}

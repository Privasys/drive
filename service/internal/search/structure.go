package search

import (
	"path/filepath"
	"strings"
)

// Deterministic document structure (drive plan §8.2/§8.3): the section
// tree is built from what the format itself declares — markdown
// headings today, the DoclingDocument hierarchy when the conversion
// leg ships — never from LLM calls. Unstructured text falls back to
// size-based sections. Every section carries absolute char anchors so
// chunks, citations and read_section slices all point at the same
// bytes.

// sizeSection is the fallback section length for unstructured text.
const sizeSection = 6 * 1024

// BuildSections derives the section list for a document. Sections are
// returned in document order; ParentIdx references an earlier element
// (-1 = root). There is always at least one section covering the file.
func BuildSections(name, text string) []SectionSpec {
	if strings.TrimSpace(text) == "" {
		return []SectionSpec{{ParentIdx: -1, Title: baseTitle(name), Depth: 0, CharStart: 0, CharEnd: int64(len(text))}}
	}
	ext := strings.ToLower(filepath.Ext(name))
	if ext == ".md" || ext == ".markdown" {
		if secs := markdownSections(name, text); len(secs) > 1 {
			return secs
		}
	}
	return sizeSections(name, text)
}

func baseTitle(name string) string {
	return strings.TrimSuffix(filepath.Base(name), filepath.Ext(name))
}

// markdownSections parses ATX headings (#..######) into a tree. The
// document root spans the whole file; each heading opens a section
// running to the next heading of the same-or-shallower level.
func markdownSections(name, text string) []SectionSpec {
	type head struct {
		level int
		title string
		start int64 // offset of the heading line
	}
	var heads []head
	offset := int64(0)
	inFence := false
	for _, line := range strings.SplitAfter(text, "\n") {
		trimmed := strings.TrimRight(line, "\n")
		if strings.HasPrefix(strings.TrimSpace(trimmed), "```") {
			inFence = !inFence
		}
		if !inFence && strings.HasPrefix(trimmed, "#") {
			level := 0
			for level < len(trimmed) && trimmed[level] == '#' {
				level++
			}
			if level >= 1 && level <= 6 && level < len(trimmed) && trimmed[level] == ' ' {
				heads = append(heads, head{
					level: level,
					title: strings.TrimSpace(trimmed[level:]),
					start: offset,
				})
			}
		}
		offset += int64(len(line))
	}
	if len(heads) == 0 {
		return nil
	}

	secs := []SectionSpec{{ParentIdx: -1, Title: baseTitle(name), Depth: 0, CharStart: 0, CharEnd: int64(len(text))}}
	// Stack of (section index, heading level); the root is level 0.
	type frame struct {
		idx   int
		level int
	}
	stack := []frame{{idx: 0, level: 0}}
	for i, h := range heads {
		end := int64(len(text))
		// A section ends at the next heading of same-or-shallower level.
		for _, later := range heads[i+1:] {
			if later.level <= h.level {
				end = later.start
				break
			}
		}
		// Pop to the nearest shallower ancestor.
		for len(stack) > 1 && stack[len(stack)-1].level >= h.level {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1].idx
		secs = append(secs, SectionSpec{
			ParentIdx: parent,
			Title:     h.title,
			Depth:     len(stack),
			CharStart: h.start,
			CharEnd:   end,
		})
		stack = append(stack, frame{idx: len(secs) - 1, level: h.level})
	}
	return secs
}

// sizeSections splits unstructured text into flat, size-based sections
// under one root, breaking on paragraph boundaries where possible.
func sizeSections(name, text string) []SectionSpec {
	root := SectionSpec{ParentIdx: -1, Title: baseTitle(name), Depth: 0, CharStart: 0, CharEnd: int64(len(text))}
	if len(text) <= sizeSection {
		return []SectionSpec{root}
	}
	secs := []SectionSpec{root}
	part := 1
	for off := 0; off < len(text); {
		lim := off + sizeSection
		if lim >= len(text) {
			lim = len(text)
		} else if cut := strings.LastIndex(text[off:lim], "\n\n"); cut > sizeSection/2 {
			lim = off + cut
		}
		secs = append(secs, SectionSpec{
			ParentIdx: 0,
			Title:     "Part " + itoa(part),
			Depth:     1,
			CharStart: int64(off),
			CharEnd:   int64(lim),
		})
		part++
		off = lim
	}
	return secs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

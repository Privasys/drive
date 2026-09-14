// Package diff computes line differences between two revisions of a text
// file, inside the enclave.
//
// A user comparing two versions of their own document should not have to
// send either of them anywhere to do it: both revisions are already
// decryptable here and nowhere else, so the comparison happens here and
// only the result leaves. There is no dependency to add for this; the
// algorithm is Myers' greedy diff, which is what every other line differ
// is built on.
//
// The edit budget is bounded on purpose. Myers is fast when two revisions
// are similar, which is the case this exists for (a saved edit to a
// document), and slow when they share almost nothing, which is the case
// where a diff tells the reader nothing anyway. Past the budget the answer
// degrades honestly to "this was replaced" rather than burning the
// enclave's memory on a comparison nobody wants to read.
package diff

import (
	"fmt"
	"strings"
)

// Op is what happened to a line between the two revisions.
type Op byte

const (
	OpEqual  Op = ' '
	OpDelete Op = '-'
	OpInsert Op = '+'
)

// MarshalJSON writes the tag as the character it is (" ", "-", "+").
// Without this a byte would go out as a number, and every consumer that is
// not Go would read 45 where the API says "-".
func (o Op) MarshalJSON() ([]byte, error) {
	return []byte(`"` + string(rune(o)) + `"`), nil
}

// UnmarshalJSON accepts that same character.
func (o *Op) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if len(s) != 1 {
		return fmt.Errorf("diff: op %q is not a single character", string(b))
	}
	*o = Op(s[0])
	return nil
}

// Line is one line of the result, tagged with what happened to it.
type Line struct {
	Op   Op     `json:"op"`
	Text string `json:"text"`
}

// Hunk is a run of changed lines with its surrounding context, numbered
// the way a unified diff numbers them (1-based, counting lines).
type Hunk struct {
	OldStart int    `json:"old_start"`
	OldLines int    `json:"old_lines"`
	NewStart int    `json:"new_start"`
	NewLines int    `json:"new_lines"`
	Lines    []Line `json:"lines"`
}

// Result is a complete comparison.
type Result struct {
	Hunks []Hunk `json:"hunks"`
	// Truncated says the two revisions differ by more than the edit
	// budget, so the answer describes a wholesale replacement rather than
	// a line-by-line edit.
	Truncated bool `json:"truncated,omitempty"`
	// Identical says the two revisions hold the same text.
	Identical bool `json:"identical,omitempty"`
}

const (
	// maxEdits bounds the search. A document edit is a handful of changed
	// lines; hundreds mean a rewrite, which no reader reads line by line.
	maxEdits = 600
	// DefaultContext is how many unchanged lines frame each hunk.
	DefaultContext = 3
)

// Lines splits text into lines without keeping the terminators. A trailing
// newline does not add an empty final line, so a file and the same file
// with its last newline trimmed do not read as differing.
func Lines(text string) []string {
	if text == "" {
		return nil
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	return strings.Split(text, "\n")
}

// Unified compares two revisions and returns the hunks between them.
// context is how many unchanged lines to keep either side of a change.
func Unified(oldText, newText string, context int) Result {
	if context < 0 {
		context = 0
	}
	a, b := Lines(oldText), Lines(newText)
	if equalLines(a, b) {
		return Result{Identical: true}
	}
	script, ok := editScript(a, b)
	if !ok {
		// Past the budget: say so plainly rather than guess at an edit.
		return Result{Truncated: true, Hunks: wholesale(a, b)}
	}
	return Result{Hunks: group(script, context)}
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// wholesale is the answer when two revisions are too far apart to compare
// usefully: everything went, everything arrived.
func wholesale(a, b []string) []Hunk {
	h := Hunk{OldStart: 1, OldLines: len(a), NewStart: 1, NewLines: len(b)}
	if len(a) == 0 {
		h.OldStart = 0
	}
	if len(b) == 0 {
		h.NewStart = 0
	}
	for _, l := range a {
		h.Lines = append(h.Lines, Line{Op: OpDelete, Text: l})
	}
	for _, l := range b {
		h.Lines = append(h.Lines, Line{Op: OpInsert, Text: l})
	}
	return []Hunk{h}
}

// editScript runs Myers' greedy algorithm over the lines that actually
// differ (common head and tail are matched off first, which is most of a
// document when one paragraph changed). ok is false when the two revisions
// are further apart than the edit budget allows.
func editScript(a, b []string) ([]Line, bool) {
	// Match off the common head and tail: cheap, and it keeps the search
	// space to the part that changed.
	head := 0
	for head < len(a) && head < len(b) && a[head] == b[head] {
		head++
	}
	tail := 0
	for tail < len(a)-head && tail < len(b)-head &&
		a[len(a)-1-tail] == b[len(b)-1-tail] {
		tail++
	}
	midA, midB := a[head:len(a)-tail], b[head:len(b)-tail]

	middle, ok := myers(midA, midB)
	if !ok {
		return nil, false
	}
	out := make([]Line, 0, len(a)+len(b))
	for _, l := range a[:head] {
		out = append(out, Line{Op: OpEqual, Text: l})
	}
	out = append(out, middle...)
	for _, l := range a[len(a)-tail:] {
		out = append(out, Line{Op: OpEqual, Text: l})
	}
	return out, true
}

// myers walks the edit graph one edit distance at a time, keeping each
// step so the path can be retraced once the far corner is reached.
func myers(a, b []string) ([]Line, bool) {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil, true
	}
	max := n + m
	if max > maxEdits {
		max = maxEdits
	}
	offset := max
	v := make([]int, 2*max+2)
	trace := make([][]int, 0, max+1)

	for d := 0; d <= max; d++ {
		snapshot := make([]int, len(v))
		copy(snapshot, v)
		trace = append(trace, snapshot)
		for k := -d; k <= d; k += 2 {
			idx := k + offset
			if idx < 0 || idx+1 >= len(v) {
				continue
			}
			var x int
			// Take the step that reaches furthest: down when the diagonal
			// below is behind, right otherwise.
			if k == -d || (k != d && v[idx-1] < v[idx+1]) {
				x = v[idx+1]
			} else {
				x = v[idx-1] + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[idx] = x
			if x >= n && y >= m {
				return backtrack(a, b, trace, offset), true
			}
		}
	}
	return nil, false
}

// backtrack walks the saved steps from the end back to the start, turning
// the path into the edits it represents.
func backtrack(a, b []string, trace [][]int, offset int) []Line {
	x, y := len(a), len(b)
	var rev []Line
	for d := len(trace) - 1; d > 0; d-- {
		v := trace[d]
		k := x - y
		idx := k + offset
		var prevK int
		if k == -d || (k != d && idx-1 >= 0 && idx+1 < len(v) && v[idx-1] < v[idx+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevIdx := prevK + offset
		if prevIdx < 0 || prevIdx >= len(v) {
			break
		}
		prevX := v[prevIdx]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			x--
			y--
			rev = append(rev, Line{Op: OpEqual, Text: a[x]})
		}
		if d > 0 {
			if x > prevX {
				x--
				rev = append(rev, Line{Op: OpDelete, Text: a[x]})
			} else if y > prevY {
				y--
				rev = append(rev, Line{Op: OpInsert, Text: b[y]})
			}
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, Line{Op: OpEqual, Text: a[x]})
	}
	for x > 0 {
		x--
		rev = append(rev, Line{Op: OpDelete, Text: a[x]})
	}
	for y > 0 {
		y--
		rev = append(rev, Line{Op: OpInsert, Text: b[y]})
	}
	// Collected back to front.
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// group turns a flat edit script into hunks, dropping the long stretches
// of unchanged text between them and keeping `context` lines either side.
func group(script []Line, context int) []Hunk {
	var hunks []Hunk
	oldLine, newLine := 1, 1
	i := 0
	for i < len(script) {
		if script[i].Op == OpEqual {
			oldLine++
			newLine++
			i++
			continue
		}
		// A change starts here: reach back for context, then run forward
		// until `context` unchanged lines in a row close the hunk.
		start := i
		back := 0
		for start > 0 && script[start-1].Op == OpEqual && back < context {
			start--
			back++
		}
		hunkOld, hunkNew := oldLine-back, newLine-back
		if hunkOld < 1 {
			hunkOld = 1
		}
		if hunkNew < 1 {
			hunkNew = 1
		}
		end := i
		run := 0
		for end < len(script) && run <= context {
			if script[end].Op == OpEqual {
				run++
			} else {
				run = 0
			}
			end++
		}
		// Trim any context beyond the allowance at the tail.
		for end > i && run > context {
			end--
			run--
		}
		h := Hunk{OldStart: hunkOld, NewStart: hunkNew}
		for _, l := range script[start:end] {
			h.Lines = append(h.Lines, l)
			switch l.Op {
			case OpEqual:
				h.OldLines++
				h.NewLines++
			case OpDelete:
				h.OldLines++
			case OpInsert:
				h.NewLines++
			}
		}
		hunks = append(hunks, h)
		// Advance the counters past everything this hunk consumed.
		for _, l := range script[i:end] {
			switch l.Op {
			case OpEqual:
				oldLine++
				newLine++
			case OpDelete:
				oldLine++
			case OpInsert:
				newLine++
			}
		}
		i = end
	}
	return hunks
}

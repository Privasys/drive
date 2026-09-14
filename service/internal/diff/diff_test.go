package diff

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// applyScript reconstructs both sides from a single all-context hunk: the
// equal and delete lines must rebuild the old text, the equal and insert
// lines the new one. If the edit script is wrong in any way, one of the
// two will not match.
func applyScript(t *testing.T, oldText, newText string) {
	t.Helper()
	res := Unified(oldText, newText, 1<<30)
	if res.Identical {
		if oldText != newText && Lines(oldText) != nil {
			// Identical is only legitimate when the lines really match.
			if strings.Join(Lines(oldText), "\n") != strings.Join(Lines(newText), "\n") {
				t.Fatalf("claimed identical but differs:\n%q\n%q", oldText, newText)
			}
		}
		return
	}
	if res.Truncated {
		return // wholesale replacement, checked separately
	}
	var gotOld, gotNew []string
	for _, h := range res.Hunks {
		for _, l := range h.Lines {
			switch l.Op {
			case OpEqual:
				gotOld = append(gotOld, l.Text)
				gotNew = append(gotNew, l.Text)
			case OpDelete:
				gotOld = append(gotOld, l.Text)
			case OpInsert:
				gotNew = append(gotNew, l.Text)
			}
		}
	}
	wantOld, wantNew := Lines(oldText), Lines(newText)
	if strings.Join(gotOld, "\n") != strings.Join(wantOld, "\n") {
		t.Fatalf("script does not rebuild the old text:\n got %q\nwant %q", gotOld, wantOld)
	}
	if strings.Join(gotNew, "\n") != strings.Join(wantNew, "\n") {
		t.Fatalf("script does not rebuild the new text:\n got %q\nwant %q", gotNew, wantNew)
	}
}

func TestScriptRebuildsBothSides(t *testing.T) {
	cases := []struct{ name, a, b string }{
		{"insert in the middle", "a\nb\nc\n", "a\nb2\nb\nc\n"},
		{"delete in the middle", "a\nb\nc\nd\n", "a\nd\n"},
		{"change one line", "a\nb\nc\n", "a\nB\nc\n"},
		{"change the first line", "a\nb\nc\n", "A\nb\nc\n"},
		{"change the last line", "a\nb\nc\n", "a\nb\nC\n"},
		{"append at the end", "a\nb\n", "a\nb\nc\nd\n"},
		{"prepend at the start", "c\nd\n", "a\nb\nc\nd\n"},
		{"empty to content", "", "a\nb\n"},
		{"content to empty", "a\nb\n", ""},
		{"whole rewrite, small", "a\nb\nc\n", "x\ny\nz\n"},
		{"repeated lines", "a\na\na\nb\n", "a\na\nb\nb\n"},
		{"one line only", "hello", "hello world"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { applyScript(t, tc.a, tc.b) })
	}
	// Deterministic larger cases: a document with scattered edits.
	base := make([]string, 0, 200)
	for i := 0; i < 200; i++ {
		base = append(base, fmt.Sprintf("line %d of the document", i))
	}
	edited := append([]string(nil), base...)
	edited[7] = "line 7 rewritten"
	edited = append(edited[:40], append([]string{"inserted paragraph"}, edited[40:]...)...)
	edited = append(edited[:120], edited[123:]...)
	applyScript(t, strings.Join(base, "\n")+"\n", strings.Join(edited, "\n")+"\n")
}

func TestIdenticalAndNewlineHandling(t *testing.T) {
	if r := Unified("a\nb\n", "a\nb\n", 3); !r.Identical || len(r.Hunks) != 0 {
		t.Fatalf("identical: %+v", r)
	}
	// A trailing newline is a terminator, not an extra empty line, and
	// Windows line endings compare equal to Unix ones.
	if r := Unified("a\nb", "a\nb\n", 3); !r.Identical {
		t.Fatalf("trailing newline should not read as a change: %+v", r)
	}
	if r := Unified("a\r\nb\r\n", "a\nb\n", 3); !r.Identical {
		t.Fatalf("CRLF should not read as a change: %+v", r)
	}
}

func TestHunkNumbering(t *testing.T) {
	// One changed line in the middle of five, with one line of context.
	r := Unified("a\nb\nc\nd\ne\n", "a\nb\nC\nd\ne\n", 1)
	if r.Identical || len(r.Hunks) != 1 {
		t.Fatalf("want one hunk: %+v", r)
	}
	h := r.Hunks[0]
	// Context line 2, the change at 3, context line 4.
	if h.OldStart != 2 || h.NewStart != 2 || h.OldLines != 3 || h.NewLines != 3 {
		t.Fatalf("hunk header: %+v", h)
	}
	var ops string
	for _, l := range h.Lines {
		ops += string(l.Op)
	}
	if ops != " -+ " && ops != " +- " {
		t.Fatalf("hunk ops %q: %+v", ops, h.Lines)
	}
}

func TestDistantChangesGiveSeparateHunks(t *testing.T) {
	var a, b []string
	for i := 0; i < 60; i++ {
		a = append(a, fmt.Sprintf("l%d", i))
	}
	b = append(b, a...)
	b[2] = "changed early"
	b[50] = "changed late"
	r := Unified(strings.Join(a, "\n"), strings.Join(b, "\n"), 2)
	if len(r.Hunks) != 2 {
		t.Fatalf("two distant changes should give two hunks, got %d", len(r.Hunks))
	}
	if r.Hunks[0].OldStart > r.Hunks[1].OldStart {
		t.Fatalf("hunks out of order: %+v", r.Hunks)
	}
	// Context must not swallow the whole file.
	total := len(r.Hunks[0].Lines) + len(r.Hunks[1].Lines)
	if total > 20 {
		t.Fatalf("hunks carry too much context: %d lines", total)
	}
}

func TestBeyondTheEditBudgetDegradesHonestly(t *testing.T) {
	var a, b []string
	for i := 0; i < 2000; i++ {
		a = append(a, fmt.Sprintf("old %d", i))
		b = append(b, fmt.Sprintf("new %d", i))
	}
	r := Unified(strings.Join(a, "\n"), strings.Join(b, "\n"), 3)
	if !r.Truncated || len(r.Hunks) != 1 {
		t.Fatalf("a wholesale rewrite should say so: truncated=%v hunks=%d", r.Truncated, len(r.Hunks))
	}
	h := r.Hunks[0]
	if h.OldLines != 2000 || h.NewLines != 2000 {
		t.Fatalf("wholesale hunk should cover both sides: %+v", struct{ O, N int }{h.OldLines, h.NewLines})
	}
}

// A hunk exists because something changed in it. One containing nothing but
// context would render as a list of unchanged lines under a heading saying
// nothing changed, which tells the reader the view is broken.
func TestEveryHunkContainsAChange(t *testing.T) {
	cases := [][2]string{
		{"a\nb\nc\n", "a\nB\nc\n"},
		{"a\nb\nc\nd\ne\nf\ng\n", "a\nb\nc\nd\ne\nf\nG\n"},
		{"a\nb\nc\nd\ne\nf\ng\n", "A\nb\nc\nd\ne\nf\ng\n"},
		{"1\n2\n3\n4\n5\n", "1\n2\n3\n4\n5\n6\n"},
		{"1\n2\n3\n4\n5\n6\n", "1\n2\n3\n4\n5\n"},
		{strings.Repeat("x\n", 40) + "tail\n", strings.Repeat("x\n", 40) + "TAIL\n"},
		{"head\n" + strings.Repeat("y\n", 40), "HEAD\n" + strings.Repeat("y\n", 40)},
	}
	for _, ctx := range []int{0, 1, 3, 10} {
		for i, tc := range cases {
			res := Unified(tc[0], tc[1], ctx)
			if res.Identical {
				t.Fatalf("case %d ctx %d: reported identical", i, ctx)
			}
			for h, hunk := range res.Hunks {
				changed := false
				for _, l := range hunk.Lines {
					if l.Op != OpEqual {
						changed = true
						break
					}
				}
				if !changed {
					t.Fatalf("case %d ctx %d: hunk %d has only context: %+v", i, ctx, h, hunk)
				}
			}
		}
	}
}

// The API documents each line as tagged " ", "-" or "+". Op is a byte, and
// a byte marshals as a NUMBER, so without this the wire carries 45 where
// every client is told to expect "-". Go decodes its own number back into a
// byte happily, which is why only a non-Go reader ever sees the difference.
func TestOpMarshalsAsTheCharacterTheAPIDocuments(t *testing.T) {
	b, err := json.Marshal(Line{Op: OpDelete, Text: "gone"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"op":"-"`) {
		t.Fatalf(`want "op":"-" on the wire, got %s`, b)
	}
	for _, op := range []Op{OpEqual, OpDelete, OpInsert} {
		raw, err := json.Marshal(Line{Op: op})
		if err != nil {
			t.Fatal(err)
		}
		var back Line
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("round trip %q: %v", string(op), err)
		}
		if back.Op != op {
			t.Fatalf("round trip %q gave %q", string(op), string(back.Op))
		}
	}
}

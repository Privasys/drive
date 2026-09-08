package search

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeSummariser struct {
	calls []string
	fail  bool
}

func (f *fakeSummariser) Model() string { return "fake-chat/" + SummaryPromptVersion }

func (f *fakeSummariser) Summarise(_ context.Context, title, text string) (string, error) {
	f.calls = append(f.calls, title)
	if f.fail {
		return "", errors.New("fleet down")
	}
	if strings.Contains(text, "Section summaries:") {
		return "Doc about " + title, nil
	}
	return "Summary of " + title, nil
}

func summaryFixture() string {
	body := strings.Repeat("Some prose about the topic that runs long enough to be summarised. ", 8)
	return "# Guide\n\nIntro line.\n\n## Setup\n\n" + body + "\n\n## Usage\n\n" + body + "\n\n## Tiny\n\nshort.\n"
}

// TestIndexerSummarisesSectionsWhenEnabled: with the policy on, every
// section long enough gets a summary, the root gets a description built
// from its head plus the child summaries, and the model is recorded.
func TestIndexerSummarisesSectionsWhenEnabled(t *testing.T) {
	ops := newFakeOps()
	sm := &fakeSummariser{}
	ix := &Indexer{
		Ops:               ops,
		Content:           contentOf(summaryFixture()),
		Embedder:          func() Embedder { return LocalEmbedder{} },
		Summariser:        func() Summariser { return sm },
		SummariseOnIngest: func() bool { return true },
		Sync:              true,
	}
	ix.Enqueue("t", "n-md", "guide.md", "text/markdown")
	if ops.status["n-md"] != statusIndexed {
		t.Fatalf("status = %q", ops.status["n-md"])
	}
	// The markdown tree: root "guide" (the file) > "Guide" (H1) > Setup,
	// Usage, Tiny. Everything long enough is summarised; the root is
	// described from its head plus the child summaries.
	sums := ops.summaries["n-md"]
	if len(sums) != 4 {
		t.Fatalf("summaries = %v (calls %v)", sums, sm.calls)
	}
	secs := ops.secs["n-md"]
	for i, sec := range secs {
		id := int64(i + 1)
		switch sec.Title {
		case "guide":
			if sums[id] != "Doc about guide" {
				t.Fatalf("root description = %q", sums[id])
			}
		case "Guide", "Setup", "Usage":
			if sums[id] != "Summary of "+sec.Title {
				t.Fatalf("%s summary = %q", sec.Title, sums[id])
			}
		case "Tiny":
			if _, ok := sums[id]; ok {
				t.Fatalf("a section under the minimum length must stay title-only")
			}
		default:
			t.Fatalf("unexpected section %q", sec.Title)
		}
	}
	if ops.summaryModel["n-md"] != "fake-chat/"+SummaryPromptVersion {
		t.Fatalf("model = %q", ops.summaryModel["n-md"])
	}
	// Children are summarised before the root.
	if sm.calls[len(sm.calls)-1] != "guide" {
		t.Fatalf("root must be described last: %v", sm.calls)
	}
}

// TestIndexerSummariesRespectPolicyAndOptOut: the attested flag off, or a
// no_summaries folder above the file, means no plaintext goes to the
// fleet for summaries; indexing itself is unaffected.
func TestIndexerSummariesRespectPolicyAndOptOut(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy bool
		optOut bool
	}{
		{"policy off", false, false},
		{"folder opted out", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ops := newFakeOps()
			ops.summariesOff["n-md"] = tc.optOut
			sm := &fakeSummariser{}
			ix := &Indexer{
				Ops:               ops,
				Content:           contentOf(summaryFixture()),
				Embedder:          func() Embedder { return LocalEmbedder{} },
				Summariser:        func() Summariser { return sm },
				SummariseOnIngest: func() bool { return tc.policy },
				Sync:              true,
			}
			ix.Enqueue("t", "n-md", "guide.md", "text/markdown")
			if ops.status["n-md"] != statusIndexed {
				t.Fatalf("status = %q", ops.status["n-md"])
			}
			if len(sm.calls) != 0 || len(ops.summaries["n-md"]) != 0 {
				t.Fatalf("no summary call expected: calls=%v stored=%v", sm.calls, ops.summaries["n-md"])
			}
		})
	}
}

// TestIndexerSummaryFailureKeepsIndex: a fleet error mid-way stores what
// was produced and leaves the file indexed.
func TestIndexerSummaryFailureKeepsIndex(t *testing.T) {
	ops := newFakeOps()
	sm := &fakeSummariser{fail: true}
	ix := &Indexer{
		Ops:               ops,
		Content:           contentOf(summaryFixture()),
		Embedder:          func() Embedder { return LocalEmbedder{} },
		Summariser:        func() Summariser { return sm },
		SummariseOnIngest: func() bool { return true },
		Sync:              true,
	}
	ix.Enqueue("t", "n-md", "guide.md", "text/markdown")
	if ops.status["n-md"] != statusIndexed {
		t.Fatalf("status = %q", ops.status["n-md"])
	}
	if len(sm.calls) != 1 {
		t.Fatalf("the leg must stop at the first failure, calls=%v", sm.calls)
	}
}

func TestCleanSummary(t *testing.T) {
	in := "<think>\nreasoning\n</think>\n\n\"A summary\n  across lines.\""
	if got := cleanSummary(in); got != "A summary across lines." {
		t.Fatalf("cleanSummary = %q", got)
	}
}

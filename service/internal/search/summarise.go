package search

import (
	"context"
	"fmt"
	"log"
	"strings"
)

// Section summaries and document descriptions (drive plan §8.5): one
// fleet chat call per section produces the one-line summary a tree
// navigator (get_doc_tree, get_folder_tree) shows beside each title, and
// the root section's summary doubles as the file's description.
//
// Summaries send file plaintext to the fleet at INGESTION time, not only
// at query time, so they are governed by the attested instance policy
// (`summarise_on_ingest`) with a per-folder opt-out (`no_summaries`,
// inherited down the tree like `no_index`). Off means the tree still
// exists; only the summaries are absent.

// SummaryPromptVersion is the versioned, image-baked prompt identity
// recorded on every section (`summary_model`), so a prompt change is a
// measured release and old summaries are distinguishable from new ones.
const SummaryPromptVersion = "summary_prompt/v1"

const (
	summarySystemPrompt = "You write one- or two-sentence summaries of sections of a document, for a table of contents. Write in the language of the text. State what the section covers and its key facts or conclusions. Return only the summary, with no preamble and no quotation marks."
	// maxSummarySections bounds the fleet calls one file can cost.
	maxSummarySections = 48
	// maxSummaryChars bounds the plaintext sent per section.
	maxSummaryChars = 6000
	// minSummaryChars: shorter sections are title-only in the tree.
	minSummaryChars = 200
	// rootHeadChars of the document head are sent with the child
	// summaries when describing the whole file.
	rootHeadChars    = 3000
	summaryMaxTokens = 160
)

// Summariser produces a one-line summary for a section's text.
type Summariser interface {
	Summarise(ctx context.Context, title, text string) (string, error)
	// Model identifies what produced the summary (recorded per section).
	Model() string
}

// FleetSummariser summarises through the pinned fleet chat model.
type FleetSummariser struct {
	Chat *FleetChat
}

func (f *FleetSummariser) Model() string {
	return f.Chat.Model + "/" + SummaryPromptVersion
}

func (f *FleetSummariser) Summarise(ctx context.Context, title, text string) (string, error) {
	out, err := f.Chat.Complete(ctx, []ChatMessage{
		{Role: "system", Content: summarySystemPrompt},
		{Role: "user", Content: fmt.Sprintf("Section title: %s\n\n%s", title, text)},
	}, summaryMaxTokens)
	if err != nil {
		return "", err
	}
	return cleanSummary(out), nil
}

// cleanSummary strips reasoning wrappers and surrounding quotes a chat
// model may add, and collapses the reply to one line.
func cleanSummary(s string) string {
	if i := strings.LastIndex(s, "</think>"); i >= 0 {
		s = s[i+len("</think>"):]
	}
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"'“”")
	return strings.Join(strings.Fields(s), " ")
}

// summarise runs the §8.5 summary leg for a freshly indexed file. Best
// effort by design: a fleet outage leaves sections without summaries
// (the next reindex fills them); it never changes the index status.
func (ix *Indexer) summarise(ctx context.Context, j job, text string, secs []SectionSpec, ids []int64) {
	if ix.SummariseOnIngest == nil || !ix.SummariseOnIngest() || ix.Summariser == nil {
		return
	}
	sm := ix.Summariser()
	if sm == nil || len(secs) == 0 || len(ids) != len(secs) {
		return
	}
	if off, err := ix.Ops.HasNoSummariseAncestor(ctx, j.tenantID, j.nodeID); err != nil || off {
		return
	}
	slice := func(start, end int64) string {
		if start < 0 {
			start = 0
		}
		if end > int64(len(text)) {
			end = int64(len(text))
		}
		if start >= end {
			return ""
		}
		return text[start:end]
	}
	out := map[int64]string{}
	calls := 0
	failed := false
	var childSummaries []string
	// Children first (document order), roots last so a root can be
	// described from its head plus what its sections turned out to say.
	// The first fleet error ends the leg: what was produced is kept, the
	// rest waits for the next reindex.
	for i, sec := range secs {
		if sec.ParentIdx < 0 {
			continue
		}
		if calls >= maxSummarySections {
			break
		}
		body := strings.TrimSpace(slice(sec.CharStart, sec.CharEnd))
		if len(body) < minSummaryChars {
			continue
		}
		if len(body) > maxSummaryChars {
			body = body[:maxSummaryChars]
		}
		calls++
		sum, err := sm.Summarise(ctx, sec.Title, body)
		if err != nil {
			log.Printf("search: summarise %s section %d: %v", j.nodeID, i, err)
			failed = true
			break
		}
		if sum == "" {
			continue
		}
		out[ids[i]] = sum
		childSummaries = append(childSummaries, sec.Title+": "+sum)
	}
	for i, sec := range secs {
		if sec.ParentIdx >= 0 || failed {
			continue
		}
		body := strings.TrimSpace(slice(sec.CharStart, sec.CharEnd))
		if len(body) < minSummaryChars && len(childSummaries) == 0 {
			continue
		}
		if len(body) > rootHeadChars {
			body = body[:rootHeadChars]
		}
		if len(childSummaries) > 0 {
			body += "\n\nSection summaries:\n- " + strings.Join(childSummaries, "\n- ")
			if len(body) > maxSummaryChars {
				body = body[:maxSummaryChars]
			}
		}
		sum, err := sm.Summarise(ctx, sec.Title, body)
		if err != nil {
			log.Printf("search: describe %s: %v", j.nodeID, err)
			break
		}
		if sum != "" {
			out[ids[i]] = sum
		}
	}
	if len(out) == 0 {
		return
	}
	if err := ix.Ops.SetSectionSummaries(ctx, j.tenantID, j.nodeID, out, sm.Model()); err != nil {
		log.Printf("search: store summaries %s: %v", j.nodeID, err)
	}
}

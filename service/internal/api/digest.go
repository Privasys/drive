package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// driveLinkRe matches a drive:// provenance citation with a hex anchor.
var driveLinkRe = regexp.MustCompile(`drive://[a-zA-Z0-9-]+#[a-f0-9]*`)

// finalize_conversation (§8.7). On "mark complete" the chat calls this;
// Drive generates digest.md via its pinned fleet dependency, so every
// plaintext-to-fleet flow stays inside Drive's attested boundary and
// disclosure (§8.6). The digest is a hand-authored PageIndex root node:
//
//   - Grounded, not generated: the prompt may cite only the provenance
//     chips actually accumulated in the conversation. Every chip is
//     resolved HERE at write time and dead ones are dropped; a digest
//     with hallucinated links is worse than none.
//   - Citations use the retrieval provenance schema on stable anchors
//     (§8.3): drive://<node_id>#<section-anchor>.
//   - Claim provenance marks: a claim carries a citation (extracted),
//     or is marked *inferred* (synthesis), and contradictions are
//     marked *ambiguous* and preserved. The prompt instructs this; the
//     model produces it.
//
// Re-completing regenerates digest.md in place.

// provChip is one accumulated citation the caller vouches was used.
type provChip struct {
	NodeID    string `json:"node_id"`
	SectionID string `json:"section_id"` // stable anchor ("" = whole file)
}

// resolvedChip is a chip that resolved to live content, with its label.
type resolvedChip struct {
	NodeID    string
	SectionID string
	Name      string
	Title     string
	Path      []string
}

func (s *Server) handleFinalizeConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	convID := r.PathValue("convID")
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req struct {
		Provenance []provChip `json:"provenance"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	chat := s.activeChat()
	if chat == nil {
		httpError(w, http.StatusNotImplemented, errors.New("digest generation unavailable (no chat model configured)"))
		return
	}
	conv, err := s.Store.GetNode(r.Context(), tenantID, convID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	doc := s.conversationDocOf(r.Context(), tenantID, conv)
	if doc.TranscriptID == "" {
		httpError(w, http.StatusBadRequest, errors.New("conversation has no transcript"))
		return
	}
	transcript, err := s.readNodeBytes(r.Context(), tenantID, doc.TranscriptID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if len(bytes.TrimSpace(transcript)) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("transcript is empty"))
		return
	}

	// Resolve every provenance chip to live content; drop dead ones.
	resolved := s.resolveChips(r.Context(), tenantID, req.Provenance)

	prompt := buildDigestPrompt(conv.Name, string(transcript), resolved)
	body, gerr := chat.Complete(r.Context(), prompt, 2048)
	if gerr != nil {
		httpError(w, http.StatusBadGateway, fmt.Errorf("digest generation failed: %w", gerr))
		return
	}
	// Validate the model's citations against the resolved allow-list;
	// rewrite any drive:// link that is not a resolved chip out of the
	// digest (grounded, not generated).
	digest := s.groundDigest(conv, resolved, body)

	// Write (or regenerate in place) digest.md, indexed.
	dg, gerr2 := s.Store.ChildByName(r.Context(), tenantID, conv.ID, digestName)
	if gerr2 == nil {
		if _, status, err := s.overwriteFile(r.Context(), p, tenantID, dg.ID, []byte(digest)); err != nil {
			httpError(w, status, err)
			return
		}
		s.extractAndStoreLinks(r.Context(), tenantID, dg.ID, digest)
		writeJSON(w, http.StatusOK, map[string]any{
			"digest_id": dg.ID, "regenerated": true, "cited": len(resolved),
		})
		return
	}
	n, status, err := s.uploadFile(r.Context(), p, tenantID, conv.ID, digestName, "text/markdown",
		bytes.NewReader([]byte(digest)), false /* index the digest */)
	if err != nil {
		httpError(w, status, err)
		return
	}
	s.extractAndStoreLinks(r.Context(), tenantID, n.ID, digest)
	writeJSON(w, http.StatusCreated, map[string]any{
		"digest_id": n.ID, "regenerated": false, "cited": len(resolved),
	})
}

// resolveChips resolves each chip to live content (node + optional
// section anchor), deduped, dropping any that no longer exist.
func (s *Server) resolveChips(ctx context.Context, tenantID string, chips []provChip) []resolvedChip {
	seen := map[string]bool{}
	var out []resolvedChip
	for _, c := range chips {
		if c.NodeID == "" {
			continue
		}
		key := c.NodeID + "#" + c.SectionID
		if seen[key] {
			continue
		}
		n, err := s.Store.GetNode(ctx, tenantID, c.NodeID)
		if err != nil {
			continue
		}
		rc := resolvedChip{NodeID: c.NodeID, SectionID: c.SectionID, Name: n.Name}
		if c.SectionID != "" {
			sec, serr := s.Store.GetSectionByAnchor(ctx, tenantID, c.NodeID, c.SectionID)
			if serr != nil {
				continue // dead anchor: drop
			}
			rc.Title = sec.Title
			rc.Path = sectionPathOf(ctx, s.Store, tenantID, c.NodeID, sec.ID)
		}
		seen[key] = true
		out = append(out, rc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// buildDigestPrompt assembles the grounded digest prompt.
func buildDigestPrompt(title, transcript string, chips []resolvedChip) []search.ChatMessage {
	var sources strings.Builder
	for _, c := range chips {
		label := c.Name
		if len(c.Path) > 0 {
			label += " › " + strings.Join(c.Path, " › ")
		}
		fmt.Fprintf(&sources, "- drive://%s#%s  (%s)\n", c.NodeID, c.SectionID, label)
	}
	if sources.Len() == 0 {
		sources.WriteString("(no sources were cited during this conversation)\n")
	}
	system := strings.Join([]string{
		"You distil a chat conversation into a Markdown digest for a knowledge base.",
		"Compose EXACTLY these sections as level-2 headings: Context, Decisions, Key facts, Outcomes, Open questions, Files & sources.",
		"Grounding rules, strictly:",
		"1. You may cite ONLY the sources listed below, verbatim, as drive://<node>#<anchor>. Never invent a link.",
		"2. Mark every substantive claim: end it with [extracted](drive://...) when it comes from a cited source; with (inferred) when it is your synthesis over the conversation; with (ambiguous) when sources conflict — preserve BOTH sides, do not resolve.",
		"3. Prefer extracted over inferred. If nothing supports a claim, drop it.",
		"Be concise and factual. Output only the Markdown digest, no preamble.",
	}, "\n")
	user := fmt.Sprintf("Conversation title: %s\n\nAvailable sources (cite only these):\n%s\nTranscript (JSONL, one turn per line):\n%s",
		title, sources.String(), transcript)
	return []search.ChatMessage{
		{Role: "system", Content: system},
		{Role: "user", Content: user},
	}
}

// groundDigest prepends deterministic frontmatter and strips any
// drive:// citation the model emitted that is not in the resolved
// allow-list (grounded, not generated). Frontmatter records the
// conversation id, completion date and cited file node ids.
func (s *Server) groundDigest(conv *store.Node, chips []resolvedChip, body string) string {
	allowed := map[string]bool{}
	fileSet := map[string]bool{}
	for _, c := range chips {
		allowed["drive://"+c.NodeID+"#"+c.SectionID] = true
		fileSet[c.NodeID] = true
	}
	body = driveLinkRe.ReplaceAllStringFunc(body, func(m string) string {
		if allowed[m] {
			return m
		}
		// Unknown citation: keep the surrounding text, drop the dead link.
		return "(unverified)"
	})
	files := make([]string, 0, len(fileSet))
	for id := range fileSet {
		files = append(files, id)
	}
	sort.Strings(files)
	var fm strings.Builder
	fm.WriteString("---\n")
	fmt.Fprintf(&fm, "conversation_id: %s\n", conv.ID)
	fmt.Fprintf(&fm, "summary: Digest of %q\n", conv.Name)
	if len(files) > 0 {
		fmt.Fprintf(&fm, "files: [%s]\n", strings.Join(files, ", "))
	}
	fm.WriteString("---\n\n")
	return fm.String() + strings.TrimRight(body, "\n") + "\n"
}

// sectionPathOf resolves a section's title path via ListSections.
func sectionPathOf(ctx context.Context, st *store.Store, tenantID, nodeID string, sectionID int64) []string {
	byID := sectionPaths(ctx, st, tenantID, nodeID)
	return byID[sectionID]
}

func (s *Server) toolFinalizeConversation(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID       string     `json:"tenant_id"`
		ConversationID string     `json:"conversation_id"`
		Provenance     []provChip `json:"provenance"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p,
		map[string]string{"tenantID": req.TenantID, "convID": req.ConversationID},
		map[string]any{"provenance": req.Provenance}, s.handleFinalizeConversation)
}

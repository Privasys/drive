package api

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/store"
)

// Memory/ (§8.7): the assistant's standing facts, always in AI scope.
// Memory's failure mode is unlike documents' — a retrieval miss on a
// standing preference means the assistant silently violates it, and it
// cannot search for a fact it does not know exists. So memory needs
// guaranteed ENUMERATION: get_memory inlines the whole folder under a
// size budget, else the memory TREE (title + one-line summary per file)
// with lazy drill-down. Search may supplement; the inlined index is the
// guarantee and search-only memory is forbidden.
//
// Convention: one fact per file, kebab-case names, an authored
// frontmatter `summary:` (the writer knows the hook). write_memory
// enforces merge hygiene — it surfaces overlapping memories so the
// caller updates in place rather than duplicating.

const memoryRoot = "Memory"

// memoryBudgetBytes is the inline size budget: under it, get_memory
// returns whole bodies; over it, the tree only.
const memoryBudgetBytes = 24 * 1024

// ensureMemoryFolder returns the tenant's top-level Memory/ folder,
// creating it on first use.
func (s *Server) ensureMemoryFolder(ctx context.Context, p *Principal, tenantID string) (*store.Node, error) {
	return s.ensureFolderByName(ctx, p, tenantID, "", memoryRoot)
}

type memoryFile struct {
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	Summary   string `json:"summary,omitempty"`
	Body      string `json:"body,omitempty"` // present only when inlined whole
	UpdatedAt string `json:"updated_at,omitempty"`
}

// handleGetMemory returns memory tiered for inlining at conversation
// start: mode "full" (bodies included) under the budget, else mode
// "tree" (titles + summaries only). Never search-only.
func (s *Server) handleGetMemory(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	// Memory/ is always in the assistant's scope (§8.7), so the assistant
	// enclave may read it on behalf of the user.
	if !(p.IsUser() || p.IsAssistant()) || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	root, err := s.Store.ChildByName(r.Context(), tenantID, "", memoryRoot)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, map[string]any{"mode": "full", "memories": []memoryFile{}})
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	kids, err := s.Store.ListChildren(r.Context(), tenantID, root.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	var total int64
	files := make([]*store.Node, 0, len(kids))
	for _, n := range kids {
		if n.Kind == store.NodeFile {
			files = append(files, n)
			total += n.PlainSize
		}
	}
	full := total <= memoryBudgetBytes
	out := make([]memoryFile, 0, len(files))
	for _, n := range files {
		m := memoryFile{NodeID: n.ID, Name: n.Name, UpdatedAt: n.UpdatedAt.UTC().Format(time.RFC3339)}
		body, _ := s.readNodeBytes(r.Context(), tenantID, n.ID)
		m.Summary = frontmatterSummary(body)
		if m.Summary == "" {
			m.Summary = leadingProse(body)
		}
		if full {
			m.Body = string(body)
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	mode := "tree"
	if full {
		mode = "full"
	}
	writeJSON(w, http.StatusOK, map[string]any{"mode": mode, "budget_bytes": memoryBudgetBytes, "memories": out})
}

// handleWriteMemory writes (or overwrites) a memory file, enforcing the
// one-fact-per-file + authored-summary convention and merge hygiene: it
// returns any existing memories whose summary overlaps, so the caller
// updates in place rather than duplicating. An assistant write raises a
// wallet notification (§7.6 rail). overwrite=false + an existing name is
// a conflict unless the caller opts into replacing it.
func (s *Server) handleWriteMemory(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canWrite(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	var req struct {
		Name      string `json:"name"`    // kebab-case, one fact
		Summary   string `json:"summary"` // authored hook
		Body      string `json:"body"`    // markdown body (may include [[wikilinks]])
		Overwrite bool   `json:"overwrite"`
		// ByAssistant marks an assistant-authored write, so the tenant's
		// wallet is notified (transparency for AI writes to memory).
		ByAssistant bool `json:"by_assistant"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	name := memoryFileName(req.Name)
	if name == "" || strings.TrimSpace(req.Body) == "" {
		httpError(w, http.StatusBadRequest, errors.New("name and body are required"))
		return
	}
	root, err := s.ensureMemoryFolder(r.Context(), p, tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	// Merge-hygiene: surface overlapping memories (by shared summary
	// words) so the caller updates rather than duplicates.
	overlaps := s.memoryOverlaps(r.Context(), tenantID, root.ID, name, req.Summary)

	content := composeMemory(req.Summary, req.Body)
	existing, gerr := s.Store.ChildByName(r.Context(), tenantID, root.ID, name)
	switch {
	case gerr == nil:
		if !req.Overwrite {
			writeJSON(w, http.StatusConflict, map[string]any{
				"error":   "a memory with this name exists; set overwrite to replace it",
				"node_id": existing.ID, "overlaps": overlaps,
			})
			return
		}
		if _, status, err := s.overwriteFile(r.Context(), p, tenantID, existing.ID, []byte(content)); err != nil {
			httpError(w, status, err)
			return
		}
		s.extractAndStoreLinks(r.Context(), tenantID, existing.ID, content)
		s.notifyMemoryWrite(p, tenantID, name, req.ByAssistant, "updated")
		writeJSON(w, http.StatusOK, map[string]any{"node_id": existing.ID, "name": name, "overlaps": overlaps})
	case errors.Is(gerr, store.ErrNotFound):
		n, status, err := s.uploadFile(r.Context(), p, tenantID, root.ID, name, "text/markdown",
			bytes.NewReader([]byte(content)), false /* index memory */)
		if err != nil {
			httpError(w, status, err)
			return
		}
		s.extractAndStoreLinks(r.Context(), tenantID, n.ID, content)
		s.notifyMemoryWrite(p, tenantID, name, req.ByAssistant, "created")
		writeJSON(w, http.StatusCreated, map[string]any{"node_id": n.ID, "name": name, "overlaps": overlaps})
	default:
		httpError(w, http.StatusInternalServerError, gerr)
	}
}

// notifyMemoryWrite raises a §7.6 wallet notification for an
// assistant-authored memory write (transparency). User edits do not
// notify (the user is the actor).
func (s *Server) notifyMemoryWrite(p *Principal, tenantID, name string, byAssistant bool, verb string) {
	if !byAssistant {
		return
	}
	s.Notifier().Fire(p.Sub, "memory-write", map[string]any{
		"tenant_id": tenantID, "memory": name, "action": verb,
	})
}

// memoryOverlaps returns existing memory names whose summary shares
// significant words with the incoming one — the merge-hygiene signal.
func (s *Server) memoryOverlaps(ctx context.Context, tenantID, rootID, name, summary string) []string {
	want := significantWords(summary)
	if len(want) == 0 {
		return nil
	}
	kids, err := s.Store.ListChildren(ctx, tenantID, rootID)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range kids {
		if n.Kind != store.NodeFile || n.Name == name {
			continue
		}
		body, _ := s.readNodeBytes(ctx, tenantID, n.ID)
		have := significantWords(frontmatterSummary(body) + " " + n.Name)
		if overlapCount(want, have) >= 2 {
			out = append(out, n.Name)
		}
	}
	return out
}

// composeMemory renders the memory file: frontmatter summary + body.
func composeMemory(summary, body string) string {
	var b strings.Builder
	if strings.TrimSpace(summary) != "" {
		b.WriteString("---\nsummary: ")
		b.WriteString(strings.ReplaceAll(strings.TrimSpace(summary), "\n", " "))
		b.WriteString("\n---\n\n")
	}
	b.WriteString(strings.TrimRight(body, "\n"))
	b.WriteString("\n")
	return b.String()
}

// memoryFileName normalises a memory name to kebab-case with a .md
// suffix (one fact per file convention).
func memoryFileName(raw string) string {
	s := slugify(strings.TrimSuffix(strings.ToLower(raw), ".md"))
	if s == "" || s == "conversation" {
		return ""
	}
	return s + ".md"
}

var memoryStopwords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true, "of": true,
	"to": true, "in": true, "is": true, "are": true, "for": true, "on": true,
	"with": true, "user": true, "prefers": true, "memory": true,
}

func significantWords(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	}) {
		if len(w) >= 3 && !memoryStopwords[w] {
			out[w] = true
		}
	}
	return out
}

func overlapCount(a, b map[string]bool) int {
	n := 0
	for w := range a {
		if b[w] {
			n++
		}
	}
	return n
}

// --- Manifest tools -------------------------------------------------------

func (s *Server) toolGetMemory(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	s.handleGetMemory(w, r2, p)
}

func (s *Server) toolWriteMemory(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID    string `json:"tenant_id"`
		Name        string `json:"name"`
		Summary     string `json:"summary"`
		Body        string `json:"body"`
		Overwrite   bool   `json:"overwrite"`
		ByAssistant bool   `json:"by_assistant"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	delegateWithBody(w, r, p, map[string]string{"tenantID": req.TenantID},
		map[string]any{
			"name": req.Name, "summary": req.Summary, "body": req.Body,
			"overwrite": req.Overwrite, "by_assistant": req.ByAssistant,
		}, s.handleWriteMemory)
}

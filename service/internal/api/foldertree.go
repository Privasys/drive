package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/store"
)

// get_folder_tree (§8.7): get_doc_tree generalised one level up —
// folder → files → per-file description → section titles/anchors. It
// derives the corpus-level table of contents on demand from the index
// (no maintained index file to go stale) and is what makes the Memory
// tree and the "what do we know from past conversations" ToC work:
// guaranteed ENUMERATION, which search cannot give.
//
// A file's one-line description prefers, in order: an authored
// frontmatter `summary:` (the writer knows the hook — the memory
// convention), the first section's stored summary (§8.5 fleet
// derivation when present), else the file's leading prose.

type folderTreeFile struct {
	NodeID      string              `json:"node_id"`
	Name        string              `json:"name"`
	MimeHint    string              `json:"mime_hint,omitempty"`
	Description string              `json:"description,omitempty"`
	IndexStatus string              `json:"index_status,omitempty"`
	Sections    []folderTreeSecJSON `json:"sections,omitempty"`
}

type folderTreeSecJSON struct {
	SectionID string `json:"section_id"` // stable anchor
	Title     string `json:"title"`
	Depth     int    `json:"depth"`
	Summary   string `json:"summary,omitempty"`
}

type folderTreeFolder struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
}

// handleFolderTree returns the tree for one folder (root when folderID
// == ""): its subfolders and its files with per-file descriptions and
// section indexes.
func (s *Server) handleFolderTree(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	folderID := r.PathValue("folderID") // "" = root
	if p.IsAssistant() {
		// The assistant enclave may walk the tree only within an AI-scoped
		// folder (a whole-tree walk would leak names outside scope), so a
		// concrete in-scope folderID is required.
		if !s.canRead(r.Context(), tenantID, p.Sub) || folderID == "" ||
			!s.nodeInAIScope(r.Context(), tenantID, folderID) {
			httpError(w, http.StatusForbidden, errors.New("forbidden"))
			return
		}
	} else if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if folderID != "" {
		if !s.allowNodeRead(r.Context(), p, tenantID, folderID) {
			httpError(w, http.StatusForbidden, errors.New("forbidden"))
			return
		}
	}
	kids, err := s.Store.ListChildren(r.Context(), tenantID, folderID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	folders := make([]folderTreeFolder, 0)
	files := make([]folderTreeFile, 0)
	for _, n := range kids {
		if n.Kind == store.NodeFolder {
			folders = append(folders, folderTreeFolder{NodeID: n.ID, Name: n.Name})
			continue
		}
		files = append(files, s.folderTreeFileOf(r.Context(), tenantID, n))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"folder_id": folderID, "folders": folders, "files": files,
	})
}

// folderTreeFileOf builds the per-file entry: description + section index.
func (s *Server) folderTreeFileOf(ctx context.Context, tenantID string, n *store.Node) folderTreeFile {
	f := folderTreeFile{NodeID: n.ID, Name: n.Name, MimeHint: n.MimeHint}
	if status, _, err := s.Store.NodeIndexMeta(ctx, tenantID, n.ID); err == nil {
		f.IndexStatus = status
	}
	secs, _ := s.Store.ListSections(ctx, tenantID, n.ID)
	for _, sec := range secs {
		f.Sections = append(f.Sections, folderTreeSecJSON{
			SectionID: sec.Anchor, Title: sec.Title, Depth: sec.Depth, Summary: sec.Summary,
		})
	}
	f.Description = s.fileDescription(ctx, tenantID, n, secs)
	return f
}

// fileDescription resolves a one-line description: authored frontmatter
// summary, then the root section summary, then leading prose.
func (s *Server) fileDescription(ctx context.Context, tenantID string, n *store.Node, secs []*store.Section) string {
	if isTextLike(n.MimeHint, n.Name) {
		if b, err := s.readNodeBytes(ctx, tenantID, n.ID); err == nil {
			if sum := frontmatterSummary(b); sum != "" {
				return sum
			}
			if lead := leadingProse(b); lead != "" {
				if len(secs) == 0 || secs[0].Summary == "" {
					return lead
				}
			}
		}
	}
	for _, sec := range secs {
		if sec.Summary != "" {
			return sec.Summary
		}
	}
	return ""
}

// frontmatterSummary extracts a leading YAML frontmatter `summary:` line
// (the memory convention). Returns "" when absent.
func frontmatterSummary(b []byte) string {
	s := string(b)
	if !strings.HasPrefix(s, "---") {
		return ""
	}
	end := strings.Index(s[3:], "\n---")
	if end < 0 {
		return ""
	}
	fm := s[3 : 3+end]
	for _, line := range strings.Split(fm, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "summary:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// leadingProse returns the first non-empty, non-heading, non-frontmatter
// line, truncated — the fallback description.
func leadingProse(b []byte) string {
	s := string(b)
	if strings.HasPrefix(s, "---") {
		if end := strings.Index(s[3:], "\n---"); end >= 0 {
			s = s[3+end+4:]
		}
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > 200 {
			return line[:200] + "…"
		}
		return line
	}
	return ""
}

// isTextLike reports whether a node is markdown/plain text (cheap to
// read for a description).
func isTextLike(mime, name string) bool {
	m := strings.ToLower(mime)
	if strings.HasPrefix(m, "text/") || strings.Contains(m, "markdown") || strings.Contains(m, "jsonl") {
		return true
	}
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".md") || strings.HasSuffix(l, ".txt")
}

// toolFolderTree is get_folder_tree for agents.
func (s *Server) toolFolderTree(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
		FolderID string `json:"folder_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	r2.SetPathValue("folderID", req.FolderID)
	s.handleFolderTree(w, r2, p)
}

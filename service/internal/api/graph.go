package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// extractAndStoreLinks pulls typed links from a markdown node's content
// and stores them immediately. The indexer does this for indexed files;
// calling it directly at memory/digest write time makes the graph work
// even on instances without pgvector (where the indexer does not run)
// and keeps the graph fresh the moment a memory or digest is written.
func (s *Server) extractAndStoreLinks(ctx context.Context, tenantID, nodeID, text string) {
	raws := search.ExtractLinks(text)
	links := make([]store.NodeLink, 0, len(raws))
	for _, r := range raws {
		l := store.NodeLink{FromNode: nodeID, FromSection: r.FromSection, Kind: store.LinkKind(r.Kind)}
		switch r.Kind {
		case "citation":
			l.ToNode, l.ToSection, l.ToName = r.ToNode, r.ToSection, r.ToNode
		case "wikilink":
			l.ToName = r.ToName
			l.ToNode = s.Store.ResolveMemoryName(ctx, tenantID, r.ToName)
		default:
			continue
		}
		links = append(links, l)
	}
	_ = s.Store.ReplaceNodeLinks(ctx, tenantID, nodeID, links)
}

// Graph view + backlinks + wiki-lint (§8.7). The graph is rendered from
// the enclave index over the sealed session: nodes are files/folders
// (coloured by folder class), edges are the typed links table plus
// derived containment. Access-scoped by construction — served only for
// the caller's own tenant, filtered to nodes the caller can read.

// handleGraph returns the tenant's node/edge graph. Members see the
// whole tenant; the web UI colours by class (memory / conversation /
// document).
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	nodes, edges, err := s.Store.GraphData(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if nodes == nil {
		nodes = []store.GraphNode{}
	}
	if edges == nil {
		edges = []store.GraphEdge{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges})
}

// handleBacklinks returns the nodes that link to a given node.
func (s *Server) handleBacklinks(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !s.allowNodeRead(r.Context(), p, tenantID, nodeID) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	links, err := s.Store.Backlinks(r.Context(), tenantID, nodeID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(links))
	for _, l := range links {
		name := ""
		if n, gerr := s.Store.GetNode(r.Context(), tenantID, l.FromNode); gerr == nil {
			name = n.Name
		}
		out = append(out, map[string]any{
			"from_node": l.FromNode, "from_name": name,
			"from_section": l.FromSection, "kind": l.Kind,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"backlinks": out})
}

// handleLint returns the wiki-lint signals: dangling links and orphans.
func (s *Server) handleLint(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	dead, err := s.Store.DeadLinks(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	orphans, err := s.Store.OrphanNodes(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	deadOut := make([]map[string]any, 0, len(dead))
	for _, l := range dead {
		deadOut = append(deadOut, map[string]any{
			"from_node": l.FromNode, "to_name": l.ToName, "kind": l.Kind,
		})
	}
	if orphans == nil {
		orphans = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dangling_links": deadOut, "orphan_nodes": orphans,
	})
}

// toolGraph is get_graph for agents.
func (s *Server) toolGraph(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	s.handleGraph(w, r2, p)
}

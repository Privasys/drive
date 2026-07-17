package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/search"
)

// AI scope as grants (§8.7). "Enable for AI" mints a grant to the
// assistant (a dedicated grantee subject) on a subtree, rendered like
// any share ("Shared with: Assistant"), revocable identically, visible
// in the audit feed. Enforcement is server-side grant-scoped search —
// the assistant's search filters to the AI-scoped node set, never a
// trusted tool parameter. Two orthogonal layers: *indexed* (no_index —
// what CAN be found) vs *AI-scoped* (this grant — what the assistant MAY
// read in conversations).
//
// Defaults: Memory/ and Chat conversations/ are always in scope
// implicitly (below); everything else is opt-in per directory.

// alwaysScoped are the folders always in AI scope regardless of an
// explicit grant (the plan's fresh-user defaults).
var alwaysScoped = []string{memoryRoot, conversationsRoot}

func (s *Server) handleEnableAI(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if _, err := s.Store.GetNode(r.Context(), tenantID, nodeID); err != nil {
		writeStoreError(w, err)
		return
	}
	if g, err := s.Grants.ActiveRawSubjectOnNode(r.Context(), tenantID, nodeID, grants.SubjectAssistant); err == nil && g != nil {
		writeJSON(w, http.StatusOK, map[string]any{"grant_id": g.ID, "already": true})
		return
	}
	g := &grants.Grant{
		TenantID: tenantID, NodeID: nodeID, Subject: grants.SubjectAssistant,
		Scope: []grants.Scope{grants.ScopeRead}, CreatedBy: p.Sub,
	}
	if err := s.Grants.Create(r.Context(), g); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"grant_id": g.ID})
}

func (s *Server) handleDisableAI(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	g, err := s.Grants.ActiveRawSubjectOnNode(r.Context(), tenantID, nodeID, grants.SubjectAssistant)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if g == nil {
		writeJSON(w, http.StatusOK, map[string]any{"disabled": false})
		return
	}
	if err := s.Grants.Revoke(r.Context(), tenantID, g.ID); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"disabled": true})
}

func (s *Server) handleListAIScope(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	gs, err := s.Grants.ListForTenantSubject(r.Context(), tenantID, grants.SubjectAssistant)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(gs))
	for _, g := range gs {
		name := ""
		if n, gerr := s.Store.GetNode(r.Context(), tenantID, g.NodeID); gerr == nil {
			name = n.Name
		}
		out = append(out, map[string]any{"grant_id": g.ID, "node_id": g.NodeID, "name": name})
	}
	// Report the implicit defaults too, so the UI can show the full scope.
	defaults := make([]string, 0, len(alwaysScoped))
	for _, name := range alwaysScoped {
		if n, gerr := s.Store.ChildByName(r.Context(), tenantID, "", name); gerr == nil {
			defaults = append(defaults, n.ID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"scoped": out, "always_scoped": defaults})
}

// aiScopeNodeSet computes the concrete node-id allow-list the assistant
// may search: the descendants of every AI-scoped folder (explicit
// grants + the always-scoped defaults Memory/ and Chat conversations/).
func (s *Server) aiScopeNodeSet(ctx context.Context, tenantID string) ([]string, error) {
	roots := map[string]bool{}
	gs, err := s.Grants.ListForTenantSubject(ctx, tenantID, grants.SubjectAssistant)
	if err != nil {
		return nil, err
	}
	for _, g := range gs {
		if g.NodeID != "" {
			roots[g.NodeID] = true
		}
	}
	for _, name := range alwaysScoped {
		if n, gerr := s.Store.ChildByName(ctx, tenantID, "", name); gerr == nil {
			roots[n.ID] = true
		}
	}
	rootIDs := make([]string, 0, len(roots))
	for id := range roots {
		rootIDs = append(rootIDs, id)
	}
	return s.Store.DescendantNodeIDs(ctx, tenantID, rootIDs)
}

// semanticSearchScoped runs the search restricted to the AI-scoped node
// set (§8.7). Used when a caller requests assistant-scoped search.
func (s *Server) semanticSearchScoped(ctx context.Context, tenantID, q string, topK int) ([]searchHitJSON, int, error) {
	allow, err := s.aiScopeNodeSet(ctx, tenantID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	emb := s.activeEmbedder()
	vecs, err := emb.Embed(ctx, []string{q}, search.Query)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	hits, err := s.Store.SearchEmbeddingsScoped(ctx, tenantID, emb.Space(), vecs[0], topK, allow)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	return s.hitsToJSON(ctx, tenantID, hits), http.StatusOK, nil
}

func (s *Server) handleEnableAITool(fn func(http.ResponseWriter, *http.Request, *Principal)) func(http.ResponseWriter, *http.Request, *Principal) {
	return func(w http.ResponseWriter, r *http.Request, p *Principal) {
		var req struct {
			TenantID string `json:"tenant_id"`
			NodeID   string `json:"node_id"`
		}
		if err := readJSON(r, &req); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
		r2 := r.Clone(r.Context())
		r2.SetPathValue("tenantID", req.TenantID)
		r2.SetPathValue("nodeID", req.NodeID)
		fn(w, r2, p)
	}
}

func (s *Server) toolEnableAI(w http.ResponseWriter, r *http.Request, p *Principal) {
	s.handleEnableAITool(s.handleEnableAI)(w, r, p)
}
func (s *Server) toolDisableAI(w http.ResponseWriter, r *http.Request, p *Principal) {
	s.handleEnableAITool(s.handleDisableAI)(w, r, p)
}
func (s *Server) toolListAIScope(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		TenantID string `json:"tenant_id"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
	r2.SetPathValue("tenantID", req.TenantID)
	s.handleListAIScope(w, r2, p)
}

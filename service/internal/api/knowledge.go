package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Per-call folder narrowing of the assistant surface.
//
// The AI scope (§8.7) is the user's own ceiling: the folders they enabled
// for AI in their Drive, Memory/ and the always-scoped roots. An agent
// harness that runs several workspaces for the same user needs something
// narrower per workspace, so a session about one customer never surfaces
// another customer's files. The harness names that subset on each MCP call
// as `folder_ids`; this file carries it through the request context and
// aiScopeNodeSet intersects with it. It can only ever narrow: a caller who
// names folders outside the AI scope gets the empty intersection, and a
// caller who names nothing gets the AI scope unchanged.

type folderFilterKey struct{}

// withFolderFilter records the folders a request may reach. Nil clears it.
func withFolderFilter(ctx context.Context, folderIDs []string) context.Context {
	return context.WithValue(ctx, folderFilterKey{}, folderIDs)
}

// folderFilterFrom returns the request's folder filter, nil when unset.
func folderFilterFrom(ctx context.Context) []string {
	ids, _ := ctx.Value(folderFilterKey{}).([]string)
	return ids
}

// folderFilterField is the MCP argument the harness sets and the model never
// sees in a schema: the tool handlers do not know it, so it is stripped here.
const folderFilterField = "folder_ids"

// splitFolderFilter removes folder_ids from a JSON-object body and returns
// the remaining body with the filter. A body without the field passes
// through untouched; a malformed field is an error the caller reports.
func splitFolderFilter(body []byte) ([]byte, []string, error) {
	obj := map[string]json.RawMessage{}
	if len(body) == 0 {
		return body, nil, nil
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, nil, errors.New("arguments must be a JSON object")
	}
	raw, ok := obj[folderFilterField]
	if !ok {
		return body, nil, nil
	}
	var ids []string
	if err := json.Unmarshal(raw, &ids); err != nil {
		return nil, nil, errors.New("folder_ids must be an array of node ids")
	}
	delete(obj, folderFilterField)
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, err
	}
	filtered := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != "" {
			filtered = append(filtered, id)
		}
	}
	// An explicit empty list means "nothing": distinguish it from absence so
	// a harness workspace set to no folders reaches no file.
	if filtered == nil {
		filtered = []string{}
	}
	return out, filtered, nil
}

// applyFolderFilter narrows an AI-scoped node set to the descendants (and
// selves) of the request's folder filter. Without a filter the set is
// returned as is.
func (s *Server) applyFolderFilter(ctx context.Context, tenantID string, scoped []string) ([]string, error) {
	filter := folderFilterFrom(ctx)
	if filter == nil {
		return scoped, nil
	}
	if len(filter) == 0 {
		return []string{}, nil
	}
	under, err := s.Store.DescendantNodeIDs(ctx, tenantID, filter)
	if err != nil {
		return nil, err
	}
	allowed := make(map[string]bool, len(under))
	for _, id := range under {
		allowed[id] = true
	}
	out := make([]string, 0, len(scoped))
	for _, id := range scoped {
		if allowed[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

// handleMCPAIScope lists the folders an assistant caller may be narrowed
// to: GET /api/v1/mcp/ai-scope, acting for the user named by the caller.
// It is the picker's source of truth, so it reports exactly the roots of
// the AI scope: every folder the user enabled for AI, the always-scoped
// roots, and, when the whole Drive is enabled, every top-level folder.
func (s *Server) handleMCPAIScope(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !(p.IsUser() || p.IsAssistant()) || p.Sub == "" {
		httpError(w, http.StatusUnauthorized, errors.New("missing acting user"))
		return
	}
	tenantID, ok := s.settingsActingTenant(w, r, p)
	if !ok {
		return
	}
	type folder struct {
		NodeID string `json:"node_id"`
		Name   string `json:"name"`
		Always bool   `json:"always,omitempty"`
	}
	seen := map[string]bool{}
	var folders []folder
	add := func(id, name string, always bool) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		folders = append(folders, folder{NodeID: id, Name: name, Always: always})
	}
	gs, err := s.Grants.ListForTenantSubject(r.Context(), tenantID, grants.SubjectAssistant)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	allScoped := false
	for _, g := range gs {
		if g.NodeID == "" {
			allScoped = true
			continue
		}
		if n, gerr := s.Store.GetNode(r.Context(), tenantID, g.NodeID); gerr == nil {
			add(n.ID, n.Name, false)
		}
	}
	if allScoped {
		top, terr := s.Store.ListChildren(r.Context(), tenantID, "")
		if terr != nil {
			httpError(w, http.StatusInternalServerError, terr)
			return
		}
		for _, n := range top {
			if n.Kind == store.NodeFolder {
				add(n.ID, n.Name, false)
			}
		}
	}
	for _, name := range alwaysScoped {
		if n, gerr := s.Store.ChildByName(r.Context(), tenantID, "", name); gerr == nil {
			add(n.ID, n.Name, true)
		}
	}
	sort.SliceStable(folders, func(i, j int) bool {
		if folders[i].Always != folders[j].Always {
			return !folders[i].Always
		}
		return folders[i].Name < folders[j].Name
	})
	if folders == nil {
		folders = []folder{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"folders": folders, "all_scoped": allScoped})
}

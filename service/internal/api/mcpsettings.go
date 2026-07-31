package api

// MCP tool settings (generic contract, v1). A tool server that wants a
// rich, user-configurable integration in a chat client advertises a
// `settings` descriptor in its catalogue and serves this per-user surface:
//
//	GET /api/v1/mcp/settings  -> { version, display, schema, values }
//	PUT /api/v1/mcp/settings  <- { values: {...} }  (partial; returns fresh doc)
//
// The `schema` is a restricted JSON-Schema profile a chat client renders
// GENERICALLY — nothing tool-specific ships in any UI:
//
//	boolean                       -> toggle row (title/description from schema)
//	array of string + x-options   -> multi-select; options are MATERIALISED
//	                                 per user by the server (value/label pairs),
//	                                 so the client never calls tools to render
//
// Client-facing extensions: x-order (property order), x-group (section
// label), x-superseded-by (grey this field while the named boolean is on),
// x-disabled / x-disabled-reason (field not currently available).
//
// Auth: the acting USER must be named — either a first-party session or the
// attested assistant enclave carrying X-Privasys-On-Behalf-Of (the chat UI
// reaches here through the confidential-ai settings proxy). Unlike the tool
// surface, PUT deliberately bypasses the assistant read-only rule
// (allowNode): changing what the assistant may recall is exactly the user
// intent this endpoint exists to carry, it is gated on the user's own role
// in their personal tenant, and it is NOT in the tool catalogue, so the
// model cannot call it from the agent loop.
//
// Drive's settings map onto existing primitives: `memory` is the
// assistant_settings flag (store/settings.go), everything else is the §8.7
// AI-scope grant set (aiscope.go) — so drive.privasys.org's own AI-scope
// view and this surface can never disagree.

import (
	"context"
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// assistantSettingsDescriptor is the static half advertised in the tool
// catalogue (GET /api/v1/mcp/tools), so a client knows this server has a
// settings surface — and how to present its entry point — before any
// per-user request is made.
var assistantSettingsDescriptor = map[string]any{
	"title":       "Memory",
	"icon":        "brain",
	"description": "What the assistant may recall from your Drive.",
}

// settingsActingTenant authenticates + resolves the acting user's personal
// tenant for the settings surface. Writes the HTTP error itself; ok=false
// means the response is already sent.
func (s *Server) settingsActingTenant(w http.ResponseWriter, r *http.Request, p *Principal) (string, bool) {
	if !(p.IsUser() || p.IsAssistant()) || p.Sub == "" {
		httpError(w, http.StatusUnauthorized, errors.New("missing acting user"))
		return "", false
	}
	t, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(w, http.StatusNotFound, errors.New("no personal drive for this user"))
			return "", false
		}
		httpError(w, http.StatusInternalServerError, err)
		return "", false
	}
	if !s.canShare(r.Context(), t.ID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return "", false
	}
	return t.ID, true
}

func (s *Server) handleMCPSettingsGet(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID, ok := s.settingsActingTenant(w, r, p)
	if !ok {
		return
	}
	doc, err := s.buildAssistantSettings(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) handleMCPSettingsPut(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID, ok := s.settingsActingTenant(w, r, p)
	if !ok {
		return
	}
	var req struct {
		Values struct {
			Memory            *bool     `json:"memory"`
			PastConversations *bool     `json:"past_conversations"`
			EntireDrive       *bool     `json:"entire_drive"`
			Folders           *[]string `json:"folders"`
		} `json:"values"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	if req.Values.Memory != nil {
		if err := s.Store.SetAssistantMemoryOn(ctx, tenantID, *req.Values.Memory); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if req.Values.EntireDrive != nil {
		if err := s.setAssistantScope(ctx, tenantID, "", *req.Values.EntireDrive, p.Sub); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if req.Values.PastConversations != nil {
		conv, err := s.Store.ChildByName(ctx, tenantID, "", conversationsRoot)
		switch {
		case err == nil:
			if err := s.setAssistantScope(ctx, tenantID, conv.ID, *req.Values.PastConversations, p.Sub); err != nil {
				httpError(w, http.StatusInternalServerError, err)
				return
			}
		case errors.Is(err, store.ErrNotFound):
			// No saved conversation yet: nothing to grant. The returned doc
			// reflects reality (off + x-disabled), never a phantom "on".
		default:
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	if req.Values.Folders != nil {
		if err := s.applyAssistantFolderScope(ctx, tenantID, *req.Values.Folders, p.Sub); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
	}
	doc, err := s.buildAssistantSettings(ctx, tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// setAssistantScope creates or revokes the assistant grant on one node
// ("" = the tenant-wide, whole-Drive grant). Idempotent both ways.
func (s *Server) setAssistantScope(ctx context.Context, tenantID, nodeID string, on bool, actor string) error {
	g, err := s.Grants.ActiveRawSubjectOnNode(ctx, tenantID, nodeID, grants.SubjectAssistant)
	if err != nil {
		return err
	}
	if on {
		if g != nil {
			return nil
		}
		return s.Grants.Create(ctx, &grants.Grant{
			TenantID: tenantID, NodeID: nodeID, Subject: grants.SubjectAssistant,
			Scope: []grants.Scope{grants.ScopeRead}, CreatedBy: actor,
		})
	}
	if g == nil {
		return nil
	}
	return s.Grants.Revoke(ctx, tenantID, g.ID)
}

// applyAssistantFolderScope reconciles the per-folder assistant grants to
// exactly `want` (validated top-level folders; Memory/ and Chat
// conversations/ are managed by their own fields and never touched here).
func (s *Server) applyAssistantFolderScope(ctx context.Context, tenantID string, want []string, actor string) error {
	current, special, err := s.assistantFolderScope(ctx, tenantID)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, id := range want {
		if id == "" || special[id] {
			continue
		}
		if _, err := s.Store.GetNode(ctx, tenantID, id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errors.New("unknown folder id " + id)
			}
			return err
		}
		wanted[id] = true
	}
	for id := range wanted {
		if !current[id] {
			if err := s.setAssistantScope(ctx, tenantID, id, true, actor); err != nil {
				return err
			}
		}
	}
	for id := range current {
		if !wanted[id] {
			if err := s.setAssistantScope(ctx, tenantID, id, false, actor); err != nil {
				return err
			}
		}
	}
	return nil
}

// assistantFolderScope returns the per-folder grant set (node id -> true),
// excluding the tenant-wide grant and the special folders (returned
// separately so callers can skip them).
func (s *Server) assistantFolderScope(ctx context.Context, tenantID string) (scoped, special map[string]bool, err error) {
	special = map[string]bool{}
	for _, name := range []string{memoryRoot, conversationsRoot} {
		if n, gerr := s.Store.ChildByName(ctx, tenantID, "", name); gerr == nil {
			special[n.ID] = true
		}
	}
	gs, err := s.Grants.ListForTenantSubject(ctx, tenantID, grants.SubjectAssistant)
	if err != nil {
		return nil, nil, err
	}
	scoped = map[string]bool{}
	for _, g := range gs {
		if g.NodeID == "" || special[g.NodeID] {
			continue
		}
		scoped[g.NodeID] = true
	}
	return scoped, special, nil
}

// buildAssistantSettings renders the full settings document for one tenant:
// static display, the schema with per-user materialised folder options, and
// the current values read from the flag + grant set.
func (s *Server) buildAssistantSettings(ctx context.Context, tenantID string) (map[string]any, error) {
	memoryOn, err := s.Store.AssistantMemoryOn(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	gs, err := s.Grants.ListForTenantSubject(ctx, tenantID, grants.SubjectAssistant)
	if err != nil {
		return nil, err
	}
	convNode, convErr := s.Store.ChildByName(ctx, tenantID, "", conversationsRoot)
	hasConversations := convErr == nil

	allScoped := false
	scopedIDs := map[string]bool{}
	for _, g := range gs {
		if g.NodeID == "" {
			allScoped = true
			continue
		}
		scopedIDs[g.NodeID] = true
	}
	conversationsOn := hasConversations && scopedIDs[convNode.ID]

	// Folder options: every top-level folder except the two special ones.
	top, err := s.Store.ListChildren(ctx, tenantID, "")
	if err != nil {
		return nil, err
	}
	options := make([]map[string]string, 0, len(top))
	folderValues := make([]string, 0, len(top))
	for _, n := range top {
		if n.Kind != store.NodeFolder || n.Name == memoryRoot || n.Name == conversationsRoot {
			continue
		}
		options = append(options, map[string]string{"value": n.ID, "label": n.Name})
		if scopedIDs[n.ID] {
			folderValues = append(folderValues, n.ID)
		}
	}

	pastConversations := map[string]any{
		"type":        "boolean",
		"title":       "Past conversations",
		"description": "Let me recall your previous chats when they are relevant.",
		"default":     false,
		"x-group":     "What I can recall",
		"x-superseded-by": "entire_drive",
	}
	if !hasConversations {
		pastConversations["x-disabled"] = true
		pastConversations["x-disabled-reason"] = "Available once you have a saved conversation."
	}

	schema := map[string]any{
		"type": "object",
		"properties": map[string]any{
			"memory": map[string]any{
				"type":        "boolean",
				"title":       "What I remember about you",
				"description": "Notes I keep as we talk — preferences, context about your work — stored in your Drive's Memory folder.",
				"default":     true,
				"x-group":     "Memory",
			},
			"past_conversations": pastConversations,
			"entire_drive": map[string]any{
				"type":        "boolean",
				"title":       "Entire Drive",
				"description": "Everything in your Drive, including files you add later. The broadest option.",
				"default":     false,
				"x-group":     "What I can recall",
			},
			"folders": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"title":       "Specific folders",
				"description": "Let me search these folders and everything in them.",
				"x-group":     "Specific folders",
				"x-options":   options,
				"x-superseded-by": "entire_drive",
			},
		},
		"x-order": []string{"memory", "past_conversations", "entire_drive", "folders"},
	}

	return map[string]any{
		"version": 1,
		"display": assistantSettingsDescriptor,
		"schema":  schema,
		"values": map[string]any{
			"memory":             memoryOn,
			"past_conversations": conversationsOn,
			"entire_drive":       allScoped,
			"folders":            folderValues,
		},
	}, nil
}

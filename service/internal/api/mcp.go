package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/Privasys/drive/service/internal/store"
)

// MCP shim (§8.7 RAG-in-enclave): exposes the assistant's read-only RAG
// tools in the privasys_http MCP shape the confidential-AI agent speaks —
// `GET /api/v1/mcp/tools` (catalogue) and `POST /api/v1/mcp/tools/<tool>`
// (call) — so the inference enclave can add Drive as an ordinary MCP tool
// server (no bespoke transport). The tools deliberately OMIT tenant_id: the
// model does not know Drive tenant ids, so the shim resolves the acting
// user's personal tenant from the authenticated principal and injects it
// before delegating to the existing tool handlers. Auth + AI-scope
// confinement are the same as the /tools/* surface (see verifyAssistantEnclave
// and the IsAssistant gates).

// mcpTool is one catalogue entry advertised to the model.
type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// assistantMCPTools is the read-only RAG surface exposed to the assistant.
// Schemas are written for the model and never mention tenant_id.
var assistantMCPTools = []mcpTool{
	{
		Name:        "search_semantic",
		Description: "Search the user's Privasys Drive for passages relevant to a query. Returns scored snippets with a node_id and a stable section_id you can pass to read_section. Only content the user has made available to the assistant is searched.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string","description":"What to search for."},"top_k":{"type":"integer","description":"Maximum hits to return (default 6)."}},"required":["query"]}`),
	},
	{
		Name:        "read_section",
		Description: "Read one section of a file by its stable section_id (from a search_semantic hit). Use this to quote grounded source text.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"file_id":{"type":"string"},"section_id":{"type":"string"}},"required":["file_id","section_id"]}`),
	},
	{
		Name:        "read_file",
		Description: "Read a whole file's text by node_id (from a search_semantic hit). Prefer read_section for large files.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"file_id":{"type":"string"}},"required":["file_id"]}`),
	},
	{
		Name:        "get_memory",
		Description: "Fetch the user's Memory — durable notes the assistant keeps about the user and their work. Always available; consult it to stay consistent across chats.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	},
	{
		Name:        "open_link",
		Description: "Open a Privasys Drive share link the user gives you (https://drive.privasys.org/l?id=…#…). Pass the whole link, including the part after #. The user gets the share as if they had clicked it, and its files become readable with search_semantic, get_folder_tree and read_file. Returns status granted, pending (the owner approves each person), awaiting-approval (the link asks for something about the user, and a request is waiting in their wallet: ask them to approve it, then call open_link again) or missing-attributes (open the link in a browser instead), with what to do next.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string","description":"The share link, complete with its #fragment."}},"required":["url"]}`),
	},
	{
		Name:        "list_shares",
		Description: "List what other people shared with the user that you can read: files and folders the user opened through you with open_link. Each has a node_id for get_folder_tree or read_file.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
	},
	{
		Name:        "get_folder_tree",
		Description: "List a folder's structure (subfolders, files and their section anchors) by folder_id, to navigate a knowledge area the user has enabled for the assistant.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"folder_id":{"type":"string"}},"required":["folder_id"]}`),
	},
}

// handleMCPList serves the assistant RAG catalogue in the privasys_http MCP
// shape (GET /api/v1/mcp/tools). The `settings` descriptor advertises the
// per-user settings surface (mcpsettings.go) so chat clients render this
// server's rich integration generically. Static by design: this route is
// the one assistant request served WITHOUT an acting user (the enclave's
// cache-refresh pull), so nothing per-user may appear here.
func (s *Server) handleMCPList(w http.ResponseWriter, _ *http.Request, _ *Principal) {
	writeJSON(w, http.StatusOK, map[string]any{
		"tools":    assistantMCPTools,
		"settings": assistantSettingsDescriptor,
	})
}

// assistantToolHandler maps an MCP tool name to the underlying /tools/*
// handler. The RAG reads, plus open_link and list_shares
// (assistantshares.go).
func (s *Server) assistantToolHandler(tool string) func(http.ResponseWriter, *http.Request, *Principal) {
	switch tool {
	case "search_semantic":
		return s.toolSearchSemantic
	case "read_section":
		return s.toolReadSection
	case "read_file":
		return s.toolReadFile
	case "get_memory":
		return s.toolGetMemory
	case "get_folder_tree":
		return s.toolFolderTree
	case "open_link":
		return s.toolOpenLink
	case "list_shares":
		return s.toolListShares
	default:
		return nil
	}
}

// handleMCPCall dispatches POST /api/v1/mcp/tools/<tool>: resolve the acting
// user's personal tenant, inject tenant_id into the args, and delegate to
// the underlying tool handler (which enforces the AI-scope confinement).
func (s *Server) handleMCPCall(w http.ResponseWriter, r *http.Request, p *Principal) {
	tool := r.PathValue("tool")
	h := s.assistantToolHandler(tool)
	if h == nil {
		httpError(w, http.StatusNotFound, errors.New("unknown tool"))
		return
	}
	// A subject-less assistant principal exists only for the catalogue
	// route (isAssistantCatalogueRequest); a call always acts for a user.
	if p.Sub == "" {
		httpError(w, http.StatusUnauthorized, errors.New("missing on-behalf-of subject"))
		return
	}
	// Shares the user received are not in any tenant of theirs, and opening
	// one needs no Drive of their own.
	if tool == "open_link" || tool == "list_shares" {
		h(w, r, p)
		return
	}
	t, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpError(w, http.StatusNotFound, errors.New("no personal drive for this user"))
			return
		}
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// A harness may narrow this call to a folder set (knowledge.go): the
	// field is lifted out of the arguments into the request context, where
	// aiScopeNodeSet intersects it with the user's AI scope. It can only
	// narrow, so accepting it from any assistant caller is safe.
	body, folderIDs, err := splitFolderFilter(body)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	// A node the model names may sit in a share the user opened through the
	// assistant rather than in their own Drive: send the call to the tenant
	// that holds it. The read gates still decide whether it may be read.
	tenantID := t.ID
	if nodeID := namedNode(body); nodeID != "" {
		if _, gerr := s.Store.GetNode(r.Context(), t.ID, nodeID); gerr != nil {
			if other, ok := s.sharedTenantOf(r.Context(), p.Sub, nodeID); ok {
				tenantID = other
			}
		}
	}
	merged, err := injectTenantID(body, tenantID)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	ctx := r.Context()
	if folderIDs != nil {
		ctx = withFolderFilter(ctx, folderIDs)
	}
	r2 := r.Clone(ctx)
	r2.Body = io.NopCloser(bytes.NewReader(merged))
	r2.ContentLength = int64(len(merged))
	h(w, r2, p)
}

// injectTenantID sets tenant_id on a JSON object body (the model never
// supplies it). An empty body becomes just the tenant_id.
func injectTenantID(body []byte, tenantID string) ([]byte, error) {
	obj := map[string]json.RawMessage{}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return nil, errors.New("arguments must be a JSON object")
		}
	}
	id, _ := json.Marshal(tenantID)
	obj["tenant_id"] = id
	return json.Marshal(obj)
}

// namedNode returns the node a read tool's arguments name (file_id or
// folder_id), or "".
func namedNode(body []byte) string {
	var args struct {
		FileID   string `json:"file_id"`
		FolderID string `json:"folder_id"`
	}
	if json.Unmarshal(body, &args) != nil {
		return ""
	}
	if args.FileID != "" {
		return args.FileID
	}
	return args.FolderID
}

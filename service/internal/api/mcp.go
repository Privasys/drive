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
		Name:        "get_folder_tree",
		Description: "List a folder's structure (subfolders, files and their section anchors) by folder_id, to navigate a knowledge area the user has enabled for the assistant.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"folder_id":{"type":"string"}},"required":["folder_id"]}`),
	},
}

// handleMCPList serves the assistant RAG catalogue in the privasys_http MCP
// shape (GET /api/v1/mcp/tools).
func (s *Server) handleMCPList(w http.ResponseWriter, _ *http.Request, _ *Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"tools": assistantMCPTools})
}

// assistantToolHandler maps an MCP tool name to the underlying /tools/*
// handler. Only the read-only RAG surface is exposed here.
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
	merged, err := injectTenantID(body, t.ID)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	r2 := r.Clone(r.Context())
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

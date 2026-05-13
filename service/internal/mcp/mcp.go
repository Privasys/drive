// Package mcp exposes the Privasys Drive operations as a minimal
// Model Context Protocol HTTP transport. We expose:
//
//   - GET /mcp/v1/tools          — tool catalog
//   - POST /mcp/v1/tools/{name}  — tool invocation
//
// Tool inputs and outputs are the JSON shapes used by the REST API.
// The wire format is intentionally compatible with the MCP "Tools"
// surface so any MCP-aware agent can be pointed at the Drive enclave.
package mcp

import (
	"encoding/json"
	"net/http"

	"github.com/Privasys/drive/service/internal/api"
)

// Tool describes one MCP-exposed operation.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Method      string         `json:"-"` // HTTP verb on the underlying REST surface
	Path        string         `json:"-"`
	Input       map[string]any `json:"input_schema"`
}

// Catalog is the static set of tools surfaced over MCP.
var Catalog = []Tool{
	{
		Name:        "drive.list_root",
		Description: "List the root-level folders and files for a tenant.",
		Method:      "GET", Path: "/v1/tenants/{tenant_id}/root",
		Input: map[string]any{"type": "object", "properties": map[string]any{
			"tenant_id": map[string]any{"type": "string"},
		}, "required": []string{"tenant_id"}},
	},
	{
		Name:        "drive.list_folder",
		Description: "List the immediate children of a folder.",
		Method:      "GET", Path: "/v1/tenants/{tenant_id}/folders/{folder_id}",
		Input: map[string]any{"type": "object", "properties": map[string]any{
			"tenant_id": map[string]any{"type": "string"},
			"folder_id": map[string]any{"type": "string"},
		}, "required": []string{"tenant_id", "folder_id"}},
	},
	{
		Name:        "drive.read_file",
		Description: "Stream the plaintext bytes of a file.",
		Method:      "GET", Path: "/v1/tenants/{tenant_id}/files/{file_id}",
		Input: map[string]any{"type": "object", "properties": map[string]any{
			"tenant_id": map[string]any{"type": "string"},
			"file_id":   map[string]any{"type": "string"},
		}, "required": []string{"tenant_id", "file_id"}},
	},
	{
		Name:        "drive.write_file",
		Description: "Upload a file to a folder. The body is the plaintext content.",
		Method:      "POST", Path: "/v1/tenants/{tenant_id}/files",
		Input: map[string]any{"type": "object", "properties": map[string]any{
			"tenant_id":  map[string]any{"type": "string"},
			"parent_id":  map[string]any{"type": "string"},
			"name":       map[string]any{"type": "string"},
			"mime":       map[string]any{"type": "string"},
		}, "required": []string{"tenant_id", "name"}},
	},
	{
		Name:        "drive.create_folder",
		Description: "Create a new folder under an optional parent folder.",
		Method:      "POST", Path: "/v1/tenants/{tenant_id}/folders",
		Input: map[string]any{"type": "object"},
	},
	{
		Name:        "drive.delete_node",
		Description: "Delete a folder (recursively) or a file by id.",
		Method:      "DELETE", Path: "/v1/tenants/{tenant_id}/nodes/{node_id}",
		Input: map[string]any{"type": "object"},
	},
	{
		Name:        "drive.changes",
		Description: "Stream the change feed since a sequence number.",
		Method:      "GET", Path: "/v1/tenants/{tenant_id}/changes",
		Input: map[string]any{"type": "object"},
	},
	{
		Name:        "drive.export_zip",
		Description: "Produce a GDPR-compliant ZIP of the tenant's tree.",
		Method:      "POST", Path: "/v1/tenants/{tenant_id}/exports",
		Input: map[string]any{"type": "object"},
	},
}

// Handler returns the MCP transport handler. It does not duplicate the
// REST handlers — it advertises them. Concrete invocation is performed
// by the agent making an HTTP call against the descriptor.
func Handler(_ *api.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /mcp/v1/tools", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tools": Catalog})
	})
	return mux
}

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/drive/service/internal/config"
)

// assistantReq builds a request on the assistant-enclave path (§8.7
// RAG-in-enclave): the interim shared-secret credential plus the acting
// user asserted via X-Privasys-On-Behalf-Of.
func assistantReq(t *testing.T, method, url, token, onBehalf, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Assistant "+token)
	if onBehalf != "" {
		req.Header.Set(onBehalfOfHeader, onBehalf)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// TestAssistantEnclaveRAG covers the confidential-AI enclave calling Drive's
// read-only RAG surface on behalf of a user: the credential gate, the acting
// user assertion, and that content reads are confined to the AI-scoped set.
func TestAssistantEnclaveRAG(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-1"
	const secret = "assistant-shared-secret"

	// Enable the interim assistant-enclave gate.
	srv.InstallConfig(&config.Config{Mode: config.ModeSovereign, AssistantEnclaveToken: secret})

	// Tenant + a Memory note (Memory/ is always in assistant scope).
	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)
	mpayload, _ := json.Marshal(map[string]any{
		"tenant_id": tenant.ID, "name": "pref", "summary": "a pref", "body": "the preference",
	})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(mpayload))); code != 200 && code != 201 {
		t.Fatalf("write_memory: %d %s", code, b)
	}

	// An in-scope Docs/ folder (Enable for AI) with a file, and an
	// out-of-scope Private/ folder with a file.
	mkFolderWithFile := func(folderName, fileName, contents string) (folderID, fileID string) {
		code, b := doReq(t, bearerReq(t, "POST",
			fmt.Sprintf("%s/v1/tenants/%s/folders", base.URL, tenant.ID), owner,
			fmt.Sprintf(`{"name":%q}`, folderName)))
		if code != 201 {
			t.Fatalf("folder %s: %d %s", folderName, code, b)
		}
		var folder nodeJSON
		_ = json.Unmarshal(b, &folder)
		req, _ := http.NewRequest("POST",
			fmt.Sprintf("%s/v1/tenants/%s/files?name=%s&mime=text/markdown&parent_id=%s",
				base.URL, tenant.ID, fileName, folder.ID),
			bytes.NewReader([]byte(contents)))
		req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
		code, b = doReq(t, req)
		if code != 201 {
			t.Fatalf("file %s: %d %s", fileName, code, b)
		}
		var file nodeJSON
		_ = json.Unmarshal(b, &file)
		return folder.ID, file.ID
	}
	docsID, docFileID := mkFolderWithFile("Docs", "spec.md", "# Spec\nthe answer is 42")
	_, privFileID := mkFolderWithFile("Private", "secret.md", "# Secret\ndo not read")

	// Enable AI on Docs/ only.
	ep, _ := json.Marshal(map[string]any{"tenant_id": tenant.ID, "node_id": docsID})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/enable_ai", owner, string(ep))); code != 201 {
		t.Fatalf("enable_ai Docs: %d %s", code, b)
	}

	// --- Credential gate ---
	// Right secret + acting user → get_memory works (Memory always scoped).
	if code, b = doReq(t, assistantReq(t, "POST", ts.URL+"/tools/get_memory", secret, owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))); code != 200 {
		t.Fatalf("assistant get_memory: %d %s", code, b)
	}
	// Wrong secret → 401.
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/tools/get_memory", "wrong", owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))); code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: want 401, got %d", code)
	}
	// Missing acting user → 401.
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/tools/get_memory", secret, "",
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))); code != http.StatusUnauthorized {
		t.Fatalf("missing on-behalf-of: want 401, got %d", code)
	}
	// Acting user who is not a tenant member → 403 (membership still applies).
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/tools/get_memory", secret, "stranger",
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))); code != http.StatusForbidden {
		t.Fatalf("stranger acting user: want 403, got %d", code)
	}

	// --- Content reads confined to the AI-scoped set ---
	// In-scope Docs/ file → readable by the assistant.
	if code, b = doReq(t, assistantReq(t, "POST", ts.URL+"/tools/read_file", secret, owner,
		fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, docFileID))); code != 200 {
		t.Fatalf("assistant read in-scope file: %d %s", code, b)
	}
	// Out-of-scope Private/ file → forbidden.
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/tools/read_file", secret, owner,
		fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, privFileID))); code != http.StatusForbidden {
		t.Fatalf("assistant read out-of-scope file: want 403, got %d", code)
	}

	// --- MCP shim: same tools without a client-supplied tenant_id ---
	// Catalogue lists the read-only RAG surface.
	code, b = doReq(t, assistantReq(t, "GET", ts.URL+"/api/v1/mcp/tools", secret, owner, ""))
	if code != 200 {
		t.Fatalf("mcp catalogue: %d %s", code, b)
	}
	var cat struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	_ = json.Unmarshal(b, &cat)
	if len(cat.Tools) == 0 {
		t.Fatalf("mcp catalogue empty: %s", b)
	}
	// get_memory via the shim with NO tenant_id — the shim injects it.
	if code, b = doReq(t, assistantReq(t, "POST", ts.URL+"/api/v1/mcp/tools/get_memory", secret, owner, `{}`)); code != 200 {
		t.Fatalf("mcp get_memory: %d %s", code, b)
	}
	// read_file via the shim confines to the AI-scoped set (out-of-scope → 403).
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/api/v1/mcp/tools/read_file", secret, owner,
		fmt.Sprintf(`{"file_id":%q}`, privFileID))); code != http.StatusForbidden {
		t.Fatalf("mcp read out-of-scope: want 403, got %d", code)
	}
	// In-scope read through the shim works.
	if code, b = doReq(t, assistantReq(t, "POST", ts.URL+"/api/v1/mcp/tools/read_file", secret, owner,
		fmt.Sprintf(`{"file_id":%q}`, docFileID))); code != 200 {
		t.Fatalf("mcp read in-scope: %d %s", code, b)
	}
	// Unknown tool → 404.
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/api/v1/mcp/tools/write_memory", secret, owner, `{}`)); code != http.StatusNotFound {
		t.Fatalf("mcp unknown/blocked tool: want 404, got %d", code)
	}

	// --- Gate disabled when no secret is configured ---
	srv.InstallConfig(&config.Config{Mode: config.ModeSovereign})
	if code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/tools/get_memory", secret, owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))); code != http.StatusUnauthorized {
		t.Fatalf("assistant path with no secret configured: want 401, got %d", code)
	}
}

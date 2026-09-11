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

// A harness narrows one MCP call to a folder set: reads outside the set are
// refused even when the folder is AI-enabled, reads inside still work, the
// field never reaches the tool handler, an empty set reaches nothing, and
// the picker's listing names exactly the AI-scope roots.
func TestAssistantFolderFilterNarrowsTheAIScope(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-kf"
	const secret = "assistant-shared-secret"
	srv.InstallConfig(&config.Config{Mode: config.ModeSovereign, AssistantEnclaveToken: secret})

	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)

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
	acmeID, acmeFile := mkFolderWithFile("Acme", "contract.md", "# Acme\nterms")
	globexID, globexFile := mkFolderWithFile("Globex", "brief.md", "# Globex\nbrief")
	for _, id := range []string{acmeID, globexID} {
		ep, _ := json.Marshal(map[string]any{"tenant_id": tenant.ID, "node_id": id})
		if code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/enable_ai", owner, string(ep))); code != 201 {
			t.Fatalf("enable_ai: %d %s", code, b)
		}
	}

	read := func(fileID string, folderIDs string) int {
		body := fmt.Sprintf(`{"file_id":%q}`, fileID)
		if folderIDs != "" {
			body = fmt.Sprintf(`{"file_id":%q,"folder_ids":%s}`, fileID, folderIDs)
		}
		code, _ := doReq(t, assistantReq(t, "POST", ts.URL+"/api/v1/mcp/tools/read_file", secret, owner, body))
		return code
	}
	// No filter: both AI-enabled files are readable.
	if code := read(acmeFile, ""); code != 200 {
		t.Fatalf("unfiltered read of Acme: %d", code)
	}
	// Narrowed to Acme: Acme reads, Globex is refused although AI-enabled.
	if code := read(acmeFile, fmt.Sprintf(`[%q]`, acmeID)); code != 200 {
		t.Fatalf("filtered read inside the set: %d", code)
	}
	if code := read(globexFile, fmt.Sprintf(`[%q]`, acmeID)); code != http.StatusForbidden {
		t.Fatalf("filtered read outside the set: want 403, got %d", code)
	}
	// An empty set reaches nothing; a malformed field is rejected.
	if code := read(acmeFile, `[]`); code != http.StatusForbidden {
		t.Fatalf("empty set: want 403, got %d", code)
	}
	if code := read(acmeFile, `"not-a-list"`); code != http.StatusBadRequest {
		t.Fatalf("malformed folder_ids: want 400, got %d", code)
	}

	// The picker's listing names both enabled roots and no top-level
	// folder that was not enabled.
	code, b = doReq(t, assistantReq(t, "GET", ts.URL+"/api/v1/mcp/ai-scope", secret, owner, ""))
	if code != 200 {
		t.Fatalf("ai-scope listing: %d %s", code, b)
	}
	var listing struct {
		Folders []struct {
			NodeID string `json:"node_id"`
			Name   string `json:"name"`
			Always bool   `json:"always"`
		} `json:"folders"`
		AllScoped bool `json:"all_scoped"`
	}
	_ = json.Unmarshal(b, &listing)
	names := map[string]bool{}
	for _, f := range listing.Folders {
		if !f.Always {
			names[f.Name] = true
		}
	}
	if !names["Acme"] || !names["Globex"] || len(names) != 2 || listing.AllScoped {
		t.Fatalf("listing: %s", b)
	}
}

func TestSplitFolderFilter(t *testing.T) {
	body, ids, err := splitFolderFilter([]byte(`{"file_id":"f1","folder_ids":["a","","b"]}`))
	if err != nil || len(ids) != 2 || ids[0] != "a" || ids[1] != "b" || bytes.Contains(body, []byte("folder_ids")) {
		t.Fatalf("split: %s %v %v", body, ids, err)
	}
	body, ids, err = splitFolderFilter([]byte(`{"query":"x"}`))
	if err != nil || ids != nil || string(body) != `{"query":"x"}` {
		t.Fatalf("absent field must pass through: %s %v %v", body, ids, err)
	}
	if _, ids, err := splitFolderFilter([]byte(`{"folder_ids":[]}`)); err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("explicit empty list must stay a list: %v %v", ids, err)
	}
}

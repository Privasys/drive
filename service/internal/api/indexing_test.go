package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestIndexingFlags: the explicit no-index upload flag and the folder
// searchability toggle persist; semantic search reports unavailable on
// an instance without pgvector (the SQLite test harness).
func TestIndexingFlags(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	// The harness has no pgvector: a normal upload stays status ''.
	if st, _, err := srv.Store.NodeIndexMeta(t.Context(), tenantID, fileID); err != nil || st != "" {
		t.Fatalf("default status: %q err=%v", st, err)
	}

	// Upload with index=false marks the file excluded + skipped.
	req := bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=secret.txt&mime=text/plain&index=false", ts.URL, tenantID),
		owner, "do not index this")
	req.Header.Set("Content-Type", "application/octet-stream")
	code, b := doReq(t, req)
	if code != 201 {
		t.Fatalf("upload: %d %s", code, b)
	}
	var node nodeJSON
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	st, noIndex, err := srv.Store.NodeIndexMeta(t.Context(), tenantID, node.ID)
	if err != nil || !noIndex || st != "skipped" {
		t.Fatalf("no-index upload: status=%q no_index=%v err=%v", st, noIndex, err)
	}

	// Folder toggle: create a folder, mark it non-searchable, and check
	// the ancestor rule sees a file created inside it.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenantID), owner, `{"name":"Private"}`))
	if code != 201 {
		t.Fatalf("create folder: %d %s", code, b)
	}
	var folder nodeJSON
	_ = json.Unmarshal(b, &folder)
	code, b = doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/indexing", ts.URL, tenantID, folder.ID),
		owner, `{"enabled":false}`))
	if code != 200 {
		t.Fatalf("toggle: %d %s", code, b)
	}
	req = bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=inside.txt&parent_id=%s", ts.URL, tenantID, folder.ID),
		owner, "inside a private folder")
	code, b = doReq(t, req)
	if code != 201 {
		t.Fatalf("upload inside: %d %s", code, b)
	}
	var inside nodeJSON
	_ = json.Unmarshal(b, &inside)
	if excluded, err := srv.Store.HasNoIndexAncestor(t.Context(), tenantID, inside.ID); err != nil || !excluded {
		t.Fatalf("ancestor rule: excluded=%v err=%v", excluded, err)
	}

	// Re-enable the folder.
	if code, _ := doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/indexing", ts.URL, tenantID, folder.ID),
		owner, `{"enabled":true}`)); code != 200 {
		t.Fatalf("re-enable: %d", code)
	}
	if excluded, _ := srv.Store.HasNoIndexAncestor(t.Context(), tenantID, inside.ID); excluded {
		t.Fatalf("still excluded after re-enable")
	}

	// Semantic search: unavailable without pgvector.
	if code, _ := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/search?q=finance", ts.URL, tenantID), owner, "")); code != http.StatusNotImplemented {
		t.Fatalf("search on sqlite: want 501, got %d", code)
	}
}

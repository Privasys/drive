package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Privasys/drive/service/internal/store"
)

func subtreeOf(t *testing.T, url, tenantID, nodeID, owner string) (int, store.SubtreeStats) {
	t.Helper()
	code, b := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/subtree", url, tenantID, nodeID), owner, ""))
	var out store.SubtreeStats
	if code == http.StatusOK {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("decode subtree: %v (%s)", err, b)
		}
	}
	return code, out
}

func mkFolder(t *testing.T, url, tenantID, owner, name, parent string) string {
	t.Helper()
	path := fmt.Sprintf("%s/v1/tenants/%s/folders", url, tenantID)
	body := fmt.Sprintf(`{"name":%q,"parent_id":%q}`, name, parent)
	code, b := doReq(t, bearerReq(t, "POST", path, owner, body))
	if code != http.StatusCreated {
		t.Fatalf("create folder %s: %d %s", name, code, b)
	}
	var n nodeJSON
	if err := json.Unmarshal(b, &n); err != nil {
		t.Fatal(err)
	}
	return n.ID
}

func mkFile(t *testing.T, url, tenantID, owner, name, parent, body string) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/tenants/%s/files?name=%s&mime=text/plain", url, tenantID, name)
	if parent != "" {
		u += "&parent_id=" + parent
	}
	req, _ := http.NewRequest("POST", u, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
	if code, b := doReq(t, req); code != http.StatusCreated {
		t.Fatalf("upload %s: %d %s", name, code, b)
	}
}

// TestSubtreeStatsCountsTheWholeTree: the count a caller uses to say what a
// delete will take with it must reach every level, not just the top one.
func TestSubtreeStatsCountsTheWholeTree(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	// Reports/ { one.txt, two.txt, Deep/ { three.txt } }
	reports := mkFolder(t, ts.URL, tenantID, owner, "Reports", "")
	deep := mkFolder(t, ts.URL, tenantID, owner, "Deep", reports)
	mkFile(t, ts.URL, tenantID, owner, "one.txt", reports, "aaaa")
	mkFile(t, ts.URL, tenantID, owner, "two.txt", reports, "bb")
	mkFile(t, ts.URL, tenantID, owner, "three.txt", deep, "cccccc")

	code, got := subtreeOf(t, ts.URL, tenantID, reports, owner)
	if code != http.StatusOK {
		t.Fatalf("subtree: %d", code)
	}
	if got.Files != 3 {
		t.Fatalf("files: want 3 across both levels, got %d", got.Files)
	}
	// Reports itself plus Deep.
	if got.Folders != 2 {
		t.Fatalf("folders: want 2, got %d", got.Folders)
	}
	if got.Bytes != 12 {
		t.Fatalf("bytes: want 12, got %d", got.Bytes)
	}
}

// TestSubtreeStatsOfAFile: a file is its own subtree, so the label for
// deleting one does not have to special-case the answer.
func TestSubtreeStatsOfAFile(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, payload := ownerTenantWithFile(t, ts.URL, owner)

	code, got := subtreeOf(t, ts.URL, tenantID, fileID, owner)
	if code != http.StatusOK {
		t.Fatalf("subtree: %d", code)
	}
	if got.Files != 1 || got.Folders != 0 || got.Bytes != int64(len(payload)) {
		t.Fatalf("a file is one file and its own bytes: %+v", got)
	}
}

// TestSubtreeStatsGuardsTheNode: an empty count must not be the answer a
// stranger gets, nor the answer for a node that is not there.
func TestSubtreeStatsGuardsTheNode(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, stranger = "user-1", "user-2"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	if code, _ := subtreeOf(t, ts.URL, tenantID, fileID, stranger); code != http.StatusForbidden {
		t.Fatalf("stranger: want 403, got %d", code)
	}
	if code, _ := subtreeOf(t, ts.URL, tenantID, "does-not-exist", owner); code != http.StatusNotFound {
		t.Fatalf("missing node: want 404, got %d", code)
	}
}

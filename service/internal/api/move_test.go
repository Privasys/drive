package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestMoveNode: a file can be moved into a folder and back to the root; a
// folder cannot be moved into itself.
func TestMoveNode(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	// Create a folder at the root.
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenantID), owner, `{"name":"Docs"}`))
	if code != 201 {
		t.Fatalf("create folder: %d %s", code, b)
	}
	var folder nodeJSON
	if err := json.Unmarshal(b, &folder); err != nil {
		t.Fatal(err)
	}

	moveURL := func(id string) string {
		return fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/move", ts.URL, tenantID, id)
	}

	// Move the file into the folder.
	if code, b := doReq(t, bearerReq(t, "POST", moveURL(fileID), owner,
		`{"parent_id":"`+folder.ID+`"}`)); code != http.StatusNoContent {
		t.Fatalf("move into folder: %d %s", code, b)
	}
	// It now lists under the folder, not the root.
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/folders/%s", ts.URL, tenantID, folder.ID), owner, ""))
	if code != 200 {
		t.Fatalf("list folder: %d %s", code, b)
	}
	var kids []nodeJSON
	if err := json.Unmarshal(b, &kids); err != nil {
		t.Fatal(err)
	}
	if len(kids) != 1 || kids[0].ID != fileID {
		t.Fatalf("file not in folder: %s", b)
	}

	// A folder cannot be moved into itself.
	if code, _ := doReq(t, bearerReq(t, "POST", moveURL(folder.ID), owner,
		`{"parent_id":"`+folder.ID+`"}`)); code != http.StatusBadRequest {
		t.Fatalf("self-move: want 400, got %d", code)
	}

	// Move the file back to the root.
	if code, _ := doReq(t, bearerReq(t, "POST", moveURL(fileID), owner, `{"parent_id":""}`)); code != http.StatusNoContent {
		t.Fatalf("move to root: %d", code)
	}
	code, b = doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/root", ts.URL, tenantID), owner, ""))
	if err := json.Unmarshal(b, &kids); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, k := range kids {
		if k.ID == fileID {
			found = true
		}
	}
	if !found {
		t.Fatalf("file not back at root: %s", b)
	}
}

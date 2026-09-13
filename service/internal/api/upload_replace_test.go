package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// TestUploadConflictThenReplace: a second upload of the same name is a
// conflict the caller can answer, and answering "replace" rewrites the
// file in place — same node id, so shares and links survive — rather than
// creating a second entry.
func TestUploadConflictThenReplace(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner = "user-1"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	upload := func(body, query string) (int, []byte) {
		req := bearerReq(t, "POST",
			fmt.Sprintf("%s/v1/tenants/%s/files?name=notes.txt&mime=text/plain%s", ts.URL, tenantID, query),
			owner, body)
		req.Header.Set("Content-Type", "application/octet-stream")
		return doReq(t, req)
	}

	code, b := upload("first version", "")
	if code != http.StatusCreated {
		t.Fatalf("first upload: %d %s", code, b)
	}
	var first nodeJSON
	if err := json.Unmarshal(b, &first); err != nil {
		t.Fatal(err)
	}

	// Same name again: refused, so the front can ask instead of guessing.
	if code, b = upload("second version", ""); code != http.StatusConflict {
		t.Fatalf("colliding upload: want 409, got %d %s", code, b)
	}

	// Replace: 200, the same node id, and the new bytes.
	code, b = upload("second version", "&overwrite=true")
	if code != http.StatusOK {
		t.Fatalf("replace: want 200, got %d %s", code, b)
	}
	var replaced nodeJSON
	if err := json.Unmarshal(b, &replaced); err != nil {
		t.Fatal(err)
	}
	if replaced.ID != first.ID {
		t.Fatalf("replace must keep the node id: %s != %s", replaced.ID, first.ID)
	}
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, first.ID), owner, ""))
	if code != 200 || string(b) != "second version" {
		t.Fatalf("content after replace: %d %q", code, b)
	}

	// Exactly one notes.txt remains in the folder.
	kids, err := srv.Store.ListRootChildren(t.Context(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, k := range kids {
		if k.Name == "notes.txt" {
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("notes.txt appears %d times after a replace", seen)
	}
}

// TestReplaceRefusesAFolderOfTheSameName: replacing swaps a file's bytes,
// never a folder's identity.
func TestReplaceRefusesAFolderOfTheSameName(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	if code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenantID), owner, `{"name":"Reports"}`)); code != 201 {
		t.Fatalf("create folder: %d %s", code, b)
	}
	req := bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=Reports&overwrite=true", ts.URL, tenantID), owner, "x")
	req.Header.Set("Content-Type", "application/octet-stream")
	if code, b := doReq(t, req); code != http.StatusConflict {
		t.Fatalf("replacing a folder: want 409, got %d %s", code, b)
	}
}

// TestDownloadSelectionZip: a folder and a file selected together come
// back as one archive, with the folder's tree laid out inside it.
func TestDownloadSelectionZip(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenantID), owner, `{"name":"Reports"}`))
	if code != 201 {
		t.Fatalf("create folder: %d %s", code, b)
	}
	var folder nodeJSON
	_ = json.Unmarshal(b, &folder)

	put := func(name, parent, body string) nodeJSON {
		t.Helper()
		url := fmt.Sprintf("%s/v1/tenants/%s/files?name=%s", ts.URL, tenantID, name)
		if parent != "" {
			url += "&parent_id=" + parent
		}
		req := bearerReq(t, "POST", url, owner, body)
		req.Header.Set("Content-Type", "application/octet-stream")
		code, b := doReq(t, req)
		if code != http.StatusCreated {
			t.Fatalf("upload %s: %d %s", name, code, b)
		}
		var n nodeJSON
		_ = json.Unmarshal(b, &n)
		return n
	}
	inside := put("q1.txt", folder.ID, "inside the folder")
	root := put("loose.txt", "", "at the root")
	_ = inside

	body := fmt.Sprintf(`{"node_ids":["%s","%s"]}`, folder.ID, root.ID)
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/download.zip", ts.URL, tenantID), owner, body))
	if code != 200 {
		t.Fatalf("download.zip: %d %s", code, b)
	}
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("not a zip: %v", err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(content)
	}
	if got["Reports/q1.txt"] != "inside the folder" {
		t.Fatalf("folder tree missing from the archive: %v", keysOf(got))
	}
	if got["loose.txt"] != "at the root" {
		t.Fatalf("selected file missing from the archive: %v", keysOf(got))
	}
}

func keysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

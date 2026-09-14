package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

type versionsResponse struct {
	NodeID   string        `json:"node_id"`
	Rev      int64         `json:"rev"`
	Versions []versionJSON `json:"versions"`
}

func listVersions(t *testing.T, url, tenantID, nodeID, owner string) versionsResponse {
	t.Helper()
	code, b := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/versions", url, tenantID, nodeID), owner, ""))
	if code != http.StatusOK {
		t.Fatalf("list versions: %d %s", code, b)
	}
	var out versionsResponse
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("list versions: %v (%s)", err, b)
	}
	return out
}

func replaceContent(t *testing.T, url, tenantID, nodeID, owner, body string) {
	t.Helper()
	code, b := doReq(t, bearerReq(t, "PUT",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/content", url, tenantID, nodeID), owner, body))
	if code != http.StatusOK {
		t.Fatalf("replace content: %d %s", code, b)
	}
}

// TestVersionHistoryThroughReplace: replacing a file keeps what it replaced,
// each revision readable on its own, and restoring an old one moves the file
// back without rewriting history.
func TestVersionHistoryThroughReplace(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, original := ownerTenantWithFile(t, ts.URL, owner)

	first := listVersions(t, ts.URL, tenantID, fileID, owner)
	if len(first.Versions) != 0 {
		t.Fatalf("a file that was never replaced has no history: %+v", first.Versions)
	}
	rev0 := first.Rev

	replaceContent(t, ts.URL, tenantID, fileID, owner, "second draft")
	replaceContent(t, ts.URL, tenantID, fileID, owner, "third draft")

	got := listVersions(t, ts.URL, tenantID, fileID, owner)
	if len(got.Versions) != 3 {
		t.Fatalf("want three revisions after two replacements, got %d: %+v", len(got.Versions), got.Versions)
	}
	// Newest first, and exactly one of them is the live content.
	if got.Versions[0].Rev != got.Rev || !got.Versions[0].Current {
		t.Fatalf("newest revision should be the current one: %+v", got.Versions)
	}
	current := 0
	for _, v := range got.Versions {
		if v.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("exactly one revision is current, got %d", current)
	}
	if got.Versions[2].Rev != rev0 {
		t.Fatalf("the original content should be the oldest revision: %+v", got.Versions)
	}

	// Each revision reads back as the bytes it held.
	read := func(rev int64) string {
		t.Helper()
		code, b := doReq(t, bearerReq(t, "GET",
			fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/versions/%d", ts.URL, tenantID, fileID, rev), owner, ""))
		if code != http.StatusOK {
			t.Fatalf("read revision %d: %d %s", rev, code, b)
		}
		return string(b)
	}
	if got := read(rev0); got != string(original) {
		t.Fatalf("original revision: %q", got)
	}
	if got := read(got.Versions[1].Rev); got != "second draft" {
		t.Fatalf("middle revision: %q", got)
	}
	if got := read(got.Versions[0].Rev); got != "third draft" {
		t.Fatalf("current revision: %q", got)
	}

	// Restoring is itself a new revision, so the restore can be undone.
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/versions/%d/restore", ts.URL, tenantID, fileID, rev0), owner, ""))
	if code != http.StatusOK {
		t.Fatalf("restore: %d %s", code, b)
	}
	var restored struct {
		Rev          int64 `json:"rev"`
		RestoredFrom int64 `json:"restored_from"`
		Restored     bool  `json:"restored"`
	}
	_ = json.Unmarshal(b, &restored)
	if !restored.Restored || restored.RestoredFrom != rev0 || restored.Rev <= got.Rev {
		t.Fatalf("restore answer: %+v (was rev %d)", restored, got.Rev)
	}
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, fileID), owner, ""))
	if code != http.StatusOK || string(b) != string(original) {
		t.Fatalf("after restore the file holds the restored bytes: %d %q", code, b)
	}
	after := listVersions(t, ts.URL, tenantID, fileID, owner)
	if len(after.Versions) != 4 || after.Rev != restored.Rev {
		t.Fatalf("restore adds a revision rather than rewriting history: %+v", after)
	}
}

// TestAppendDoesNotVersion: a transcript appends once per turn, so appends
// extend the same content rather than producing a revision each time.
func TestAppendDoesNotVersion(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, original := ownerTenantWithFile(t, ts.URL, owner)

	for _, line := range []string{"one\n", "two\n"} {
		code, b := doReq(t, bearerReq(t, "POST",
			fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/append", ts.URL, tenantID, fileID), owner, line))
		if code != http.StatusOK {
			t.Fatalf("append: %d %s", code, b)
		}
	}
	got := listVersions(t, ts.URL, tenantID, fileID, owner)
	if len(got.Versions) != 0 {
		t.Fatalf("appends must not record revisions: %+v", got.Versions)
	}
	code, b := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, fileID), owner, ""))
	if code != http.StatusOK || string(b) != string(original)+"one\ntwo\n" {
		t.Fatalf("appended content: %d %q", code, b)
	}
}

// TestHistoryIsNotIndexed: the semantic index belongs to the current
// version. Sections hang off the node, so replacing a file cannot leave
// index rows behind for what it replaced.
func TestHistoryIsNotIndexed(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	replaceContent(t, ts.URL, tenantID, fileID, owner, "second draft")
	replaceContent(t, ts.URL, tenantID, fileID, owner, "third draft")

	versions, err := srv.Store.ListFileVersions(t.Context(), tenantID, fileID, 0)
	if err != nil || len(versions) != 3 {
		t.Fatalf("history: %d rows %v", len(versions), err)
	}
	secs, err := srv.Store.ListSections(t.Context(), tenantID, fileID)
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 0 {
		t.Fatalf("no history was indexed, so the harness has no sections: %d", len(secs))
	}
}

// TestDeleteTakesHistory: history does not outlive the file it belongs to.
func TestDeleteTakesHistory(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	replaceContent(t, ts.URL, tenantID, fileID, owner, "second draft")
	if v, _ := srv.Store.ListFileVersions(t.Context(), tenantID, fileID, 0); len(v) != 2 {
		t.Fatalf("expected two revisions before delete, got %d", len(v))
	}
	if code, b := doReq(t, bearerReq(t, "DELETE",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s", ts.URL, tenantID, fileID), owner, "")); code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", code, b)
	}
	v, err := srv.Store.ListFileVersions(t.Context(), tenantID, fileID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Fatalf("history outlived its file: %d rows", len(v))
	}
}

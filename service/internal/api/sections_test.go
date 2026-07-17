package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Privasys/drive/service/internal/store"
)

// TestDocTreeAndReadSection: the agentic retrieval legs return the
// section tree and a whole section's text with provenance. Sections are
// seeded directly (the SQLite harness has no pgvector pipeline).
func TestDocTreeAndReadSection(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner, stranger = "user-1", "user-9"
	tenantID, fileID, payload := ownerTenantWithFile(t, ts.URL, owner)

	// Seed a two-level tree over the real file content.
	half := int64(len(payload) / 2)
	ids, err := srv.Store.ReplaceSections(t.Context(), tenantID, fileID, []store.SectionInput{
		{ParentIdx: -1, Title: "shared", Depth: 0, CharStart: 0, CharEnd: int64(len(payload))},
		{ParentIdx: 0, Title: "First half", Depth: 1, CharStart: 0, CharEnd: half},
		{ParentIdx: 0, Title: "Second half", Depth: 1, CharStart: half, CharEnd: int64(len(payload))},
	})
	if err != nil || len(ids) != 3 {
		t.Fatalf("seed sections: %v", err)
	}

	// Tree.
	code, b := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s/tree", ts.URL, tenantID, fileID), owner, ""))
	if code != 200 {
		t.Fatalf("tree: %d %s", code, b)
	}
	// The public tree returns STABLE anchors (§8.3), not DB row ids.
	var tree struct {
		Name     string `json:"name"`
		Sections []struct {
			SectionID string `json:"section_id"`
			ParentID  string `json:"parent_id"`
			Title     string `json:"title"`
			Depth     int    `json:"depth"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(b, &tree); err != nil {
		t.Fatal(err)
	}
	if len(tree.Sections) != 3 || tree.Sections[1].ParentID == "" || tree.Sections[1].ParentID != tree.Sections[0].SectionID {
		t.Fatalf("tree unexpected: %s", b)
	}
	if tree.Sections[2].Title != "Second half" {
		t.Fatalf("section order unexpected: %s", b)
	}
	secondAnchor := tree.Sections[2].SectionID

	// Anchors are deterministic: reindexing the same tree keeps them.
	ids2, err := srv.Store.ReplaceSections(t.Context(), tenantID, fileID, []store.SectionInput{
		{ParentIdx: -1, Title: "shared", Depth: 0, CharStart: 0, CharEnd: int64(len(payload))},
		{ParentIdx: 0, Title: "First half", Depth: 1, CharStart: 0, CharEnd: half},
		{ParentIdx: 0, Title: "Second half", Depth: 1, CharStart: half, CharEnd: int64(len(payload))},
	})
	if err != nil || len(ids2) != 3 {
		t.Fatalf("reindex sections: %v", err)
	}
	if again, gerr := srv.Store.GetSectionByAnchor(t.Context(), tenantID, fileID, secondAnchor); gerr != nil {
		t.Fatalf("anchor did not survive reindex: %v", gerr)
	} else if again.Title != "Second half" {
		t.Fatalf("anchor resolved to the wrong section: %q", again.Title)
	}

	// Read the second-half section by its anchor; text must be the exact slice.
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s/sections/%s", ts.URL, tenantID, fileID, secondAnchor), owner, ""))
	if code != 200 {
		t.Fatalf("read section: %d %s", code, b)
	}
	var sec struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	}
	if err := json.Unmarshal(b, &sec); err != nil {
		t.Fatal(err)
	}
	if sec.Title != "Second half" || sec.Text != string(payload[half:]) {
		t.Fatalf("section slice wrong: %q", sec.Text)
	}

	// A stranger has no access.
	if code, _ := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s/tree", ts.URL, tenantID, fileID), stranger, "")); code != http.StatusForbidden {
		t.Fatalf("stranger tree: want 403, got %d", code)
	}

	// A section id from another file 404s.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenantID), owner, `{"name":"Other"}`))
	if code != 201 {
		t.Fatalf("folder: %d %s", code, b)
	}
	var folder nodeJSON
	_ = json.Unmarshal(b, &folder)
	if code, _ := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s/sections/%s", ts.URL, tenantID, folder.ID, secondAnchor), owner, "")); code != http.StatusNotFound {
		t.Fatalf("cross-file section: want 404, got %d", code)
	}
}

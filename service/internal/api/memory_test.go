package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestMemoryAndFolderTree drives the §8.7 memory + get_folder_tree flow:
// write two memories (with merge-hygiene overlap detection), read them
// back tiered-inline, and enumerate them via get_folder_tree.
func TestMemoryAndFolderTree(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-1"
	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)

	write := func(name, summary, body string, overwrite bool) (int, []byte) {
		payload, _ := json.Marshal(map[string]any{
			"tenant_id": tenant.ID, "name": name, "summary": summary, "body": body,
			"overwrite": overwrite, "by_assistant": true,
		})
		return doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(payload)))
	}

	// First memory.
	code, b = write("coffee-preference", "The user takes espresso, no sugar",
		"The user drinks a double espresso in the morning, never with sugar.", false)
	if code != 201 {
		t.Fatalf("write memory: %d %s", code, b)
	}

	// A near-duplicate summary must surface the overlap (merge hygiene).
	code, b = write("espresso-note", "The user prefers espresso with no sugar",
		"Reminder: espresso only, no sugar.", false)
	if code != 201 {
		t.Fatalf("write memory 2: %d %s", code, b)
	}
	var wr struct {
		Overlaps []string `json:"overlaps"`
	}
	_ = json.Unmarshal(b, &wr)
	if len(wr.Overlaps) == 0 || wr.Overlaps[0] != "coffee-preference.md" {
		t.Fatalf("merge hygiene missed the overlap: %s", b)
	}

	// Re-writing the same name without overwrite is a conflict.
	if code, _ := write("coffee-preference", "x", "y", false); code != http.StatusConflict {
		t.Fatalf("re-write without overwrite: want 409, got %d", code)
	}
	// With overwrite it succeeds.
	if code, b := write("coffee-preference", "The user takes espresso, no sugar",
		"Updated: a double ristretto now.", true); code != 200 {
		t.Fatalf("overwrite: %d %s", code, b)
	}

	// get_memory: small corpus inlines whole (mode full, bodies present).
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/get_memory", owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID)))
	if code != 200 {
		t.Fatalf("get_memory: %d %s", code, b)
	}
	var mem struct {
		Mode     string `json:"mode"`
		Memories []struct {
			Name    string `json:"name"`
			Summary string `json:"summary"`
			Body    string `json:"body"`
		} `json:"memories"`
	}
	_ = json.Unmarshal(b, &mem)
	if mem.Mode != "full" || len(mem.Memories) != 2 {
		t.Fatalf("memory shape: %s", b)
	}
	if mem.Memories[0].Summary == "" || !strings.Contains(mem.Memories[0].Body, "ristretto") {
		t.Fatalf("memory body/summary missing: %s", b)
	}

	// get_folder_tree over the root shows the Memory folder.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/get_folder_tree", owner,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID)))
	if code != 200 {
		t.Fatalf("folder_tree root: %d %s", code, b)
	}
	var root struct {
		Folders []struct {
			NodeID string `json:"node_id"`
			Name   string `json:"name"`
		} `json:"folders"`
	}
	_ = json.Unmarshal(b, &root)
	var memFolder string
	for _, f := range root.Folders {
		if f.Name == "Memory" {
			memFolder = f.NodeID
		}
	}
	if memFolder == "" {
		t.Fatalf("Memory folder not in tree: %s", b)
	}

	// get_folder_tree over Memory/ lists the files with descriptions.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/get_folder_tree", owner,
		fmt.Sprintf(`{"tenant_id":%q,"folder_id":%q}`, tenant.ID, memFolder)))
	if code != 200 {
		t.Fatalf("folder_tree memory: %d %s", code, b)
	}
	var tree struct {
		Files []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"files"`
	}
	_ = json.Unmarshal(b, &tree)
	if len(tree.Files) != 2 {
		t.Fatalf("memory tree files: %s", b)
	}
	for _, f := range tree.Files {
		if f.Description == "" {
			t.Fatalf("memory file %q has no authored description: %s", f.Name, b)
		}
	}
}

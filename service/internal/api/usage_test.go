package api

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The storage gauge's breakdown: per top-level folder, and per app under
// AppData, each a subtree sum.
func TestQuotaBreakdownBySubtree(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	put := func(p, content string) {
		st, b, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path="+p, devAuth, content, map[string]string{"X-Drive-Parents": "create"})
		if st != 201 {
			t.Fatalf("put %s: %d %s", p, st, b)
		}
	}
	put("Docs/a.txt", strings.Repeat("x", 100))
	put("Docs/sub/b.txt", strings.Repeat("y", 50))
	put("AppData/Harness/notes.md", strings.Repeat("z", 30))
	put("AppData/Chat/log.jsonl", strings.Repeat("w", 20))
	put("root.txt", strings.Repeat("r", 7))

	resp, qb := doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/quota", devAuth, "")
	if resp.StatusCode != 200 {
		t.Fatalf("quota: %d %s", resp.StatusCode, qb)
	}
	var q struct {
		Used      int64 `json:"used_bytes"`
		Breakdown []struct {
			Name  string `json:"name"`
			Bytes int64  `json:"bytes"`
		} `json:"breakdown"`
		Apps []struct {
			Name  string `json:"name"`
			Bytes int64  `json:"bytes"`
		} `json:"apps"`
	}
	_ = json.Unmarshal(qb, &q)
	if q.Used != 207 {
		t.Fatalf("used %d", q.Used)
	}
	top := map[string]int64{}
	for _, e := range q.Breakdown {
		top[e.Name] = e.Bytes
	}
	if top["Docs"] != 150 || top["AppData"] != 50 || top["root.txt"] != 7 {
		t.Fatalf("breakdown %s", qb)
	}
	if len(q.Apps) != 2 || q.Apps[0].Name != "Harness" || q.Apps[0].Bytes != 30 || q.Apps[1].Bytes != 20 {
		t.Fatalf("apps %s", qb)
	}
}

// "Apps with access": app grants, with their folder and scope; a revoke
// removes the row.
func TestListAppsWithAccess(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	st, fb, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=AppData/Harness/x.txt", devAuth, "hi", map[string]string{"X-Drive-Parents": "create"})
	if st != 201 {
		t.Fatalf("put: %d %s", st, fb)
	}
	_, pb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=AppData/Harness", devAuth, "", nil)
	var folder struct{ ID string }
	_ = json.Unmarshal(pb, &folder)
	resp, gb := doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+folder.ID+"/grants", devAuth,
		fmt.Sprintf(`{"subject":"app:%s","scope":["read","write"],"binding_pubkey":"%s"}`, testAppID, testBindingKeyB64()))
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		t.Fatalf("grant: %d %s", resp.StatusCode, gb)
	}
	resp, ab := doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/apps", devAuth, "")
	if resp.StatusCode != 200 {
		t.Fatalf("apps: %d %s", resp.StatusCode, ab)
	}
	var lst struct {
		Apps []struct {
			GrantID string   `json:"grant_id"`
			AppID   string   `json:"app_id"`
			Folder  string   `json:"folder"`
			Scope   []string `json:"scope"`
		} `json:"apps"`
	}
	_ = json.Unmarshal(ab, &lst)
	if len(lst.Apps) != 1 || lst.Apps[0].AppID != testAppID || lst.Apps[0].Folder != "AppData/Harness" || len(lst.Apps[0].Scope) != 2 {
		t.Fatalf("apps list %s", ab)
	}
	st, _, _ = rawReq(t, "DELETE", ts.URL+"/v1/tenants/"+tenant.ID+"/grants/"+lst.Apps[0].GrantID, devAuth, "", nil)
	if st != 204 {
		t.Fatalf("revoke: %d", st)
	}
	_, ab = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/apps", devAuth, "")
	_ = json.Unmarshal(ab, &lst)
	if len(lst.Apps) != 0 {
		t.Fatalf("after revoke: %s", ab)
	}
}

// A workspace folder is flagged in listings and exports as the working tree
// its manifest describes; a missing blob is reported, not fatal.
func TestWorkspaceFlagAndExport(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	put := func(p, content string) {
		st, b, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path="+p, devAuth, content, map[string]string{"X-Drive-Parents": "create"})
		if st != 201 {
			t.Fatalf("put %s: %d %s", p, st, b)
		}
	}
	blob := func(content string) string {
		h := sha256.Sum256([]byte(content))
		return hex.EncodeToString(h[:])
	}
	main := "package main\n"
	readme := "# hello\n"
	ws := "AppData/Harness/workspace"
	put(ws+"/.blobs/"+blob(main), main)
	put(ws+"/.blobs/"+blob(readme), readme)
	mf := map[string]any{
		"version": 1, "app": testAppID, "saved_at": "2026-09-08T10:00:00Z",
		"files": []map[string]any{
			{"path": "src/main.go", "size": len(main), "mode": "0644", "blob": blob(main)},
			{"path": "README.md", "size": len(readme), "blob": blob(readme)},
			{"path": "../escape.txt", "size": 1, "blob": blob(main)},
			{"path": "lost.bin", "size": 3, "blob": strings.Repeat("0", 64)},
		},
	}
	raw, _ := json.Marshal(mf)
	put(ws+"/.workspace.json", string(raw))
	put("AppData/Harness/plain/note.txt", "n")

	// Listing of AppData/Harness flags the workspace folder, not the plain one.
	_, pb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=AppData/Harness", devAuth, "", nil)
	var folder struct{ ID string }
	_ = json.Unmarshal(pb, &folder)
	resp, lb := doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+folder.ID, devAuth, "")
	if resp.StatusCode != 200 {
		t.Fatalf("list: %d %s", resp.StatusCode, lb)
	}
	var kids []struct {
		ID                  string `json:"id"`
		Name                string `json:"name"`
		WorkspaceManifestID string `json:"workspace_manifest_id"`
	}
	_ = json.Unmarshal(lb, &kids)
	var wsID string
	for _, k := range kids {
		switch k.Name {
		case "workspace":
			if k.WorkspaceManifestID == "" {
				t.Fatalf("workspace folder not flagged: %s", lb)
			}
			wsID = k.ID
		case "plain":
			if k.WorkspaceManifestID != "" {
				t.Fatalf("plain folder flagged: %s", lb)
			}
		}
	}
	// Export rebuilds the tree.
	st, zb, hdr := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+wsID+"/workspace.zip", devAuth, "", nil)
	if st != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "application/zip") {
		t.Fatalf("zip: %d %s %s", st, hdr.Get("Content-Type"), zb)
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = string(b)
	}
	if got["src/main.go"] != main || got["README.md"] != readme {
		t.Fatalf("zip content %v", got)
	}
	if _, ok := got["../escape.txt"]; ok {
		t.Fatal("escaping path must be dropped")
	}
	if !strings.Contains(got["WORKSPACE-MISSING-BLOBS.txt"], "lost.bin") {
		t.Fatalf("missing blob not reported: %v", got)
	}
	// A plain folder is not exportable as a workspace.
	st, _, _ = rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+folder.ID+"/workspace.zip", devAuth, "", nil)
	if st != 404 {
		t.Fatalf("plain folder export: want 404, got %d", st)
	}
}

func testBindingKeyB64() string {
	pub, _, _ := ed25519.GenerateKey(nil)
	return base64.StdEncoding.EncodeToString(pub)
}

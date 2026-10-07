package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/config"
)

// TestAssistantOpensShareLinks: an assistant acting for a user opens a share
// link with open_link, and what it shares becomes readable through the
// assistant's tools, for that user only and only while the share stands.
func TestAssistantOpensShareLinks(t *testing.T) {
	_, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner, recipient, stranger = "user-1", "user-2", "user-3"
	const secret = "assistant-shared-secret"
	srv.InstallConfig(&config.Config{Mode: config.ModeSovereign, AssistantEnclaveToken: secret})

	// The owner's tenant: a folder holding one file.
	code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)
	code, b = doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/folders", ts.URL, tenant.ID), owner, `{"name":"Fundraising"}`))
	if code != 201 {
		t.Fatalf("folder: %d %s", code, b)
	}
	var folder nodeJSON
	_ = json.Unmarshal(b, &folder)
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=plan.md&mime=text/markdown&parent_id=%s", ts.URL, tenant.ID, folder.ID),
		bytes.NewReader([]byte("# Plan\nthe round is two million")))
	req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
	code, b = doReq(t, req)
	if code != 201 {
		t.Fatalf("file: %d %s", code, b)
	}
	var file nodeJSON
	_ = json.Unmarshal(b, &file)

	// The recipient has a Drive of their own (the shim resolves it).
	for _, u := range []string{recipient, stranger} {
		if code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/v1/me/tenant", u, "")); code != 200 && code != 201 {
			t.Fatalf("personal tenant %s: %d %s", u, code, b)
		}
	}

	mkLink := func(body string) (id, sec string) {
		code, b := doReq(t, bearerReq(t, "POST",
			fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenant.ID, folder.ID), owner, body))
		if code != 201 {
			t.Fatalf("create link: %d %s", code, b)
		}
		var l struct {
			ID     string `json:"id"`
			Secret string `json:"secret"`
		}
		_ = json.Unmarshal(b, &l)
		return l.ID, l.Secret
	}
	linkURL := func(id, sec string) string {
		return fmt.Sprintf("https://drive.privasys.org/l?id=%s&a=name#%s", id, sec)
	}
	call := func(user, tool string, args map[string]any) (int, map[string]any) {
		body, _ := json.Marshal(args)
		code, b := doReq(t, assistantReq(t, "POST", ts.URL+"/api/v1/mcp/tools/"+tool, secret, user, string(body)))
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		if out == nil {
			out = map[string]any{"raw": string(b)}
		}
		return code, out
	}

	// Before the link is opened, the shared file is out of reach.
	if code, _ := call(recipient, "read_file", map[string]any{"file_id": file.ID}); code == 200 {
		t.Fatalf("read before open_link succeeded")
	}

	// open_link on an open link: the user is granted, the assistant marked.
	id, sec := mkLink(`{"mode":"open","scope":["read"]}`)
	code, out := call(recipient, "open_link", map[string]any{"url": linkURL(id, sec)})
	if code != 200 || out["status"] != "granted" || out["node_id"] != folder.ID {
		t.Fatalf("open_link: %d %v", code, out)
	}
	// The user holds the share themselves, as a click would have given them.
	if code, _ := doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenant.ID, file.ID), recipient, "")); code != 200 {
		t.Fatalf("user read after assistant opened the link: %d", code)
	}

	// The shared folder and its file read through the assistant's tools,
	// which find the owner's tenant from the node id alone.
	if code, out := call(recipient, "get_folder_tree", map[string]any{"folder_id": folder.ID}); code != 200 || !strings.Contains(fmt.Sprint(out), "plan.md") {
		t.Fatalf("folder tree: %d %v", code, out)
	}
	if code, out := call(recipient, "read_file", map[string]any{"file_id": file.ID}); code != 200 || !strings.Contains(decoded(out), "two million") {
		t.Fatalf("read_file: %d %v", code, out)
	}
	if code, out := call(recipient, "list_shares", map[string]any{}); code != 200 || !strings.Contains(fmt.Sprint(out), "Fundraising") {
		t.Fatalf("list_shares: %d %v", code, out)
	}
	// Opening it again is harmless.
	if code, out := call(recipient, "open_link", map[string]any{"url": linkURL(id, sec)}); code != 200 || out["status"] != "granted" {
		t.Fatalf("second open_link: %d %v", code, out)
	}

	// Another user's assistant reads nothing of it.
	if code, _ := call(stranger, "read_file", map[string]any{"file_id": file.ID}); code == 200 {
		t.Fatalf("stranger's assistant read the share")
	}
	// A mark without the share grants nothing.
	if err := srv.markAssistantShare(context.Background(), tenant.ID, folder.ID, stranger); err != nil {
		t.Fatal(err)
	}
	if srv.assistantMayReadShared(context.Background(), stranger, tenant.ID, file.ID) {
		t.Fatalf("a mark alone let the assistant read")
	}

	// A link that requires an attribute: nothing is filed, and the assistant
	// is told what the user must share.
	id, sec = mkLink(`{"mode":"restricted","scope":["read"],"required_attributes":["name"]}`)
	code, out = call(stranger, "open_link", map[string]any{"url": linkURL(id, sec)})
	if code != 200 || out["status"] != linkMissingAttrs || !strings.Contains(fmt.Sprint(out["missing_attributes"]), "name") {
		t.Fatalf("restricted with attributes: %d %v", code, out)
	}

	// A link the owner approves person by person: pending, then readable
	// once approved, without opening the link again.
	id, sec = mkLink(`{"mode":"restricted","scope":["read"]}`)
	code, out = call(stranger, "open_link", map[string]any{"url": linkURL(id, sec)})
	if code != 200 || out["status"] != "pending" {
		t.Fatalf("approval link: %d %v", code, out)
	}
	if code, _ := call(stranger, "read_file", map[string]any{"file_id": file.ID}); code == 200 {
		t.Fatalf("read before the owner approved")
	}
	code, b = doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/link-requests?status=pending", ts.URL, tenant.ID), owner, ""))
	if code != 200 {
		t.Fatalf("list requests: %d %s", code, b)
	}
	var lr struct {
		Requests []struct {
			ID string `json:"id"`
		} `json:"requests"`
	}
	_ = json.Unmarshal(b, &lr)
	if len(lr.Requests) != 1 {
		t.Fatalf("requests: %s", b)
	}
	if code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/link-requests/%s/approve", ts.URL, tenant.ID, lr.Requests[0].ID), owner, "")); code != 200 {
		t.Fatalf("approve: %d %s", code, b)
	}
	if code, out := call(stranger, "read_file", map[string]any{"file_id": file.ID}); code != 200 || !strings.Contains(decoded(out), "two million") {
		t.Fatalf("read after approval: %d %v", code, out)
	}

	// A malformed link is refused plainly.
	if code, _ := call(recipient, "open_link", map[string]any{"url": "https://drive.privasys.org/l?id=x"}); code != http.StatusBadRequest {
		t.Fatalf("incomplete link: want 400, got %d", code)
	}
}

// decoded is read_file's content as text.
func decoded(out map[string]any) string {
	s, _ := out["content_base64"].(string)
	b, _ := base64.StdEncoding.DecodeString(s)
	return string(b)
}

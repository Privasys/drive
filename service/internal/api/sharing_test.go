package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// bearerReq builds an authenticated request for an arbitrary dev subject.
func bearerReq(t *testing.T, method, url, sub, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dev:"+sub+":"+sub+"@privasys.org")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// TestUserToUserShare covers the share lifecycle: a recipient cannot read
// an owner's file until the owner mints a subject grant, can read it while
// the grant is active, sees it in their inbox, and loses access the moment
// the grant is revoked.
func TestUserToUserShare(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	const recipient = "user-2"

	do := func(req *http.Request) (*http.Response, []byte) {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// Owner creates a tenant and uploads a file.
	resp, b := do(bearerReq(t, "POST", ts.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if resp.StatusCode != 201 {
		t.Fatalf("create tenant: %d %s", resp.StatusCode, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &tenant); err != nil {
		t.Fatal(err)
	}

	payload := []byte("shared secret document")
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=shared.txt&mime=text/plain", ts.URL, tenant.ID),
		bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
	resp, b = do(req)
	if resp.StatusCode != 201 {
		t.Fatalf("upload: %d %s", resp.StatusCode, b)
	}
	var node nodeJSON
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}

	fileURL := fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenant.ID, node.ID)

	// Recipient cannot read it before any share.
	if resp, _ := do(bearerReq(t, "GET", fileURL, recipient, "")); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("pre-share read: want 403, got %d", resp.StatusCode)
	}

	// Owner shares the node with the recipient (read scope).
	resp, b = do(bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/grants", ts.URL, tenant.ID, node.ID),
		owner, `{"subject":"subject:`+recipient+`","scope":["read"]}`))
	if resp.StatusCode != 201 {
		t.Fatalf("create grant: %d %s", resp.StatusCode, b)
	}
	var grant struct {
		ID string `json:"ID"`
	}
	if err := json.Unmarshal(b, &grant); err != nil {
		t.Fatal(err)
	}
	if grant.ID == "" {
		t.Fatalf("grant id empty: %s", b)
	}

	// Recipient can now read it, and the bytes match.
	resp, got := do(bearerReq(t, "GET", fileURL, recipient, ""))
	if resp.StatusCode != 200 {
		t.Fatalf("shared read: %d %s", resp.StatusCode, got)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("shared read mismatch: %q", got)
	}

	// The share appears in the recipient's inbox.
	resp, b = do(bearerReq(t, "GET", ts.URL+"/v1/shared", recipient, ""))
	if resp.StatusCode != 200 {
		t.Fatalf("inbox: %d %s", resp.StatusCode, b)
	}
	var inbox struct {
		Shared []sharedItem `json:"shared"`
	}
	if err := json.Unmarshal(b, &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Shared) != 1 || inbox.Shared[0].NodeID != node.ID || inbox.Shared[0].SharedBy != owner {
		t.Fatalf("inbox unexpected: %+v", inbox.Shared)
	}
	if inbox.Shared[0].Name != "shared.txt" {
		t.Fatalf("inbox name: %q", inbox.Shared[0].Name)
	}

	// Owner revokes the grant.
	resp, b = do(bearerReq(t, "DELETE",
		fmt.Sprintf("%s/v1/tenants/%s/grants/%s", ts.URL, tenant.ID, grant.ID), owner, ""))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", resp.StatusCode, b)
	}

	// Access is gone immediately.
	if resp, _ := do(bearerReq(t, "GET", fileURL, recipient, "")); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post-revoke read: want 403, got %d", resp.StatusCode)
	}
	// And the inbox is empty.
	resp, b = do(bearerReq(t, "GET", ts.URL+"/v1/shared", recipient, ""))
	if resp.StatusCode != 200 {
		t.Fatalf("inbox after revoke: %d %s", resp.StatusCode, b)
	}
	_ = json.Unmarshal(b, &inbox)
	inbox.Shared = nil
	if err := json.Unmarshal(b, &inbox); err != nil {
		t.Fatal(err)
	}
	if len(inbox.Shared) != 0 {
		t.Fatalf("inbox should be empty after revoke: %+v", inbox.Shared)
	}
}

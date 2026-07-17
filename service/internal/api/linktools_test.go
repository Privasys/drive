package api

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)

// TestLinkTools drives the whole share-link lifecycle through the
// manifest-tool surface: create (restricted) -> redeem with attributes
// -> list pending -> approve -> the requester reads the file. Same
// implementation as the REST handlers, so this locks the delegation
// plumbing (path-value injection + body rewrite).
func TestLinkTools(t *testing.T) {
	base, srv := newTestServer(t)
	// The shared harness mounts Routes() (/v1 only); the tool surface
	// lives on the full Handler.
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, payload := ownerTenantWithFile(t, base.URL, owner)

	// Create a restricted link via the tool.
	code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/tools/share_link_create", owner,
		fmt.Sprintf(`{"tenant_id":%q,"node_id":%q,"mode":"restricted","required_attributes":["name"]}`, tenantID, nodeID)))
	if code != 201 {
		t.Fatalf("share_link_create: %d %s", code, b)
	}
	var link struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &link); err != nil || link.ID == "" || link.Secret == "" {
		t.Fatalf("link response: %s", b)
	}

	// Redeem without the required attribute: no request filed.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/redeem_link", recipient,
		fmt.Sprintf(`{"link_id":%q,"secret":%q}`, link.ID, link.Secret)))
	if code != 403 {
		t.Fatalf("redeem without attributes: %d %s", code, b)
	}

	// Redeem with the attribute: pending request.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/redeem_link", recipient,
		fmt.Sprintf(`{"link_id":%q,"secret":%q,"attributes":{"name":"Bob Example"}}`, link.ID, link.Secret)))
	if code != 200 {
		t.Fatalf("redeem: %d %s", code, b)
	}
	var redeemed struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(b, &redeemed); err != nil || redeemed.Status != "pending" || redeemed.RequestID == "" {
		t.Fatalf("redeem response: %s", b)
	}

	// Owner lists pending via the tool.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/list_link_requests", owner,
		fmt.Sprintf(`{"tenant_id":%q,"status":"pending"}`, tenantID)))
	if code != 200 {
		t.Fatalf("list_link_requests: %d %s", code, b)
	}
	var listed struct {
		Requests []struct {
			ID string `json:"id"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(b, &listed); err != nil || len(listed.Requests) != 1 {
		t.Fatalf("pending list: %s", b)
	}

	// Approve via the tool; the recipient can now read.
	code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/decide_link_request", owner,
		fmt.Sprintf(`{"tenant_id":%q,"request_id":%q,"decision":"approve"}`, tenantID, redeemed.RequestID)))
	if code != 200 {
		t.Fatalf("decide: %d %s", code, b)
	}
	code, got := doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, nodeID), recipient, ""))
	if code != 200 || string(got) != string(payload) {
		t.Fatalf("post-approval read: %d %q", code, got)
	}
}

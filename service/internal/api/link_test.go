package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

// helper: run a request and return status + body.
func doReq(t *testing.T, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, b
}

// ownerTenantWithFile creates a user tenant owned by `owner` holding one
// text file, returning the tenant id, node id and the file's plaintext.
func ownerTenantWithFile(t *testing.T, url, owner string) (string, string, []byte) {
	t.Helper()
	code, b := doReq(t, bearerReq(t, "POST", url+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("create tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &tenant); err != nil {
		t.Fatal(err)
	}
	payload := []byte("link shared document")
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=shared.txt&mime=text/plain", url, tenant.ID),
		bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer dev:"+owner+":"+owner+"@privasys.org")
	code, b = doReq(t, req)
	if code != 201 {
		t.Fatalf("upload: %d %s", code, b)
	}
	var node nodeJSON
	if err := json.Unmarshal(b, &node); err != nil {
		t.Fatal(err)
	}
	return tenant.ID, node.ID, payload
}

// TestOpenLinkShare: a recipient redeems an open link and gains read
// access; a wrong secret is rejected; revoking the link blocks new
// redemptions.
func TestOpenLinkShare(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, recipient, other = "user-1", "user-2", "user-3"
	tenantID, nodeID, payload := ownerTenantWithFile(t, ts.URL, owner)
	fileURL := fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, nodeID)

	// Recipient cannot read before redeeming.
	if code, _ := doReq(t, bearerReq(t, "GET", fileURL, recipient, "")); code != http.StatusForbidden {
		t.Fatalf("pre-link read: want 403, got %d", code)
	}

	// Owner creates an open link.
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID),
		owner, `{"mode":"open","scope":["read"]}`))
	if code != 201 {
		t.Fatalf("create link: %d %s", code, b)
	}
	var link struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &link); err != nil {
		t.Fatal(err)
	}
	if link.ID == "" || link.Secret == "" {
		t.Fatalf("link id/secret empty: %s", b)
	}

	resolveURL := fmt.Sprintf("%s/v1/links/%s/resolve", ts.URL, link.ID)
	redeemURL := fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link.ID)

	// Wrong secret is rejected.
	if code, _ := doReq(t, bearerReq(t, "POST", resolveURL, recipient, `{"secret":"AAAA"}`)); code != http.StatusNotFound {
		t.Fatalf("bad-secret resolve: want 404, got %d", code)
	}

	// Resolve reveals the node metadata.
	code, b = doReq(t, bearerReq(t, "POST", resolveURL, recipient, `{"secret":"`+link.Secret+`"}`))
	if code != 200 {
		t.Fatalf("resolve: %d %s", code, b)
	}
	var meta struct {
		Mode string `json:"mode"`
		Node struct {
			Name string `json:"name"`
		} `json:"node"`
		AlreadyGranted bool `json:"already_granted"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Mode != "open" || meta.Node.Name != "shared.txt" || meta.AlreadyGranted {
		t.Fatalf("resolve unexpected: %s", b)
	}

	// Redeem grants access.
	code, b = doReq(t, bearerReq(t, "POST", redeemURL, recipient, `{"secret":"`+link.Secret+`"}`))
	if code != 200 {
		t.Fatalf("redeem: %d %s", code, b)
	}
	var rr struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(b, &rr)
	if rr.Status != "granted" {
		t.Fatalf("redeem status: %s", b)
	}

	// Recipient can now read the file.
	code, got := doReq(t, bearerReq(t, "GET", fileURL, recipient, ""))
	if code != 200 || !bytes.Equal(got, payload) {
		t.Fatalf("post-redeem read: %d %q", code, got)
	}

	// Redeeming again is idempotent.
	if code, _ := doReq(t, bearerReq(t, "POST", redeemURL, recipient, `{"secret":"`+link.Secret+`"}`)); code != 200 {
		t.Fatalf("re-redeem: %d", code)
	}

	// Owner revokes the link; a new user can no longer redeem it.
	code, _ = doReq(t, bearerReq(t, "DELETE",
		fmt.Sprintf("%s/v1/tenants/%s/grants/%s", ts.URL, tenantID, link.ID), owner, ""))
	if code != http.StatusNoContent {
		t.Fatalf("revoke link: %d", code)
	}
	if code, _ := doReq(t, bearerReq(t, "POST", redeemURL, other, `{"secret":"`+link.Secret+`"}`)); code != http.StatusNotFound {
		t.Fatalf("post-revoke redeem: want 404, got %d", code)
	}
}

// TestRestrictedLinkShare: redeeming a restricted link files a pending
// request that grants access only after the owner approves.
func TestRestrictedLinkShare(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, payload := ownerTenantWithFile(t, ts.URL, owner)
	fileURL := fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, nodeID)

	// Owner creates a restricted link requiring a name.
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID),
		owner, `{"mode":"restricted","scope":["read"],"required_attributes":["name"]}`))
	if code != 201 {
		t.Fatalf("create restricted link: %d %s", code, b)
	}
	var link struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &link); err != nil {
		t.Fatal(err)
	}

	// Redeeming WITHOUT the required attribute files nothing.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link.ID), recipient,
		`{"secret":"`+link.Secret+`"}`))
	if code != http.StatusForbidden {
		t.Fatalf("redeem without attrs: want 403, got %d %s", code, b)
	}

	// The owner can re-copy the link: the list returns the secret.
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID), owner, ""))
	if code != 200 {
		t.Fatalf("list links: %d %s", code, b)
	}
	var ll struct {
		Links []struct {
			Secret string `json:"secret"`
		} `json:"links"`
	}
	if err := json.Unmarshal(b, &ll); err != nil {
		t.Fatal(err)
	}
	if len(ll.Links) != 1 || ll.Links[0].Secret != link.Secret {
		t.Fatalf("list did not return the secret: %s", b)
	}

	// Recipient redeems with attributes -> pending, no access yet.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link.ID), recipient,
		`{"secret":"`+link.Secret+`","attributes":{"name":"Alice Example"}}`))
	if code != 200 {
		t.Fatalf("redeem restricted: %d %s", code, b)
	}
	var rr struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(b, &rr)
	if rr.Status != "pending" || rr.RequestID == "" {
		t.Fatalf("redeem restricted status: %s", b)
	}
	if code, _ := doReq(t, bearerReq(t, "GET", fileURL, recipient, "")); code != http.StatusForbidden {
		t.Fatalf("pre-approval read: want 403, got %d", code)
	}

	// Owner sees the pending request — by sub only. The presented
	// attributes ride out to the owner's wallet in the notification and
	// are never persisted on the drive (§7.6 PII boundary).
	code, b = doReq(t, bearerReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/link-requests?status=pending", ts.URL, tenantID), owner, ""))
	if code != 200 {
		t.Fatalf("list requests: %d %s", code, b)
	}
	var lr struct {
		Requests []struct {
			ID         string            `json:"id"`
			Requester  string            `json:"requester_sub"`
			Attributes map[string]string `json:"attributes"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(b, &lr); err != nil {
		t.Fatal(err)
	}
	if len(lr.Requests) != 1 || lr.Requests[0].Requester == "" {
		t.Fatalf("requests unexpected: %s", b)
	}
	if len(lr.Requests[0].Attributes) != 0 {
		t.Fatalf("attributes must not persist on the drive: %s", b)
	}

	// Owner approves -> recipient gains access.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/link-requests/%s/approve", ts.URL, tenantID, rr.RequestID), owner, ""))
	if code != 200 {
		t.Fatalf("approve: %d %s", code, b)
	}
	code, got := doReq(t, bearerReq(t, "GET", fileURL, recipient, ""))
	if code != 200 || !bytes.Equal(got, payload) {
		t.Fatalf("post-approval read: %d %q", code, got)
	}
}

// A restricted link with NO required attributes is pure owner-approval ("I
// approve each person"): redeem files a request with nothing to present, and
// only the owner's approval mints the grant. This is what the chat front's
// "Private" share uses.
func TestOwnerApprovalLinkShare(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, recipient = "user-1", "user-2"
	tenantID, nodeID, payload := ownerTenantWithFile(t, ts.URL, owner)
	fileURL := fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, nodeID)

	// Restricted with no attributes is accepted (owner-approval only).
	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, nodeID),
		owner, `{"mode":"restricted","scope":["read"]}`))
	if code != 201 {
		t.Fatalf("create owner-approval link: %d %s", code, b)
	}
	var link struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &link); err != nil {
		t.Fatal(err)
	}

	// Recipient redeems with no attributes -> pending, no access yet.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, link.ID), recipient,
		`{"secret":"`+link.Secret+`"}`))
	if code != 200 {
		t.Fatalf("redeem owner-approval: %d %s", code, b)
	}
	var rr struct {
		Status    string `json:"status"`
		RequestID string `json:"request_id"`
	}
	_ = json.Unmarshal(b, &rr)
	if rr.Status != "pending" || rr.RequestID == "" {
		t.Fatalf("redeem status: %s", b)
	}
	if code, _ := doReq(t, bearerReq(t, "GET", fileURL, recipient, "")); code != http.StatusForbidden {
		t.Fatalf("pre-approval read: want 403, got %d", code)
	}

	// Owner approves -> recipient gains access.
	code, b = doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/link-requests/%s/approve", ts.URL, tenantID, rr.RequestID), owner, ""))
	if code != 200 {
		t.Fatalf("approve: %d %s", code, b)
	}
	code, got := doReq(t, bearerReq(t, "GET", fileURL, recipient, ""))
	if code != 200 || !bytes.Equal(got, payload) {
		t.Fatalf("post-approval read: %d %q", code, got)
	}
}

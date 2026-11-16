package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// A one-off restricted link closes when the sharer approves its visitor.
// The visitor, waiting on the link page, still reaches it and sees the
// access; anyone else finds it gone.
func TestOneOffRestrictedLinkAfterApproval(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, visitor = "user-1", "user-2"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)
	l := createLink(t, ts.URL, tenantID, nodeID, owner, `{"mode":"restricted","scope":["read"],"required_attributes":["name"],"uses":"once"}`)
	body := `{"secret":"` + l["secret"].(string) + `","attributes":{"name":"Test Person"}}`
	call := func(op, who string) (int, map[string]any) {
		code, b := doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/links/%s/%s", ts.URL, l["id"], op), who, body))
		var out map[string]any
		_ = json.Unmarshal(b, &out)
		return code, out
	}

	code, out := call("redeem", visitor)
	if code != 200 || out["status"] != "pending" {
		t.Fatalf("redeem: %d %v", code, out)
	}
	code, b := doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/tenants/%s/link-requests/%s/approve", ts.URL, tenantID, out["request_id"]), owner, ""))
	if code != 200 {
		t.Fatalf("approve: %d %s", code, b)
	}

	if code, out := call("resolve", visitor); code != 200 || out["already_granted"] != true {
		t.Fatalf("visitor after approval: %d %v", code, out)
	}
	if code, out := call("redeem", visitor); code != 200 || out["status"] != "granted" {
		t.Fatalf("visitor redeem after approval: %d %v", code, out)
	}
	for _, op := range []string{"resolve", "redeem"} {
		if code, _ := call(op, "user-3"); code != http.StatusNotFound {
			t.Fatalf("someone else %s on a closed link: want 404, got %d", op, code)
		}
	}
}

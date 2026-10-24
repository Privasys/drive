package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// A visitor sees a link as shared by the name its sharer signed in with,
// never by a personal Drive's name; and the sharer sees what a visitor
// presented while the request waits, not after deciding it.
func TestSharerNameAndRequestDetails(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner, visitor = "user-1", "user-2"
	tenantID, nodeID, _ := ownerTenantWithFile(t, ts.URL, owner)

	resolveOwner := func(link map[string]any) string {
		t.Helper()
		code, b := doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/links/%s/resolve", ts.URL, link["id"]), visitor,
			`{"secret":"`+link["secret"].(string)+`"}`))
		if code != 200 {
			t.Fatalf("resolve: %d %s", code, b)
		}
		var r struct {
			OwnerName string `json:"owner_name"`
		}
		_ = json.Unmarshal(b, &r)
		return r.OwnerName
	}

	// Made before the sharer's name was recorded: no name rather than the
	// personal Drive's name.
	anon := createLink(t, ts.URL, tenantID, nodeID, owner, `{"mode":"open"}`)
	if got := resolveOwner(anon); got != "" {
		t.Fatalf("a personal Drive's name was shown: %q", got)
	}

	srv.Verifier = claimsVerifier{bySub: map[string]map[string]any{
		owner:   {"name": "Ada Sharer"},
		visitor: {"name": "Vic Visitor"},
	}}
	named := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","required_attributes":["name"]}`)
	if got := resolveOwner(named); got != "Ada Sharer" {
		t.Fatalf("shared by %q, want the sharer's name", got)
	}

	if code, b := doReq(t, bearerReq(t, "POST", fmt.Sprintf("%s/v1/links/%s/redeem", ts.URL, named["id"]), visitor,
		`{"secret":"`+named["secret"].(string)+`","attributes":{"name":"Vic Visitor"}}`)); code != 200 {
		t.Fatalf("redeem: %d %s", code, b)
	}
	list := func() []linkRequestView {
		t.Helper()
		code, b := doReq(t, bearerReq(t, "GET", fmt.Sprintf("%s/v1/tenants/%s/link-requests?status=", ts.URL, tenantID), owner, ""))
		if code != 200 {
			t.Fatalf("list: %d %s", code, b)
		}
		var out struct {
			Requests []linkRequestView `json:"requests"`
		}
		_ = json.Unmarshal(b, &out)
		return out.Requests
	}
	reqs := list()
	if len(reqs) != 1 || reqs[0].Attributes["name"] != "Vic Visitor" {
		t.Fatalf("the sharer cannot see what was presented: %+v", reqs)
	}
	if code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/link-requests/%s/approve", ts.URL, tenantID, reqs[0].ID), owner, "")); code != http.StatusOK {
		t.Fatalf("approve: %d %s", code, b)
	}
	for _, r := range list() {
		if len(r.Attributes) != 0 || strings.Contains(fmt.Sprint(r.Attributes), "Vic") {
			t.Fatalf("details kept after the decision: %+v", r)
		}
	}
}

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A visitor never sees a personal Drive's name (its owner's subject), and
// Drive keeps no sharer's name to show instead. The sharer sees what a
// visitor presented while the request waits, not after deciding it, nor
// once requestDetailsRetention has passed.
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

	srv.Verifier = claimsVerifier{bySub: map[string]map[string]any{
		owner:   {"name": "Ada Sharer"},
		visitor: {"name": "Vic Visitor"},
	}}
	named := createLink(t, ts.URL, tenantID, nodeID, owner,
		`{"mode":"restricted","required_attributes":["name"]}`)
	if got := resolveOwner(named); got != "" {
		t.Fatalf("shared by %q, want no name", got)
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
	// Nobody decides for a week: the sweep clears them.
	if n, err := srv.Store.ClearStaleRequestDetails(context.Background(), time.Now().Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("stale details cleared: %d %v", n, err)
	}
	if r := list(); len(r[0].Attributes) != 0 {
		t.Fatalf("details kept past retention: %+v", r)
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

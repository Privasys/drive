package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestWorkspaceMembers: list/add/change-role/remove on an enterprise
// tenant, with the last-owner guard.
func TestWorkspaceMembers(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner, alice = "user-1", "user-2"

	code, b := doReq(t, bearerReq(t, "POST", ts.URL+"/v1/tenants", owner,
		`{"kind":"enterprise","name":"Acme"}`))
	if code != 201 {
		t.Fatalf("create workspace: %d %s", code, b)
	}
	var ws struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &ws); err != nil {
		t.Fatal(err)
	}
	membersURL := fmt.Sprintf("%s/v1/tenants/%s/members", ts.URL, ws.ID)

	// Add alice as reader.
	if code, b := doReq(t, bearerReq(t, "POST", membersURL, owner,
		`{"user_sub":"`+alice+`","role":"reader"}`)); code != http.StatusNoContent {
		t.Fatalf("add member: %d %s", code, b)
	}

	// Any member can list; the list carries both.
	code, b = doReq(t, bearerReq(t, "GET", membersURL, alice, ""))
	if code != 200 {
		t.Fatalf("list members: %d %s", code, b)
	}
	var lm struct {
		Members []struct {
			Sub  string `json:"sub"`
			Role string `json:"role"`
		} `json:"members"`
	}
	if err := json.Unmarshal(b, &lm); err != nil {
		t.Fatal(err)
	}
	if len(lm.Members) != 2 {
		t.Fatalf("members: %s", b)
	}

	// A reader cannot change roles.
	if code, _ := doReq(t, bearerReq(t, "PATCH", membersURL+"/"+alice, alice,
		`{"role":"admin"}`)); code != http.StatusForbidden {
		t.Fatalf("reader role change: want 403, got %d", code)
	}
	// The owner promotes alice to admin.
	if code, b := doReq(t, bearerReq(t, "PATCH", membersURL+"/"+alice, owner,
		`{"role":"admin"}`)); code != http.StatusNoContent {
		t.Fatalf("promote: %d %s", code, b)
	}

	// The last owner cannot be demoted or removed.
	if code, _ := doReq(t, bearerReq(t, "PATCH", membersURL+"/"+owner, owner,
		`{"role":"reader"}`)); code != http.StatusConflict {
		t.Fatalf("demote last owner: want 409, got %d", code)
	}
	if code, _ := doReq(t, bearerReq(t, "DELETE", membersURL+"/"+owner, owner, "")); code != http.StatusConflict {
		t.Fatalf("remove last owner: want 409, got %d", code)
	}

	// Alice leaves herself.
	if code, _ := doReq(t, bearerReq(t, "DELETE", membersURL+"/"+alice, alice, "")); code != http.StatusNoContent {
		t.Fatalf("self-leave: want 204, got %d", code)
	}
	code, b = doReq(t, bearerReq(t, "GET", membersURL, owner, ""))
	_ = json.Unmarshal(b, &lm)
	if len(lm.Members) != 1 || lm.Members[0].Sub != owner {
		t.Fatalf("after leave: %s", b)
	}
}

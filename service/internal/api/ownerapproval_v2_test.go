package api

import (
	"encoding/json"
	"testing"

	"github.com/Privasys/drive/service/internal/vaultmek"
	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// body is the approval request as the caller sends it to privasys.id.
func body(t *testing.T, handle, audience string, plan *vaultmek.TeesApprovalV2) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(approvalRequest(handle, audience, plan))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

// A binding-v2 approval request is an update_policy bound to the exact new
// policy, its digest, the version replaced and the members.
func TestApprovalRequestBindingV2Body(t *testing.T) {
	plan := &vaultmek.TeesApprovalV2{
		NewPolicyJSON: json.RawMessage(`{"version":1}`), Target: "ab", PolicyVersion: 3,
		Members:    []string{"m1", "m2"},
		Identities: []vsdk.VaultIdentity{{MemberID: "m1"}, {MemberID: "m2"}},
	}
	got := body(t, "h", "aud", plan)
	want := map[string]string{
		"binding_version": `2`, "operation": `"update_policy"`, "handle": `"h"`,
		"target": `"ab"`, "policy_version": `3`, "members": `["m1","m2"]`,
		"issuer_index": `0`, "new_policy": `{"version":1}`, "audience": `"aud"`,
		"context": `{"app_name":"Privasys Drive","key_type":"Your Drive key","source":"Privasys Drive was updated; approve the new version to keep opening your files.","summary":"Let Privasys Drive open your Drive key with its updated build."}`,
	}
	for k, v := range want {
		if string(got[k]) != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if len(got["member_identities"]) == 0 {
		t.Error("member_identities missing")
	}

	got = body(t, "h", "", nil)
	if string(got["operation"]) != `"policy-update"` || got["binding_version"] != nil || got["audience"] != nil {
		t.Errorf("v1 body changed: %v", got)
	}
}

// On update_policy_from the request also carries the policy replaced.
func TestApprovalRequestUpdatePolicyFromBody(t *testing.T) {
	plan := &vaultmek.TeesApprovalV2{
		NewPolicyJSON: json.RawMessage(`{"version":2}`), Target: "cd", PolicyVersion: 3,
		Members: []string{"m1"}, Identities: []vsdk.VaultIdentity{{MemberID: "m1"}},
		From: true, CurrentPolicyJSON: json.RawMessage(`{"version":1}`), ReplacedPD: "ee",
	}
	got := body(t, "h", "", plan)
	for k, v := range map[string]string{
		"operation": `"update_policy_from"`, "current_policy": `{"version":1}`,
		"new_policy": `{"version":2}`, "target": `"cd"`, "policy_version": `3`,
	} {
		if string(got[k]) != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if got["replaced_pd"] != nil {
		t.Error("replaced_pd goes to the vault, not the IdP")
	}
}

func TestIsApprovalToken(t *testing.T) {
	if !isApprovalToken(testJWT(`{"vault_op":"op"}`)) {
		t.Error("an operation-bound token is an approval token")
	}
	for _, tok := range []string{testJWT(`{"sub":"s"}`), testJWT(`{"vault_op":""}`), "x.y", ""} {
		if isApprovalToken(tok) {
			t.Errorf("%q is not an approval token", tok)
		}
	}
}

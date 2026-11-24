package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Privasys/drive/service/internal/vaultmek"
	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// A binding-v2 approval asks the IdP for an update_policy bound to the exact
// new policy, its digest, the version replaced and the members.
func TestApprovalBeginBindingV2Body(t *testing.T) {
	var got map[string]json.RawMessage
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fido2/vault-approval/begin" {
			t.Errorf("path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_ = json.NewEncoder(w).Encode(map[string]any{"vault_op": "op", "push_registered": true})
	}))
	defer srv.Close()
	t.Setenv("PRIVASYS_ISSUER", srv.URL)
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = old }()

	policy := json.RawMessage(`{"version":1}`)
	plan := &vaultmek.TeesApprovalV2{
		NewPolicyJSON: policy, Target: "ab", PolicyVersion: 3,
		Members:    []string{"m1", "m2"},
		Identities: []vsdk.VaultIdentity{{MemberID: "m1"}, {MemberID: "m2"}},
	}
	if _, _, err := idpApprovalBegin(context.Background(), "bearer", "h", "aud", plan); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"binding_version": `2`, "operation": `"update_policy"`, "handle": `"h"`,
		"target": `"ab"`, "policy_version": `3`, "members": `["m1","m2"]`,
		"issuer_index": `0`, "new_policy": `{"version":1}`, "audience": `"aud"`,
	}
	for k, v := range want {
		if string(got[k]) != v {
			t.Errorf("%s = %s, want %s", k, got[k], v)
		}
	}
	if len(got["member_identities"]) == 0 {
		t.Error("member_identities missing")
	}

	got = nil
	if _, _, err := idpApprovalBegin(context.Background(), "bearer", "h", "", nil); err != nil {
		t.Fatal(err)
	}
	if string(got["operation"]) != `"policy-update"` || got["binding_version"] != nil || got["audience"] != nil {
		t.Errorf("v1 body changed: %v", got)
	}
}

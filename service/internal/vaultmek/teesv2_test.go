package vaultmek

import (
	"testing"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

func TestNeedsBindingV2(t *testing.T) {
	v2 := vsdk.Condition{OidcStepUp: &vsdk.OidcStepUpCond{RequiredAmr: []string{"webauthn"}, OperationBound: true, Binding: 2}}
	v1 := vsdk.Condition{OidcStepUp: &vsdk.OidcStepUpCond{RequiredAmr: []string{"webauthn"}, OperationBound: true}}
	owner := []vsdk.PrincipalRef{{Owner: true}}
	cases := []struct {
		name string
		ops  []vsdk.OperationRule
		want bool
	}{
		{"today's key: update without approval", []vsdk.OperationRule{{Ops: []vsdk.Operation{vsdk.OpDeleteKey, vsdk.OpUpdatePolicy}, Principals: owner}}, false},
		{"v1 step-up on update", []vsdk.OperationRule{{Ops: []vsdk.Operation{vsdk.OpUpdatePolicy}, Principals: owner, Requires: []vsdk.Condition{v1}}}, false},
		{"v2 only on export", []vsdk.OperationRule{{Ops: []vsdk.Operation{vsdk.OpExportKey}, Principals: owner, Requires: []vsdk.Condition{v2}}}, false},
		{"v2 on update", []vsdk.OperationRule{{Ops: []vsdk.Operation{vsdk.OpDeleteKey, vsdk.OpUpdatePolicy}, Principals: owner, Requires: []vsdk.Condition{v2}}}, true},
	}
	for _, c := range cases {
		if got := NeedsBindingV2(vsdk.KeyPolicy{Operations: c.ops}); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

package api

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Privasys/drive/service/internal/vaultmek"
)

// recorderMEKs answers ReadStoredPolicy: the policy, or readErr (a key the
// running build can no longer open).
type recorderMEKs struct {
	*perHandleMEKs
	readErr error
	reads   int
}

func (f *recorderMEKs) ReadStoredPolicy(context.Context, vaultmek.Ref) (json.RawMessage, uint32, error) {
	f.reads++
	if f.readErr != nil {
		return nil, 0, f.readErr
	}
	return json.RawMessage(`{"principals":{}}`), 4, nil
}

// TestEagerPolicyRecord proves the pass fills a missing record from the
// vaults' answer, leaves a present one alone, lists a key it cannot read
// without guessing, and the records route reports "all recorded" only when
// every key has one.
func TestEagerPolicyRecord(t *testing.T) {
	ts, srv := newTestServer(t)
	base := newPerHandleMEKs()
	mek := base.seed(sweepOldHandle)
	fake := &recorderMEKs{perHandleMEKs: base, readErr: errors.New("vault error: caller is not in policy.principals")}
	srv.MEKs = fake
	tenantID := createTenantForSweep(t, ts)
	ref := vaultmek.Ref{Handle: sweepOldHandle, Endpoints: []string{"https://v:1"}, MrenclaveHex: "00", Threshold: 1}
	if _, err := srv.switchTenantMEK(context.Background(), tenantID, srv.MEK, mek, ref); err != nil {
		t.Fatal(err)
	}

	var state struct {
		Total       int      `json:"total"`
		Recorded    int      `json:"recorded"`
		Missing     []string `json:"missing"`
		AllRecorded bool     `json:"all_recorded"`
		V1          int      `json:"binding_v1"`
		V2          int      `json:"binding_v2"`
	}
	// The build cannot read it: listed, nothing recorded.
	pass := srv.recordAllKeyPolicies(context.Background())
	if pass.Filled != 0 || len(pass.Failed) != 1 {
		t.Fatalf("unreadable key: %+v", pass)
	}
	_ = json.Unmarshal([]byte(doOperatorGet(t, ts, "/v1/admin/tenant-keys/records")), &state)
	if state.AllRecorded || state.Recorded != 0 || len(state.Missing) != 1 {
		t.Fatalf("before: %+v", state)
	}

	// Readable: filled from the vaults' answer, with its version.
	fake.readErr = nil
	pass = srv.recordAllKeyPolicies(context.Background())
	if pass.Filled != 1 || len(pass.Failed) != 0 {
		t.Fatalf("readable key: %+v", pass)
	}
	raw, _ := srv.Store.TenantMekRef(context.Background(), tenantID)
	got, _ := vaultmek.ParseRef(raw)
	if string(got.Policy) != `{"principals":{}}` || got.PolicyVersion != 4 {
		t.Fatalf("record: %s v%d", got.Policy, got.PolicyVersion)
	}
	_ = json.Unmarshal([]byte(doOperatorGet(t, ts, "/v1/admin/tenant-keys/records")), &state)
	if !state.AllRecorded || state.Recorded != 1 || state.V1 != 1 || state.V2 != 0 {
		t.Fatalf("after: %+v", state)
	}

	// Already present: not read again.
	reads := fake.reads
	pass = srv.recordAllKeyPolicies(context.Background())
	if pass.Present != 1 || fake.reads != reads {
		t.Fatalf("present key re-read: %+v", pass)
	}
}

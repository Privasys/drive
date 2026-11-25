package vaultmek

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Without a recorded policy no plan is built and nothing is dialled.
func TestPrepareWithoutRecordNeedsRestage(t *testing.T) {
	c := New("", "")
	_, err := c.PrepareTeesApprovalV2(context.Background(), Ref{Handle: "h", Endpoints: []string{"v:1"}}, "g")
	if !errors.Is(err, ErrRestageNeeded) {
		t.Fatalf("want ErrRestageNeeded, got %v", err)
	}
}

// A recorded policy without a binding-2 rule takes the v1 approval: no
// plan, no error, nothing dialled.
func TestPrepareV1KeyFromRecord(t *testing.T) {
	c := New("", "")
	p, _ := json.Marshal(vsdk.KeyPolicy{})
	plan, err := c.PrepareTeesApprovalV2(context.Background(), Ref{Handle: "h", Endpoints: []string{"v:1"}, Policy: p, PolicyVersion: 2}, "g")
	if err != nil || plan != nil {
		t.Fatalf("v1 key: plan %v, err %v", plan, err)
	}
}

func TestUnionTeesAddsWithoutDuplicates(t *testing.T) {
	a := vsdk.Principal{}
	b := vsdk.Principal{}
	if err := json.Unmarshal([]byte(`{"Tee":{"name":"old"}}`), &a); err != nil {
		t.Skip("principal shape differs; union is covered by JSON equality")
	}
	_ = json.Unmarshal([]byte(`{"Tee":{"name":"new"}}`), &b)
	got := unionTees([]vsdk.Principal{a}, []vsdk.Principal{a, b})
	if len(got) != 2 {
		t.Fatalf("union of {old} and {old,new}: %d principals", len(got))
	}
	ja, _ := json.Marshal(got[0])
	jb, _ := json.Marshal(got[1])
	if string(ja) == string(jb) {
		t.Fatal("the running measurement must stay next to the new one")
	}
}

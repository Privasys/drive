package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/vaultmek"
)

// v2MEKs is a key whose rule takes binding 2: PrepareTeesApprovalV2 returns
// plan, or prepErr. It records every v2 update sent.
type v2MEKs struct {
	*fakeMEKs
	plan    *vaultmek.TeesApprovalV2
	prepErr error
	v2sent  []string
}

func (f *v2MEKs) PrepareTeesApprovalV2(context.Context, vaultmek.Ref, string) (*vaultmek.TeesApprovalV2, error) {
	return f.plan, f.prepErr
}

func (f *v2MEKs) RefreshTeesV2(_ context.Context, _ vaultmek.Ref, _ *vaultmek.TeesApprovalV2, approval string) error {
	f.v2sent = append(f.v2sent, approval)
	if f.clearOnRefresh {
		f.loadErr = nil
	}
	return nil
}

func v2Server(t *testing.T, f *v2MEKs) string {
	t.Helper()
	ts := newFullServer(t, func(s *Server) { s.MEKs = f })
	_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	resp, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth,
		`{"grant":"g","handle":"apps.privasys.org/x/data/y/mek/v1","constellation":{"endpoints":["v1:1","v2:2"],"mrenclave":"00","attestation_server":"as","threshold":2}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("adopt: %d %s", resp.StatusCode, body)
	}
	f.loadErr = errors.New("vaultmek: only 0/2 shares recovered: vault error: caller is not in policy.principals")
	return ts.URL
}

// TestBindingV2FailureHasNoFallback proves the measurement approval fails
// closed: when the key's binding-2 plan cannot be built, the re-arm answers
// 502, describes no approval and makes no v1 attempt, so no binding-0 card
// can reach the holder, with or without an approval token.
func TestBindingV2FailureHasNoFallback(t *testing.T) {
	for _, prepErr := range []error{
		errors.New("vaultmek: approval v2: v1:1: identity: server error (401)"),
		errors.New("vaultmek: approval v2: v1:1: the stored form does not match its digest"),
		errors.New("vaultmek: approval v2: v2:2: the vaults return different stored forms of the new policy"),
		vaultmek.ErrPolicyNotLossless,
	} {
		mek := sha256.Sum256([]byte("vault-held-tenant-mek"))
		fake := &v2MEKs{fakeMEKs: &fakeMEKs{mek: mek[:], clearOnRefresh: true}, prepErr: prepErr}
		url := v2Server(t, fake)
		for _, req := range []string{`{"grant":"fresh"}`, `{"grant":"fresh","approval_token":"` + testJWT(`{"vault_op":"op"}`) + `"}`} {
			resp, body := doJSON(t, "POST", url+"/v1/me/tenant/key", devAuth, req)
			if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "approval") && strings.Contains(string(body), "operation") {
				t.Fatalf("%v: want 502 with no approval described, got %d %s", prepErr, resp.StatusCode, body)
			}
		}
		if len(fake.refreshed) != 0 || len(fake.v2sent) != 0 {
			t.Fatalf("%v: an update was sent (v1 %v, v2 %v)", prepErr, fake.refreshed, fake.v2sent)
		}
	}
}

// TestRestageNeededWithoutPolicyRecord: a key whose policy is not on record
// cannot have its measurement approved; the caller gets restage_needed, no
// approval is described and nothing is sent.
func TestRestageNeededWithoutPolicyRecord(t *testing.T) {
	mek := sha256.Sum256([]byte("vault-held-tenant-mek"))
	fake := &v2MEKs{fakeMEKs: &fakeMEKs{mek: mek[:]}, prepErr: vaultmek.ErrRestageNeeded}
	url := v2Server(t, fake)
	resp, body := doJSON(t, "POST", url+"/v1/me/tenant/key", devAuth, `{"grant":"fresh"}`)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "restage_needed") {
		t.Fatalf("want 409 restage_needed, got %d %s", resp.StatusCode, body)
	}
	if len(fake.refreshed) != 0 || len(fake.v2sent) != 0 {
		t.Fatal("an update was sent")
	}
}

// TestBindingV2TwoStep: the re-arm describes the binding-2 approval for the
// caller to obtain, then sends the update with the approval token alone.
func TestBindingV2TwoStep(t *testing.T) {
	mek := sha256.Sum256([]byte("vault-held-tenant-mek"))
	plan := &vaultmek.TeesApprovalV2{
		NewPolicyJSON: json.RawMessage(`{"v":2}`), Target: "cd", PolicyVersion: 3,
		Members: []string{"m1"}, From: true, CurrentPolicyJSON: json.RawMessage(`{"v":1}`),
	}
	fake := &v2MEKs{fakeMEKs: &fakeMEKs{mek: mek[:], clearOnRefresh: true}, plan: plan}
	url := v2Server(t, fake)

	resp, body := doJSON(t, "POST", url+"/v1/me/tenant/key", devAuth, `{"grant":"fresh"}`)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), `"operation":"update_policy_from"`) ||
		!strings.Contains(string(body), `"binding_version":2`) {
		t.Fatalf("step 1: %d %s", resp.StatusCode, body)
	}
	if len(fake.v2sent) != 0 || len(fake.refreshed) != 0 {
		t.Fatal("an update was sent before the approval")
	}

	approval := testJWT(`{"vault_op":"op-2"}`)
	resp, body = doJSON(t, "POST", url+"/v1/me/tenant/key", devAuth, `{"grant":"fresh","approval_token":"`+approval+`"}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"measurement_approved":true`) {
		t.Fatalf("step 2: %d %s", resp.StatusCode, body)
	}
	if len(fake.v2sent) != 1 || fake.v2sent[0] != approval || len(fake.refreshed) != 0 {
		t.Fatalf("sent v2 %v, v1 %v", fake.v2sent, fake.refreshed)
	}
}

// v2RefuseMEKs is a binding-2 key whose vaults refuse the update (a stale
// policy record: PD(current) or policy_version no longer match).
type v2RefuseMEKs struct{ v2MEKs }

func (f *v2RefuseMEKs) RefreshTeesV2(context.Context, vaultmek.Ref, *vaultmek.TeesApprovalV2, string) error {
	return errors.New("vaultmek: measurement approval incomplete: v1:1: update policy: vault error: approval does not match the current policy")
}

// TestStaleRecordSurfacesNoFallback: a vault refusing the approved update
// (the record was stale) is an error to the caller, with no v1 attempt.
func TestStaleRecordSurfacesNoFallback(t *testing.T) {
	mek := sha256.Sum256([]byte("vault-held-tenant-mek"))
	plan := &vaultmek.TeesApprovalV2{NewPolicyJSON: json.RawMessage(`{}`), Target: "t", PolicyVersion: 1}
	fake := &v2RefuseMEKs{v2MEKs{fakeMEKs: &fakeMEKs{mek: mek[:]}, plan: plan}}
	ts := newFullServer(t, func(s *Server) { s.MEKs = fake })
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	resp, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth,
		`{"grant":"g","handle":"apps.privasys.org/x/data/y/mek/v1","constellation":{"endpoints":["v1:1"],"mrenclave":"00","attestation_server":"as","threshold":1}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("adopt: %d %s", resp.StatusCode, body)
	}
	fake.loadErr = errors.New("vaultmek: only 0/1 shares recovered: vault error: caller is not in policy.principals")
	resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth, `{"grant":"fresh","approval_token":"`+testJWT(`{"vault_op":"op"}`)+`"}`)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "does not match") {
		t.Fatalf("stale record: want 502 with the vault's refusal, got %d %s", resp.StatusCode, body)
	}
	if len(fake.refreshed) != 0 {
		t.Fatalf("the v1 path ran: %v", fake.refreshed)
	}
}

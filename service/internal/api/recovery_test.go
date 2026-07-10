package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/store"
)

// escrowedServer boots a full escrowed instance with a fake vault and
// the given recovery policy JSON fragment.
func escrowedServer(t *testing.T, recovery string) (tsURL string, holder *Server) {
	t.Helper()
	h := struct{ s *Server }{}
	ts := newFullServer(t, func(s *Server) {
		s.MEKs = &fakeMEKs{mek: make([]byte, 32)}
		h.s = s
	})
	orgRef := `{"handle":"apps.privasys.org/x/org/mek/v1","endpoints":["v:1"],"threshold":1}`
	cfgBody := `{"mode":"escrowed","org_mek_ref":` + strconv.Quote(orgRef) + `,"recovery":` + recovery + `}`
	resp, body := doJSON(t, "POST", ts.URL+"/configure", devAuth, cfgBody)
	if resp.StatusCode != 200 {
		t.Fatalf("configure escrowed: %d %s", resp.StatusCode, body)
	}
	return ts.URL, h.s
}

// TestRecoveryGateLifecycle drives the full escrowed recovery: request
// by a permitted requester, k-of-n approvals with duplicate rejection,
// execution minting a time-bounded tenant-wide read grant, disclosure,
// and the grantee actually reading the data.
func TestRecoveryGateLifecycle(t *testing.T) {
	url, srv := escrowedServer(t,
		`{"issuer":"https://acme.example","quorum":2,"approvers":["appr-a","appr-b","appr-c"],"requesters":["req-1"]}`)

	// Owner sets up a tenant with a vault MEK (escrow-wrapped) + a file.
	_, body := doJSON(t, "POST", url+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	resp, body := doJSON(t, "POST", url+"/v1/me/tenant/key", devAuth,
		`{"grant":"g","handle":"h","constellation":{"endpoints":["v:1"],"mrenclave":"00","attestation_server":"as","threshold":1}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("provision: %d %s", resp.StatusCode, body)
	}
	content := base64.StdEncoding.EncodeToString([]byte("escrowed secret payload"))
	resp, body = doJSON(t, "POST", url+"/tools/write_file", devAuth,
		fmt.Sprintf(`{"tenant_id":%q,"name":"doc.txt","content_base64":%q}`, tenant.ID, content))
	if resp.StatusCode != 200 {
		t.Fatalf("upload: %d %s", resp.StatusCode, body)
	}
	var node struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &node)

	granteeAuth := "Bearer dev:rescuer:rescuer@acme.example"
	readBody := fmt.Sprintf(`{"tenant_id":%q,"file_id":%q}`, tenant.ID, node.ID)

	// Before recovery the grantee can read nothing.
	if resp, _ := doJSON(t, "POST", url+"/tools/read_file", granteeAuth, readBody); resp.StatusCode != 403 {
		t.Fatalf("pre-recovery read: want 403, got %d", resp.StatusCode)
	}

	// A non-requester cannot file a recovery.
	reqBody := fmt.Sprintf(`{"tenant_id":%q,"reason":"legal hold 42","grantee_sub":"rescuer","ttl_seconds":3600}`, tenant.ID)
	if resp, _ := doJSON(t, "POST", url+"/tools/request_recovery", "Bearer dev:rando:r@x", reqBody); resp.StatusCode != 403 {
		t.Fatalf("request by rando: want 403, got %d", resp.StatusCode)
	}
	// An approver may not request either (requesters list is set).
	if resp, _ := doJSON(t, "POST", url+"/tools/request_recovery", "Bearer dev:appr-a:a@x", reqBody); resp.StatusCode != 403 {
		t.Fatalf("request by approver with requester list set: want 403, got %d", resp.StatusCode)
	}
	resp, body = doJSON(t, "POST", url+"/tools/request_recovery", "Bearer dev:req-1:rq@x", reqBody)
	if resp.StatusCode != 200 {
		t.Fatalf("request: %d %s", resp.StatusCode, body)
	}
	var rec struct {
		RecoveryID string `json:"recovery_id"`
		DigestHex  string `json:"digest_hex"`
	}
	_ = json.Unmarshal(body, &rec)
	if rec.RecoveryID == "" || rec.DigestHex == "" {
		t.Fatalf("request response: %s", body)
	}

	approve := func(auth, token string) (*http.Response, []byte) {
		return doJSON(t, "POST", url+"/tools/approve_recovery", auth,
			fmt.Sprintf(`{"tenant_id":%q,"recovery_id":%q,"approval_token":%q}`, tenant.ID, rec.RecoveryID, token))
	}

	// A non-approver token is rejected.
	if resp, _ := approve(devAuth, "dev:rando:r@x"); resp.StatusCode != 403 {
		t.Fatalf("non-approver approval: want 403, got %d", resp.StatusCode)
	}
	// First approval: 1/2, still pending.
	resp, body = approve(devAuth, "dev:appr-a:a@x")
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"approvals":1`) {
		t.Fatalf("first approval: %d %s", resp.StatusCode, body)
	}
	// The same token cannot approve twice.
	if resp, _ := approve(devAuth, "dev:appr-a:a@x"); resp.StatusCode != 409 {
		t.Fatalf("replayed approval: want 409, got %d", resp.StatusCode)
	}
	// The same approver with a different token cannot count twice.
	if resp, _ := approve(devAuth, "dev:appr-a:other@x"); resp.StatusCode != 409 {
		t.Fatalf("duplicate approver: want 409, got %d", resp.StatusCode)
	}
	// Second distinct approver reaches the quorum and executes.
	resp, body = approve(devAuth, "dev:appr-b:b@x")
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"status":"executed"`) {
		t.Fatalf("quorum approval: %d %s", resp.StatusCode, body)
	}
	var executed struct {
		GrantID string `json:"grant_id"`
	}
	_ = json.Unmarshal(body, &executed)
	if executed.GrantID == "" {
		t.Fatalf("no grant id: %s", body)
	}

	// The grantee now reads the tenant's data (tenant-wide grant).
	resp, body = doJSON(t, "POST", url+"/tools/read_file", granteeAuth, readBody)
	if resp.StatusCode != 200 || !strings.Contains(string(body), content) {
		t.Fatalf("post-recovery read: %d %s", resp.StatusCode, body)
	}
	// Root listing works too.
	resp, body = doJSON(t, "POST", url+"/tools/list_root", granteeAuth,
		fmt.Sprintf(`{"tenant_id":%q}`, tenant.ID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), "doc.txt") {
		t.Fatalf("post-recovery list: %d %s", resp.StatusCode, body)
	}

	// Further approvals on an executed recovery are refused.
	if resp, _ := approve(devAuth, "dev:appr-c:c@x"); resp.StatusCode != 409 {
		t.Fatalf("approval after execute: want 409, got %d", resp.StatusCode)
	}

	// Disclosure: the tenant's audit shows the full trail.
	resp, body = doJSON(t, "GET", url+"/v1/tenants/"+tenant.ID+"/audit", devAuth, "")
	for _, ev := range []string{"recovery_requested", "recovery_approved", "recovery_executed"} {
		if !strings.Contains(string(body), ev) {
			t.Fatalf("audit missing %s: %s", ev, body)
		}
	}

	// The minted grant is time-bounded.
	g, err := srv.Grants.Get(context.Background(), executed.GrantID)
	if err != nil || g.ExpiresAt == nil {
		t.Fatalf("grant not time-bounded: %+v %v", g, err)
	}
	if d := time.Until(*g.ExpiresAt); d > time.Hour+time.Minute || d < 50*time.Minute {
		t.Fatalf("grant expiry not ~1h: %s", d)
	}
}

// fakeIssuerVerifier returns canned identities per token.
type fakeIssuerVerifier struct{ ids map[string]*oidc.Identity }

func (f *fakeIssuerVerifier) Verify(_ context.Context, token string) (*oidc.Identity, error) {
	if id, ok := f.ids[token]; ok {
		return id, nil
	}
	return nil, fmt.Errorf("bad token")
}

// TestRecoveryCeremonyBinding exercises the privasys.id branch of the
// approval verification: amr=webauthn is required and the vault_op
// claim must bind THIS recovery's digest.
func TestRecoveryCeremonyBinding(t *testing.T) {
	_, srv := escrowedServer(t,
		`{"issuer":"https://acme.example","quorum":1,"approvers":["appr-a"]}`)
	srv.DevMode = false // exercise the production branch
	pol := &config.RecoveryPolicy{Issuer: config.DefaultIssuer, Quorum: 1, Approvers: []string{"appr-a"}}
	rec := &store.Recovery{ID: "rid-1", TenantID: "t-1", GranteeSub: "rescuer", Reason: "dr"}
	digest := recoveryDigest(rec.ID, rec.TenantID, rec.GranteeSub, rec.Reason)
	exp := time.Now().Add(2 * time.Minute).Unix()

	mkID := func(vaultOp string, amr []any) *oidc.Identity {
		return &oidc.Identity{Sub: "appr-a", Issuer: config.DefaultIssuer, Claims: map[string]any{
			"amr": amr, "vault_op": vaultOp, "nonce": "n-1", "exp": float64(exp),
		}}
	}
	good := srv.ceremonyBinding(rec.ID, digest, "n-1", exp)
	srv.recVer = map[string]oidc.Verifier{config.DefaultIssuer: &fakeIssuerVerifier{ids: map[string]*oidc.Identity{
		"tok-good":    mkID(good, []any{"webauthn"}),
		"tok-noamr":   mkID(good, nil),
		"tok-otherop": mkID(srv.ceremonyBinding("other-rid", digest, "n-1", exp), []any{"webauthn"}),
	}}}

	if sub, jti, err := srv.verifyRecoveryApproval(context.Background(), pol, rec, "tok-good"); err != nil || sub != "appr-a" || !strings.HasPrefix(jti, "op:") {
		t.Fatalf("good ceremony: %q %q %v", sub, jti, err)
	}
	if _, _, err := srv.verifyRecoveryApproval(context.Background(), pol, rec, "tok-noamr"); err == nil {
		t.Fatal("missing amr must be rejected")
	}
	if _, _, err := srv.verifyRecoveryApproval(context.Background(), pol, rec, "tok-otherop"); err == nil {
		t.Fatal("a binding for another recovery must be rejected")
	}
}

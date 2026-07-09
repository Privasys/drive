package api

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/platform"
	"github.com/Privasys/drive/service/internal/store"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// newFullServer mounts the complete Handler (health/status/configure +
// /v1 + /tools) the way main.go does.
func newFullServer(t *testing.T, mutate func(*Server)) *httptest.Server {
	t.Helper()
	_, srv := newTestServer(t)
	srv.StateDir = t.TempDir()
	srv.DevMode = true
	srv.Version = "test"
	if mutate != nil {
		mutate(srv)
	}
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	return ts
}

func doJSON(t *testing.T, method, url, auth, body string) (*http.Response, []byte) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, b
}

const devAuth = "Bearer dev:user-1:bertrand@privasys.org"

func TestConfigureLifecycle(t *testing.T) {
	ts := newFullServer(t, nil)

	// Before configure: liveness 200, readiness 503, status awaiting_config.
	resp, _ := doJSON(t, "GET", ts.URL+"/health", "", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health (liveness) before configure: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/readiness", "", "")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("readiness before configure: %d", resp.StatusCode)
	}
	resp, body := doJSON(t, "GET", ts.URL+"/status", "", "")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "awaiting_config") {
		t.Fatalf("status before configure: %d %s", resp.StatusCode, body)
	}

	// Unauthenticated configure is rejected.
	resp, _ = doJSON(t, "POST", ts.URL+"/configure", "", `{"mode":"sovereign"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated configure: %d", resp.StatusCode)
	}

	// Escrowed is not shippable yet: fail closed.
	resp, _ = doJSON(t, "POST", ts.URL+"/configure", devAuth, `{"mode":"escrowed"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("escrowed configure: %d", resp.StatusCode)
	}

	// Sovereign configures the instance.
	resp, body = doJSON(t, "POST", ts.URL+"/configure", devAuth, `{"mode":"sovereign"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("configure: %d %s", resp.StatusCode, body)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/readiness", "", "")
	if resp.StatusCode != 200 {
		t.Fatalf("readiness after configure: %d", resp.StatusCode)
	}
	resp, body = doJSON(t, "GET", ts.URL+"/status", "", "")
	if !strings.Contains(string(body), `"ready"`) || !strings.Contains(string(body), "sovereign") {
		t.Fatalf("status after configure: %s", body)
	}

	// Defaults may be re-submitted with the same mode.
	resp, _ = doJSON(t, "POST", ts.URL+"/configure", devAuth, `{"mode":"sovereign","quota_default_bytes":1024}`)
	if resp.StatusCode != 200 {
		t.Fatalf("reconfigure same mode: %d", resp.StatusCode)
	}
}

func TestConfigPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	_, srv := newTestServer(t)
	srv.StateDir = dir
	srv.DevMode = true
	ts := httptest.NewServer(srv.Handler(""))
	resp, _ := doJSON(t, "POST", ts.URL+"/configure", devAuth, `{"mode":"sovereign"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("configure: %d", resp.StatusCode)
	}
	ts.Close()

	// A fresh process loads the persisted config (main.go boot path).
	cfg, err := config.Load(dir)
	if err != nil || cfg == nil {
		t.Fatalf("reload config: %v %v", cfg, err)
	}
	if cfg.Mode != config.ModeSovereign {
		t.Fatalf("mode %q", cfg.Mode)
	}
}

func TestConfigureRequiresAuthenticatedUser(t *testing.T) {
	// The owner/admin role is enforced by the enclave-os runtime in
	// front of the app (proxied configure calls do not carry the user's
	// bearer verbatim, so the app cannot re-check it). In-app, configure
	// requires an authenticated user; anonymous callers are rejected.
	ts := newFullServer(t, func(s *Server) {
		s.DevMode = false
		s.Platform = platform.Env{AppID: "9e107d9d-52bb-4c2e-8f25-7673a955a0d1"}
	})
	resp, _ := doJSON(t, "POST", ts.URL+"/configure", "", `{"mode":"sovereign"}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous configure: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "POST", ts.URL+"/configure", devAuth, `{"mode":"sovereign"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("authenticated configure: %d", resp.StatusCode)
	}
}

func TestPersonalTenantAutoProvision(t *testing.T) {
	ts := newFullServer(t, nil)

	// First call creates the personal tenant.
	resp, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("first ensure: %d %s", resp.StatusCode, body)
	}
	var first struct{ ID, Kind, Name string }
	_ = json.Unmarshal(body, &first)
	if first.Kind != "user" || first.Name != "bertrand@privasys.org" {
		t.Fatalf("personal tenant: %+v", first)
	}

	// Second call is idempotent: same tenant, 200.
	resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second ensure: %d %s", resp.StatusCode, body)
	}
	var second struct{ ID string }
	_ = json.Unmarshal(body, &second)
	if second.ID != first.ID {
		t.Fatalf("ensure not idempotent: %s vs %s", second.ID, first.ID)
	}

	// /v1/me lists the membership with the owner role.
	resp, body = doJSON(t, "GET", ts.URL+"/v1/me", devAuth, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me: %d %s", resp.StatusCode, body)
	}
	var me struct {
		Sub     string
		Tenants []struct{ ID, Role string }
	}
	_ = json.Unmarshal(body, &me)
	if me.Sub != "user-1" || len(me.Tenants) != 1 ||
		me.Tenants[0].ID != first.ID || me.Tenants[0].Role != "owner" {
		t.Fatalf("me listing: %s", body)
	}

	// A different user gets their own tenant, not this one.
	other := "Bearer dev:user-2:other@example.com"
	resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant", other, "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("other ensure: %d %s", resp.StatusCode, body)
	}
	var otherT struct{ ID string }
	_ = json.Unmarshal(body, &otherT)
	if otherT.ID == first.ID {
		t.Fatal("personal tenants must not be shared across subs")
	}
}

// fakeMEKs is a deterministic in-memory MEKProvider for tests.
type fakeMEKs struct {
	mek     []byte
	loadErr error // when set, Load fails (simulates a stale attestation token)
}

func (f *fakeMEKs) Provision(_ context.Context, b vaultmek.Bundle) (vaultmek.Ref, error) {
	return vaultmek.Ref{Handle: b.Handle, Endpoints: b.Endpoints, Threshold: b.Threshold}, nil
}
func (f *fakeMEKs) Load(context.Context, vaultmek.Ref) ([]byte, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.mek, nil
}

// Unwrap fakes the vault by XORing with a fixed pad (deterministic,
// reversible) so a sealed round-trip is testable without a vault.
func (f *fakeMEKs) Unwrap(_ context.Context, _ vaultmek.Ref, ciphertext, _ []byte) ([]byte, error) {
	out := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		out[i] = b ^ 0x5a
	}
	return out, nil
}

func TestTenantKeySwitchRewrapsContent(t *testing.T) {
	mek := sha256.Sum256([]byte("vault-held-tenant-mek"))
	ts := newFullServer(t, func(s *Server) { s.MEKs = &fakeMEKs{mek: mek[:]} })

	// Personal tenant + a file sealed under the instance MEK.
	_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	content := base64.StdEncoding.EncodeToString([]byte("pre-switch content"))
	resp, body := doJSON(t, "POST", ts.URL+"/tools/write_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","name":"old.txt","content_base64":"%s"}`, tenant.ID, content))
	if resp.StatusCode != 200 {
		t.Fatalf("pre-switch write: %d %s", resp.StatusCode, body)
	}
	var oldFile struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &oldFile)

	// Switch the tenant to the vault MEK; existing content is re-wrapped.
	resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth,
		`{"grant":"g","handle":"apps.privasys.org/x/data/y/mek/v1","constellation":{"endpoints":["v1:1","v2:2"],"mrenclave":"00","attestation_server":"as","threshold":2}}`)
	if resp.StatusCode != http.StatusCreated || !strings.Contains(string(body), `"rewrapped_nodes":1`) {
		t.Fatalf("switch: %d %s", resp.StatusCode, body)
	}

	// The pre-switch file reads back under the new key.
	resp, body = doJSON(t, "POST", ts.URL+"/tools/read_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","file_id":"%s"}`, tenant.ID, oldFile.ID))
	if resp.StatusCode != 200 {
		t.Fatalf("post-switch read: %d %s", resp.StatusCode, body)
	}
	var out struct {
		ContentBase64 string `json:"content_base64"`
	}
	_ = json.Unmarshal(body, &out)
	if got, _ := base64.StdEncoding.DecodeString(out.ContentBase64); string(got) != "pre-switch content" {
		t.Fatalf("post-switch content mismatch: %q", got)
	}

	// New writes work, and a repeat call re-arms instead of re-provisioning.
	resp, _ = doJSON(t, "POST", ts.URL+"/tools/write_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","name":"new.txt","content_base64":"%s"}`, tenant.ID, content))
	if resp.StatusCode != 200 {
		t.Fatalf("post-switch write: %d", resp.StatusCode)
	}
	resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth, `{}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"loaded"`) {
		t.Fatalf("re-arm: %d %s", resp.StatusCode, body)
	}
}

func TestQuotaEnforcement(t *testing.T) {
	// Configure a tiny quota, then prove writes are metered and the
	// ceiling holds.
	ts := newFullServer(t, nil)
	resp, _ := doJSON(t, "POST", ts.URL+"/configure", devAuth, `{"mode":"sovereign","quota_default_bytes":20}`)
	if resp.StatusCode != 200 {
		t.Fatalf("configure quota: %d", resp.StatusCode)
	}
	_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	write := func(name, plain string) int {
		b := base64.StdEncoding.EncodeToString([]byte(plain))
		resp, _ := doJSON(t, "POST", ts.URL+"/tools/write_file", devAuth,
			fmt.Sprintf(`{"tenant_id":"%s","name":"%s","content_base64":"%s"}`, tenant.ID, name, b))
		return resp.StatusCode
	}
	if s := write("a.txt", "0123456789"); s != 200 { // 10 bytes, fits
		t.Fatalf("first write: %d", s)
	}
	if s := write("b.txt", "0123456789"); s != 200 { // 10 more, exactly 20
		t.Fatalf("second write (fills quota): %d", s)
	}
	if s := write("c.txt", "x"); s != http.StatusRequestEntityTooLarge { // over
		t.Fatalf("over-quota write should be 413, got %d", s)
	}

	// /v1/quota reports the usage.
	resp, body = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/quota", devAuth, "")
	if resp.StatusCode != 200 {
		t.Fatalf("quota endpoint: %d", resp.StatusCode)
	}
	var q struct {
		Used, Limit, Remaining int64
		Unlimited              bool
	}
	// tolerant field names
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	q.Used = int64(raw["used_bytes"].(float64))
	q.Limit = int64(raw["limit_bytes"].(float64))
	if q.Used != 20 || q.Limit != 20 {
		t.Fatalf("quota report: used=%d limit=%d (%s)", q.Used, q.Limit, body)
	}

	// Deleting frees quota; a new small write then fits.
	// (find b.txt id)
	_, body = doJSON(t, "POST", ts.URL+"/tools/list_root", devAuth, fmt.Sprintf(`{"tenant_id":"%s"}`, tenant.ID))
	var listed struct {
		Nodes []struct{ ID, Name string }
	}
	_ = json.Unmarshal(body, &listed)
	var bID string
	for _, n := range listed.Nodes {
		if n.Name == "b.txt" {
			bID = n.ID
		}
	}
	doJSON(t, "POST", ts.URL+"/tools/delete_node", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","node_id":"%s"}`, tenant.ID, bID))
	if s := write("d.txt", "12345"); s != 200 {
		t.Fatalf("write after freeing quota: %d", s)
	}
}

func TestBucketCredStoreAndUnwrap(t *testing.T) {
	pad := func(b []byte) []byte { // mirror the fake's XOR seal
		out := make([]byte, len(b))
		for i, x := range b {
			out[i] = x ^ 0x5a
		}
		return out
	}
	srvHolder := struct{ s *Server }{}
	ts := newFullServer(t, func(s *Server) {
		s.MEKs = &fakeMEKs{mek: make([]byte, 32)}
		srvHolder.s = s
	})
	_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	// Before setting: not configured.
	resp, body := doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/bucket-cred", devAuth, "")
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"configured":false`) {
		t.Fatalf("pre-set bucket-cred: %d %s", resp.StatusCode, body)
	}

	// Store a sealed credential (the "ciphertext" is the fake's XOR seal
	// of the plaintext, so unwrap recovers it).
	plaintext := []byte(`{"type":"service_account","project":"x"}`)
	ctB64 := base64.RawURLEncoding.EncodeToString(pad(plaintext))
	resp, body = doJSON(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/bucket-cred", devAuth,
		fmt.Sprintf(`{"key_ref":{"handle":"apps.privasys.org/x/data/y/bucket/v1","endpoints":["v:1"]},"ciphertext_b64":"%s","iv_b64":"%s","content_type":"gcs-sa-json"}`,
			ctB64, base64.RawURLEncoding.EncodeToString([]byte("iv0"))))
	if resp.StatusCode != 200 {
		t.Fatalf("set bucket-cred: %d %s", resp.StatusCode, body)
	}

	// Metadata visible; plaintext never returned.
	resp, body = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/bucket-cred", devAuth, "")
	if !strings.Contains(string(body), `"configured":true`) ||
		!strings.Contains(string(body), "gcs-sa-json") ||
		strings.Contains(string(body), "service_account") {
		t.Fatalf("bucket-cred metadata leaked or wrong: %s", body)
	}

	// In-enclave unwrap recovers the plaintext.
	got, ct, err := srvHolder.s.bucketCredential(context.Background(), tenant.ID)
	if err != nil {
		t.Fatalf("bucketCredential: %v", err)
	}
	if string(got) != string(plaintext) || ct != "gcs-sa-json" {
		t.Fatalf("unwrap mismatch: %q (%s)", got, ct)
	}

	// Rotation swaps the blob.
	newPlain := []byte(`{"type":"service_account","project":"rotated"}`)
	resp, _ = doJSON(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/bucket-cred", devAuth,
		fmt.Sprintf(`{"key_ref":{"handle":"apps.privasys.org/x/data/y/bucket/v2","endpoints":["v:1"]},"ciphertext_b64":"%s","iv_b64":"aXY","content_type":"gcs-sa-json"}`,
			base64.RawURLEncoding.EncodeToString(pad(newPlain))))
	if resp.StatusCode != 200 {
		t.Fatalf("rotate: %d", resp.StatusCode)
	}
	got, _, _ = srvHolder.s.bucketCredential(context.Background(), tenant.ID)
	if string(got) != string(newPlain) {
		t.Fatalf("post-rotation unwrap: %q", got)
	}

	// Delete clears it.
	resp, _ = doJSON(t, "DELETE", ts.URL+"/v1/tenants/"+tenant.ID+"/bucket-cred", devAuth, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete bucket-cred: %d", resp.StatusCode)
	}
}

func TestSealedTransportDataPlane(t *testing.T) {
	ts := newFullServer(t, nil)
	const sub = "wallet-user-9"
	sealed := func(method, path, body string) (*http.Response, []byte) {
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, r)
		req.Header.Set("X-Privasys-Sub", sub)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	// A sealed session provisions its personal tenant and uses the data
	// plane with no bearer, attributed to the relay-asserted sub.
	resp, body := sealed("POST", "/v1/me/tenant", "")
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("sealed ensure tenant: %d %s", resp.StatusCode, body)
	}
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	content := base64.StdEncoding.EncodeToString([]byte("sealed content"))
	resp, body = sealed("POST", "/tools/write_file",
		fmt.Sprintf(`{"tenant_id":"%s","name":"s.txt","content_base64":"%s"}`, tenant.ID, content))
	if resp.StatusCode != 200 {
		t.Fatalf("sealed write: %d %s", resp.StatusCode, body)
	}
	resp, body = sealed("POST", "/tools/changes", fmt.Sprintf(`{"tenant_id":"%s"}`, tenant.ID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), sub) {
		t.Fatalf("sealed changes (attribution): %d %s", resp.StatusCode, body)
	}

	// Another sealed sub cannot see the first tenant's drive.
	req, _ := http.NewRequest("POST", ts.URL+"/tools/list_root",
		strings.NewReader(fmt.Sprintf(`{"tenant_id":"%s"}`, tenant.ID)))
	req.Header.Set("X-Privasys-Sub", "someone-else")
	req.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(req)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-sub sealed access: %d", resp2.StatusCode)
	}

	// Sealed transport is refused for configure (no roles).
	resp, _ = sealed("POST", "/configure", `{"mode":"sovereign"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("sealed configure must be forbidden: %d", resp.StatusCode)
	}
}

func TestEnterpriseFolderACLOverride(t *testing.T) {
	ts := newFullServer(t, nil)
	owner := devAuth // dev:user-1
	contributor := "Bearer dev:contrib:c@x"

	// Enterprise tenant; owner adds a contributor.
	resp, body := doJSON(t, "POST", ts.URL+"/v1/tenants", owner, `{"kind":"enterprise","name":"Acme"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create tenant: %d %s", resp.StatusCode, body)
	}
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	resp, _ = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/members", owner,
		`{"user_sub":"contrib","role":"contributor"}`)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add member: %d", resp.StatusCode)
	}

	// Two folders: "finance" (to be restricted) and "shared".
	mkdir := func(name string) string {
		_, b := doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", owner,
			fmt.Sprintf(`{"name":"%s"}`, name))
		var n struct{ ID string }
		_ = json.Unmarshal(b, &n)
		return n.ID
	}
	finance := mkdir("finance")
	shared := mkdir("shared")

	// Before override: the contributor can list both.
	for _, f := range []string{finance, shared} {
		resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+f, contributor, "")
		if resp.StatusCode != 200 {
			t.Fatalf("pre-override contributor list %s: %d", f, resp.StatusCode)
		}
	}

	// Restrict finance to owner+admin.
	resp, body = doJSON(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+finance+"/acl", owner,
		`{"roles":["owner","admin"]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("set acl: %d %s", resp.StatusCode, body)
	}

	// Contributor is now denied inside finance, still allowed in shared,
	// and the owner keeps access to finance (cannot be locked out).
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+finance, contributor, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("contributor in restricted finance should be 403, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+shared, contributor, "")
	if resp.StatusCode != 200 {
		t.Fatalf("contributor in shared should be 200, got %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+finance, owner, "")
	if resp.StatusCode != 200 {
		t.Fatalf("owner in restricted finance should be 200, got %d", resp.StatusCode)
	}

	// A child of finance inherits the override (nearest-ancestor walk):
	// the owner creates a subfolder, the contributor is denied there too.
	_, b := doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", owner,
		fmt.Sprintf(`{"name":"q1","parent_id":"%s"}`, finance))
	var sub struct{ ID string }
	_ = json.Unmarshal(b, &sub)
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+sub.ID, contributor, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("contributor in finance/q1 should be 403 (inherited), got %d", resp.StatusCode)
	}

	// Clearing the override restores contributor access.
	doJSON(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+finance+"/acl", owner, `{"roles":[]}`)
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/folders/"+finance, contributor, "")
	if resp.StatusCode != 200 {
		t.Fatalf("contributor after clearing override: %d", resp.StatusCode)
	}
}

func TestBackendSelection(t *testing.T) {
	_, srv := newTestServer(t)
	srv.MEKs = &fakeMEKs{mek: make([]byte, 32)}
	ctx := context.Background()

	tOwner := &store.Tenant{Kind: store.TenantUser, Name: "o"}
	if err := srv.Store.CreateTenant(ctx, tOwner, "o"); err != nil {
		t.Fatal(err)
	}

	// No BYO credential: the instance default backend.
	bk, err := srv.backendFor(ctx, tOwner.ID)
	if err != nil || bk != srv.Backend {
		t.Fatalf("no-cred backend: %v (want instance default)", err)
	}

	setCred := func(contentType string) {
		cred := SealedBucketCred{
			KeyRef:        vaultmek.Ref{Handle: "h", Endpoints: []string{"v:1"}},
			CiphertextB64: base64.RawURLEncoding.EncodeToString([]byte("x")),
			IvB64:         base64.RawURLEncoding.EncodeToString([]byte("iv")),
			ContentType:   contentType,
			Bucket:        "b",
		}
		blob, _ := json.Marshal(cred)
		if err := srv.Store.SetTenantBucketCred(ctx, tOwner.ID, string(blob)); err != nil {
			t.Fatal(err)
		}
	}

	// A supported content type routes into its provider branch (the
	// fake unwrap yields non-JSON, so S3/OVH creds fail to parse — which
	// proves the branch was taken, without a live cloud client).
	for _, ct := range []string{"s3-keypair", "ovh-s3"} {
		setCred(ct)
		if _, err := srv.backendFor(ctx, tOwner.ID); err == nil ||
			!strings.Contains(err.Error(), "credential") {
			t.Fatalf("%s selection: %v (want the s3/ovh branch)", ct, err)
		}
	}

	// An unknown content type surfaces a clear unsupported error.
	setCred("unknown-provider")
	if _, err := srv.backendFor(ctx, tOwner.ID); err == nil ||
		!strings.Contains(err.Error(), "unsupported bucket credential") {
		t.Fatalf("unknown content type: %v (want unsupported)", err)
	}
}

func TestEscrowedProvisionWrapsAndDiscloses(t *testing.T) {
	holder := struct{ s *Server }{}
	ts := newFullServer(t, func(s *Server) {
		s.MEKs = &fakeMEKs{mek: make([]byte, 32)} // stands in for tenant MEK + MEK_org
		holder.s = s
	})

	// Configure escrowed mode with a MEK_org ref + recovery policy.
	orgRef := `{"handle":"apps.privasys.org/x/org/mek/v1","endpoints":["v:1"],"threshold":1}`
	cfgBody := `{"mode":"escrowed","org_mek_ref":` + strconv.Quote(orgRef) +
		`,"recovery":{"issuer":"https://acme.example","quorum":2,"approvers":["a","b","c"]}}`
	resp, body := doJSON(t, "POST", ts.URL+"/configure", devAuth, cfgBody)
	if resp.StatusCode != 200 {
		t.Fatalf("configure escrowed: %d %s", resp.StatusCode, body)
	}

	_, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	// Provisioning a tenant MEK in escrowed mode escrow-wraps it.
	resp, body = doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth,
		`{"grant":"g","handle":"h","constellation":{"endpoints":["v:1"],"mrenclave":"00","attestation_server":"as","threshold":1}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("provision: %d %s", resp.StatusCode, body)
	}
	if w, err := holder.s.Store.TenantEscrowWrap(context.Background(), tenant.ID); err != nil || w == "" {
		t.Fatalf("escrow wrap not stored: %q %v", w, err)
	}

	// The escrow is disclosed to the tenant via the audit log.
	resp, body = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/audit", devAuth, "")
	if resp.StatusCode != 200 || !strings.Contains(string(body), "escrow_wrapped") {
		t.Fatalf("audit disclosure: %d %s", resp.StatusCode, body)
	}
}

func TestEscrowedConfigValidation(t *testing.T) {
	ts := newFullServer(t, func(s *Server) { s.MEKs = &fakeMEKs{mek: make([]byte, 32)} })
	// escrowed without org_mek_ref / recovery is rejected.
	for _, c := range []string{
		`{"mode":"escrowed"}`,
		`{"mode":"escrowed","org_mek_ref":"{}"}`,
		`{"mode":"escrowed","org_mek_ref":"{}","recovery":{"quorum":0}}`,
		`{"mode":"escrowed","org_mek_ref":"{}","recovery":{"quorum":3,"approvers":["a"]}}`,
	} {
		resp, _ := doJSON(t, "POST", ts.URL+"/configure", devAuth, c)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %s, got %d", c, resp.StatusCode)
		}
	}
}

func TestVaultKeyStaleReturns409(t *testing.T) {
	fake := &fakeMEKs{mek: make([]byte, 32)}
	ts := newFullServer(t, func(s *Server) { s.MEKs = fake })

	_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	// Provision a vault MEK (sets the tenant's mek_ref).
	resp, _ := doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth,
		`{"grant":"g","handle":"h","constellation":{"endpoints":["v:1"],"mrenclave":"00","attestation_server":"as","threshold":1}}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("provision: %d", resp.StatusCode)
	}

	// Now the vault load fails (stale attestation token). A content op
	// must return an actionable 409 vault_key_stale, not an opaque 502.
	fake.loadErr = errors.New("attestation token expired")
	content := base64.StdEncoding.EncodeToString([]byte("x"))
	resp, body = doJSON(t, "POST", ts.URL+"/tools/write_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","name":"f.txt","content_base64":"%s"}`, tenant.ID, content))
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "vault_key_stale") {
		t.Fatalf("stale vault key should be 409 vault_key_stale, got %d %s", resp.StatusCode, body)
	}

	// Re-arm (load succeeds again) and the op works.
	fake.loadErr = nil
	resp, _ = doJSON(t, "POST", ts.URL+"/tools/write_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","name":"f.txt","content_base64":"%s"}`, tenant.ID, content))
	if resp.StatusCode != 200 {
		t.Fatalf("after re-arm: %d", resp.StatusCode)
	}
}

func TestTenantKeyGuards(t *testing.T) {
	ts := newFullServer(t, nil)

	// Without a vault client (off-platform), the endpoint says so.
	resp, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant/key", devAuth, `{}`)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("tenant key without vault client: %d %s", resp.StatusCode, body)
	}
	// Tenants without a vault MEK keep working on the instance MEK:
	// the upload/download roundtrip in TestEndToEnd covers that path.
}

func TestCrossUserForbidden(t *testing.T) {
	ts := newFullServer(t, nil)

	resp, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	if resp.StatusCode != 201 {
		t.Fatalf("create tenant: %d %s", resp.StatusCode, body)
	}
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	// Another authenticated user is not a member: everything 403s.
	other := "Bearer dev:user-2:someone@example.com"
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/root", other, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-user list: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", other, `{"name":"X"}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-user mkdir: %d", resp.StatusCode)
	}
	// The owner still can.
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/root", devAuth, "")
	if resp.StatusCode != 200 {
		t.Fatalf("owner list: %d", resp.StatusCode)
	}
}

func TestAppGrantScopeAndSubtree(t *testing.T) {
	ts := newFullServer(t, nil)

	// Owner: tenant, a folder with a file inside, and a file at root.
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	_, body = doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/folders", devAuth, `{"name":"shared"}`)
	var folder struct{ ID string }
	_ = json.Unmarshal(body, &folder)

	upload := func(parent, name string) string {
		url := fmt.Sprintf("%s/v1/tenants/%s/files?name=%s", ts.URL, tenant.ID, name)
		if parent != "" {
			url += "&parent_id=" + parent
		}
		req, _ := http.NewRequest("POST", url, strings.NewReader("content of "+name))
		req.Header.Set("Authorization", devAuth)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 201 {
			t.Fatalf("upload %s: %d %s", name, resp.StatusCode, b)
		}
		var n struct{ ID string }
		_ = json.Unmarshal(b, &n)
		return n.ID
	}
	inFolder := upload(folder.ID, "in-folder.txt")
	atRoot := upload("", "at-root.txt")

	// Owner mints a read-only app grant on the folder.
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pk := base64.RawStdEncoding.EncodeToString(pub)
	resp, body := doJSON(t, "POST", ts.URL+"/v1/tenants/"+tenant.ID+"/nodes/"+folder.ID+"/grants", devAuth,
		fmt.Sprintf(`{"subject":"app:deadbeef","scope":["read"],"binding_pubkey":"%s"}`, pk))
	if resp.StatusCode != 201 {
		t.Fatalf("create grant: %d %s", resp.StatusCode, body)
	}
	var grant struct{ ID string }
	_ = json.Unmarshal(body, &grant)

	tok, err := grants.MintToken(priv, grants.Envelope{
		Iss: "drive.privasys.org", Aud: "privasys-drive",
		Sub: tenant.ID, Node: folder.ID, Scope: []grants.Scope{grants.ScopeRead},
		JTI: grant.ID, Iat: time.Now().Unix(), Exp: time.Now().Add(5 * time.Minute).Unix(),
		PK: pk,
	})
	if err != nil {
		t.Fatal(err)
	}
	appAuth := "AppGrant " + tok

	// In-scope: read the file inside the granted folder.
	resp, body = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+inFolder, appAuth, "")
	if resp.StatusCode != 200 || string(body) != "content of in-folder.txt" {
		t.Fatalf("appgrant read: %d %q", resp.StatusCode, body)
	}
	// List the granted folder via the tool surface too.
	resp, body = doJSON(t, "POST", ts.URL+"/tools/list_folder", appAuth,
		fmt.Sprintf(`{"tenant_id":"%s","folder_id":"%s"}`, tenant.ID, folder.ID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), "in-folder.txt") {
		t.Fatalf("appgrant tool list: %d %s", resp.StatusCode, body)
	}

	// Outside the subtree: the root file is invisible.
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+atRoot, appAuth, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("appgrant out-of-subtree read: %d", resp.StatusCode)
	}
	// Beyond the scope: writes are refused.
	req, _ := http.NewRequest("POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=evil.txt&parent_id=%s", ts.URL, tenant.ID, folder.ID),
		strings.NewReader("nope"))
	req.Header.Set("Authorization", appAuth)
	wresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	wresp.Body.Close()
	if wresp.StatusCode != http.StatusForbidden {
		t.Fatalf("appgrant write with read scope: %d", wresp.StatusCode)
	}
	// Tenant-level surfaces are user-only.
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/changes", appAuth, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("appgrant changes: %d", resp.StatusCode)
	}

	// Revocation kills the token immediately.
	resp, _ = doJSON(t, "DELETE", ts.URL+"/v1/tenants/"+tenant.ID+"/grants/"+grant.ID, devAuth, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+inFolder, appAuth, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("appgrant after revoke: %d", resp.StatusCode)
	}

	// A token signed by a different key than the grant binding fails.
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	badTok, _ := grants.MintToken(otherPriv, grants.Envelope{
		Iss: "drive.privasys.org", Aud: "privasys-drive",
		Sub: tenant.ID, Node: folder.ID, Scope: []grants.Scope{grants.ScopeRead},
		JTI: grant.ID, Iat: time.Now().Unix(), Exp: time.Now().Add(5 * time.Minute).Unix(),
		PK: pk,
	})
	resp, _ = doJSON(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/files/"+inFolder, "AppGrant "+badTok, "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged appgrant: %d", resp.StatusCode)
	}
}

func TestToolsWriteReadRoundtrip(t *testing.T) {
	ts := newFullServer(t, nil)

	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	content := base64.StdEncoding.EncodeToString([]byte("tool payload"))
	resp, body := doJSON(t, "POST", ts.URL+"/tools/write_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","name":"t.txt","mime":"text/plain","content_base64":"%s"}`, tenant.ID, content))
	if resp.StatusCode != 200 {
		t.Fatalf("tool write: %d %s", resp.StatusCode, body)
	}
	var n struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &n)

	resp, body = doJSON(t, "POST", ts.URL+"/tools/read_file", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","file_id":"%s"}`, tenant.ID, n.ID))
	if resp.StatusCode != 200 {
		t.Fatalf("tool read: %d %s", resp.StatusCode, body)
	}
	var out struct {
		ContentBase64 string `json:"content_base64"`
	}
	_ = json.Unmarshal(body, &out)
	got, _ := base64.StdEncoding.DecodeString(out.ContentBase64)
	if string(got) != "tool payload" {
		t.Fatalf("roundtrip mismatch: %q", got)
	}

	resp, body = doJSON(t, "POST", ts.URL+"/tools/list_root", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s"}`, tenant.ID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), "t.txt") {
		t.Fatalf("tool list_root: %d %s", resp.StatusCode, body)
	}

	resp, body = doJSON(t, "POST", ts.URL+"/tools/changes", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s"}`, tenant.ID))
	if resp.StatusCode != 200 || !strings.Contains(string(body), "user-1") {
		t.Fatalf("tool changes (actor attribution): %d %s", resp.StatusCode, body)
	}
}

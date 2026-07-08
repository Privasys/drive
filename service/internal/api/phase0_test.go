package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/platform"
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

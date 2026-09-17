package api

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Privasys/drive/service/internal/store"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// perHandleMEKs is a vault double that keeps DISTINCT material per handle, so
// a re-key genuinely changes the key rather than re-wrapping under the same
// value (which would make the sweep pass vacuously).
type perHandleMEKs struct {
	mu   sync.Mutex
	keys map[string][]byte
	// loadErrFor fails Load for one handle: the old constellation being
	// unreachable must abort that tenant with nothing committed.
	loadErrFor string
}

func newPerHandleMEKs() *perHandleMEKs {
	return &perHandleMEKs{keys: map[string][]byte{}}
}

func (f *perHandleMEKs) seed(handle string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic(err)
	}
	f.keys[handle] = k
	return k
}

func (f *perHandleMEKs) Provision(_ context.Context, b vaultmek.Bundle) (vaultmek.Ref, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[b.Handle]; !ok {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return vaultmek.Ref{}, err
		}
		f.keys[b.Handle] = k
	}
	return vaultmek.Ref{
		Handle: b.Handle, Endpoints: b.Endpoints, MrenclaveHex: b.MrenclaveHex,
		AttServer: b.AttServer, AttToken: b.AttToken, Threshold: b.Threshold,
	}, nil
}

func (f *perHandleMEKs) Load(_ context.Context, ref vaultmek.Ref) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ref.Handle == f.loadErrFor {
		return nil, fmt.Errorf("vault unreachable for %s", ref.Handle)
	}
	k, ok := f.keys[ref.Handle]
	if !ok {
		return nil, fmt.Errorf("no key at %s", ref.Handle)
	}
	return k, nil
}

func (f *perHandleMEKs) Unwrap(context.Context, vaultmek.Ref, []byte, []byte) ([]byte, error) {
	return nil, fmt.Errorf("not used")
}
func (f *perHandleMEKs) RefreshTees(context.Context, vaultmek.Ref, string, string) error {
	return nil
}
func (f *perHandleMEKs) Regenerate(_ context.Context, ref vaultmek.Ref, b vaultmek.Bundle) (vaultmek.Ref, error) {
	return vaultmek.Ref{}, fmt.Errorf("not used")
}

const (
	sweepOldHandle = "apps.privasys.org/abc123/data/deadbeefdeadbeefdeadbeefdeadbeef/mek/v1"
	sweepNewHandle = "apps.privasys.org/abc123/data/deadbeefdeadbeefdeadbeefdeadbeef/mek/v2"
)

// TestResweepRekeysTenantAndKeepsContentReadable is the whole point of the
// sweep: after moving a tenant to a NEW MEK on a new constellation, both the
// current content and its retained revisions must still read back — and the
// tenant must actually be on new key material.
func TestResweepRekeysTenantAndKeepsContentReadable(t *testing.T) {
	ts, srv := newTestServer(t)
	fake := newPerHandleMEKs()
	oldMEK := fake.seed(sweepOldHandle)
	srv.MEKs = fake

	tenantID := createTenantForSweep(t, ts)

	// Put the tenant on the "old" constellation, with its content sealed
	// under that MEK: provision from the instance key, which runs the same
	// sweep in the other direction.
	oldRef := vaultmek.Ref{
		Handle: sweepOldHandle, Endpoints: []string{"https://old-1:8443"},
		MrenclaveHex: "0ld0ld", AttServer: "https://as", Threshold: 1,
	}
	if _, err := srv.switchTenantMEK(context.Background(), tenantID, srv.MEK, oldMEK, oldRef); err != nil {
		t.Fatalf("seed onto old constellation: %v", err)
	}

	// Upload a file, then overwrite it so a retained revision exists.
	uploadFileForSweep(t, ts, tenantID, "notes.txt", "first version")
	// Replacing the bytes keeps the first as a previous version.
	replaceContentForSweep(t, ts, tenantID, nodeIDByName(t, ts, tenantID, "notes.txt"), "second version")

	body := fmt.Sprintf(`{"items":[{"tenant_id":%q,"handle":%q,"grant":"g",
		"attestation_token":"t",
		"constellation":{"endpoints":["https://new-1:8443"],"mrenclave":"new00","attestation_server":"https://as","threshold":1}}]}`,
		tenantID, sweepNewHandle)
	resp := doSweep(t, ts, body)
	if resp.Rekeyed != 1 {
		t.Fatalf("rekeyed = %d, results = %+v", resp.Rekeyed, resp.Results)
	}
	got := resp.Results[0]
	if got.Status != "rekeyed" {
		t.Fatalf("status = %q (%s)", got.Status, got.Error)
	}
	if got.Handle != sweepNewHandle {
		t.Errorf("handle = %q, want %q", got.Handle, sweepNewHandle)
	}
	if got.Versions < 1 {
		t.Errorf("no retained revision was re-wrapped (versions = %d): a sweep that skips them silently breaks previous versions", got.Versions)
	}

	// The tenant must now point at the new handle, and its MEK must be
	// different material — not the same key re-split.
	ref, err := srv.Store.TenantMekRef(context.Background(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := vaultmek.ParseRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Handle != sweepNewHandle {
		t.Fatalf("tenant still on %q", parsed.Handle)
	}
	newMEK, err := fake.Load(context.Background(), parsed)
	if err != nil {
		t.Fatal(err)
	}
	if string(newMEK) == string(oldMEK) {
		t.Fatal("re-key produced the SAME material: compromised shares would still open the data")
	}

	// Content must still read, which proves the re-wrap was correct.
	if bodyText := readFileForSweep(t, ts, tenantID, "notes.txt"); bodyText != "second version" {
		t.Errorf("current content = %q after re-key", bodyText)
	}
}

// TestResweepRejectsForeignHandle guards the sweep against being pointed at a
// handle outside the tenant's own namespace.
func TestResweepRejectsForeignHandle(t *testing.T) {
	ts, srv := newTestServer(t)
	fake := newPerHandleMEKs()
	oldMEK := fake.seed(sweepOldHandle)
	srv.MEKs = fake
	tenantID := createTenantForSweep(t, ts)
	oldRef := vaultmek.Ref{Handle: sweepOldHandle, Endpoints: []string{"https://old-1:8443"}, Threshold: 1}
	if _, err := srv.switchTenantMEK(context.Background(), tenantID, srv.MEK, oldMEK, oldRef); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"items":[{"tenant_id":%q,"handle":"apps.privasys.org/abc123/data/ffffffffffffffffffffffffffffffff/mek/v2",
		"grant":"g","constellation":{"endpoints":["https://new-1:8443"],"mrenclave":"new00","threshold":1}}]}`, tenantID)
	resp := doSweep(t, ts, body)
	if resp.Rekeyed != 0 {
		t.Fatalf("a foreign handle was accepted: %+v", resp.Results)
	}
	if !strings.Contains(resp.Results[0].Error, "next generation") {
		t.Errorf("error = %q, want a next-generation rejection", resp.Results[0].Error)
	}
	// The tenant must be untouched.
	ref, _ := srv.Store.TenantMekRef(context.Background(), tenantID)
	if !strings.Contains(ref, sweepOldHandle) {
		t.Errorf("tenant ref moved despite the rejection: %s", ref)
	}
}

// TestResweepUnreadableOldKeyCommitsNothing covers the constellation being
// unreachable: without the old MEK nothing can be re-wrapped, and the tenant
// must be left exactly as it was.
func TestResweepUnreadableOldKeyCommitsNothing(t *testing.T) {
	ts, srv := newTestServer(t)
	fake := newPerHandleMEKs()
	oldMEK := fake.seed(sweepOldHandle)
	srv.MEKs = fake
	tenantID := createTenantForSweep(t, ts)
	oldRef := vaultmek.Ref{Handle: sweepOldHandle, Endpoints: []string{"https://old-1:8443"}, Threshold: 1}
	if _, err := srv.switchTenantMEK(context.Background(), tenantID, srv.MEK, oldMEK, oldRef); err != nil {
		t.Fatal(err)
	}
	fake.loadErrFor = sweepOldHandle

	body := fmt.Sprintf(`{"items":[{"tenant_id":%q,"handle":%q,"grant":"g",
		"constellation":{"endpoints":["https://new-1:8443"],"mrenclave":"new00","threshold":1}}]}`,
		tenantID, sweepNewHandle)
	resp := doSweep(t, ts, body)
	if resp.Rekeyed != 0 {
		t.Fatalf("re-key reported success without the old key: %+v", resp.Results)
	}
	ref, _ := srv.Store.TenantMekRef(context.Background(), tenantID)
	if !strings.Contains(ref, sweepOldHandle) {
		t.Errorf("tenant ref moved despite an unreadable old key: %s", ref)
	}
}

// TestResweepDryRunCommitsNothing proves the rehearsal really is one.
func TestResweepDryRunCommitsNothing(t *testing.T) {
	ts, srv := newTestServer(t)
	fake := newPerHandleMEKs()
	oldMEK := fake.seed(sweepOldHandle)
	srv.MEKs = fake
	tenantID := createTenantForSweep(t, ts)
	oldRef := vaultmek.Ref{Handle: sweepOldHandle, Endpoints: []string{"https://old-1:8443"}, Threshold: 1}
	if _, err := srv.switchTenantMEK(context.Background(), tenantID, srv.MEK, oldMEK, oldRef); err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"dry_run":true,"items":[{"tenant_id":%q,"handle":%q}]}`, tenantID, sweepNewHandle)
	resp := doSweep(t, ts, body)
	if len(resp.Results) != 1 || resp.Results[0].Status != "ready" {
		t.Fatalf("dry run = %+v, want one 'ready'", resp.Results)
	}
	ref, _ := srv.Store.TenantMekRef(context.Background(), tenantID)
	if !strings.Contains(ref, sweepOldHandle) {
		t.Errorf("dry run moved the tenant: %s", ref)
	}
}

// TestTenantKeysPendingHidesSubjectsAndFiltersByConstellation checks the
// operator listing: it must report the hashed owner ref (never the subject)
// and must exclude tenants already on the target constellation.
func TestTenantKeysPendingHidesSubjectsAndFiltersByConstellation(t *testing.T) {
	ts, srv := newTestServer(t)
	fake := newPerHandleMEKs()
	oldMEK := fake.seed(sweepOldHandle)
	srv.MEKs = fake
	tenantID := createTenantForSweep(t, ts)
	oldRef := vaultmek.Ref{
		Handle: sweepOldHandle, Endpoints: []string{"https://old-1:8443"},
		MrenclaveHex: "0ld0ld", Threshold: 1,
	}
	if _, err := srv.switchTenantMEK(context.Background(), tenantID, srv.MEK, oldMEK, oldRef); err != nil {
		t.Fatal(err)
	}

	var listing struct {
		Count   int `json:"count"`
		Pending []struct {
			TenantID   string `json:"tenant_id"`
			OwnerRef   string `json:"owner_ref"`
			NextHandle string `json:"next_handle"`
			Mrenclave  string `json:"mrenclave"`
		} `json:"pending"`
	}
	raw := doGet(t, ts, "/v1/admin/tenant-keys/pending?mrenclave=new00")
	if err := json.Unmarshal([]byte(raw), &listing); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	if listing.Count != 1 {
		t.Fatalf("count = %d, want 1: %s", listing.Count, raw)
	}
	e := listing.Pending[0]
	if e.OwnerRef != "deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("owner_ref = %q, want the handle's hashed segment", e.OwnerRef)
	}
	if e.NextHandle != sweepNewHandle {
		t.Errorf("next_handle = %q", e.NextHandle)
	}
	if strings.Contains(raw, "user-1") || strings.Contains(raw, "bertrand@privasys.org") {
		t.Errorf("the listing leaked a raw tenant subject: %s", raw)
	}

	// Asking about the constellation it is already on yields nothing.
	raw = doGet(t, ts, "/v1/admin/tenant-keys/pending?mrenclave=0ld0ld")
	if !strings.Contains(raw, `"count":0`) {
		t.Errorf("a tenant already on the target was still listed: %s", raw)
	}
}

// --- helpers ---------------------------------------------------------------

type sweepResponse struct {
	DryRun  bool `json:"dry_run"`
	Rekeyed int  `json:"rekeyed"`
	Results []struct {
		TenantID string `json:"tenant_id"`
		Status   string `json:"status"`
		Handle   string `json:"handle"`
		Nodes    int    `json:"rewrapped_nodes"`
		Versions int    `json:"rewrapped_versions"`
		Error    string `json:"error"`
	} `json:"results"`
}

// createTenantForSweep makes a personal tenant and returns its id.
func createTenantForSweep(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "POST", ts.URL+"/v1/tenants",
		`{"kind":"user","name":"Bertrand"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("create tenant: %d %s", resp.StatusCode, b)
	}
	var tenant store.Tenant
	if err := json.NewDecoder(resp.Body).Decode(&tenant); err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

// uploadFileForSweep writes name with the given content. Writing the same
// name twice retains the first as a previous version, which is exactly what
// the sweep has to carry across a re-key.
func uploadFileForSweep(t *testing.T, ts *httptest.Server, tenantID, name, content string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/tenants/%s/files?name=%s&mime=text/plain", ts.URL, tenantID, name)
	req, _ := http.NewRequest("POST", url, strings.NewReader(content))
	req.Header.Set("Authorization", "Bearer dev:user-1:bertrand@privasys.org")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("upload %s: %d %s", name, resp.StatusCode, b)
	}
}

// readFileForSweep downloads a file by name from the tenant's root.
func readFileForSweep(t *testing.T, ts *httptest.Server, tenantID, name string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/root", ts.URL, tenantID), ""))
	if err != nil {
		t.Fatal(err)
	}
	var listed []nodeJSON
	_ = json.NewDecoder(resp.Body).Decode(&listed)
	resp.Body.Close()
	id := ""
	for _, n := range listed {
		if n.Name == name {
			id = n.ID
		}
	}
	if id == "" {
		t.Fatalf("file %q not found in root listing %+v", name, listed)
	}
	resp, err = http.DefaultClient.Do(authedReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/files/%s", ts.URL, tenantID, id), ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("download %s: %d %s", name, resp.StatusCode, b)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func doSweep(t *testing.T, ts *httptest.Server, body string) sweepResponse {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "POST",
		ts.URL+"/v1/admin/tenant-keys/resweep", body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("resweep: %d %s", resp.StatusCode, raw)
	}
	var out sweepResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%v: %s", err, raw)
	}
	return out
}

func doGet(t *testing.T, ts *httptest.Server, path string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "GET", ts.URL+path, ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, raw)
	}
	return string(raw)
}

// replaceContentForSweep overwrites an existing file's bytes, which retains
// the superseded content as a previous version — the rows the sweep must
// re-wrap alongside the current ones.
func replaceContentForSweep(t *testing.T, ts *httptest.Server, tenantID, nodeID, content string) {
	t.Helper()
	url := fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/content", ts.URL, tenantID, nodeID)
	req, _ := http.NewRequest("PUT", url, strings.NewReader(content))
	req.Header.Set("Authorization", "Bearer dev:user-1:bertrand@privasys.org")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("replace content: %d %s", resp.StatusCode, b)
	}
}

// nodeIDByName finds a node id in the tenant's root listing.
func nodeIDByName(t *testing.T, ts *httptest.Server, tenantID, name string) string {
	t.Helper()
	resp, err := http.DefaultClient.Do(authedReq(t, "GET",
		fmt.Sprintf("%s/v1/tenants/%s/root", ts.URL, tenantID), ""))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var listed []nodeJSON
	_ = json.NewDecoder(resp.Body).Decode(&listed)
	for _, n := range listed {
		if n.Name == name {
			return n.ID
		}
	}
	t.Fatalf("file %q not found in %+v", name, listed)
	return ""
}

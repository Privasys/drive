package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/grants"
)

// S4. A request the wallet forwards without reading must not be able to select
// WHOSE data the capability lands on. Drive's rule for creating a grant is a
// user principal with write rights on the tenant, which includes enterprise
// tenants the holder merely belongs to, so a tenant id smuggled through here
// would land a capability somewhere the approval screen never named.
func TestRequestNamingAnOwnershipBoundaryIsRefused(t *testing.T) {
	refused := []struct {
		name string
		body string
	}{
		{"tenant_id at the top level", `{"folder":"Harness","tenant_id":"t-other"}`},
		{"tenant", `{"folder":"Harness","tenant":"t-other"}`},
		{"hyphenated spelling", `{"folder":"Harness","tenant-id":"t-other"}`},
		{"different case", `{"folder":"Harness","TenantID":"t-other"}`},
		{"nested inside an object", `{"folder":"Harness","opts":{"tenant_id":"t-other"}}`},
		{"nested inside an array", `{"folder":"Harness","opts":[{"tenant":"t-other"}]}`},
		{"owner selection", `{"folder":"Harness","owner_sub":"someone-else"}`},
		{"user selection", `{"folder":"Harness","user_sub":"someone-else"}`},
	}
	for _, c := range refused {
		if !namesOwnershipBoundary(json.RawMessage(c.body)) {
			t.Errorf("%s: accepted, but it selects the boundary: %s", c.name, c.body)
		}
	}
}

func TestOrdinaryRequestIsAccepted(t *testing.T) {
	allowed := []string{
		`{"folder":"Harness"}`,
		`{"folder":"Harness","purpose":"agent sessions"}`,
		// "folder" and "label" scope WITHIN the boundary, which is the whole
		// point: a request may say which resource, never whose.
		`{"folder":"Harness","label":"Sessions"}`,
		`{}`,
	}
	for _, body := range allowed {
		if namesOwnershipBoundary(json.RawMessage(body)) {
			t.Errorf("refused a request that names no boundary: %s", body)
		}
	}
	if namesOwnershipBoundary(nil) {
		t.Error("an absent request must not be treated as naming a boundary")
	}
}

// Undecodable input is refused rather than waved through, because the whole
// contract is that Drive has inspected what the wallet did not.
func TestUndecodableRequestIsTreatedAsUnsafe(t *testing.T) {
	if !namesOwnershipBoundary(json.RawMessage(`{not json`)) {
		t.Error("undecodable request was treated as safe")
	}
}

// The permissions are what the wallet DISPLAYED. Minting anything other than
// exactly those would grant something the holder never saw.
func TestScopesMirrorWhatTheWalletDisplayed(t *testing.T) {
	got, err := scopesFromPermissions([]string{"read", "write"})
	if err != nil {
		t.Fatal(err)
	}
	want := []grants.Scope{grants.ScopeRead, grants.ScopeWrite}
	if len(got) != len(want) {
		t.Fatalf("scope = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scope = %v, want %v", got, want)
		}
	}
}

func TestUnknownPermissionIsRefusedNotDropped(t *testing.T) {
	// Silently narrowing is as wrong as silently widening: either way the
	// capability stops matching the sentence the holder approved.
	if _, err := scopesFromPermissions([]string{"read", "administer"}); err == nil {
		t.Fatal("an unknown permission was accepted")
	}
}

func TestEmptyPermissionsAreRefused(t *testing.T) {
	if _, err := scopesFromPermissions(nil); err == nil {
		t.Fatal("a capability with no permissions was accepted")
	}
}

func TestDuplicatePermissionsCollapse(t *testing.T) {
	got, err := scopesFromPermissions([]string{"read", "READ", " read "})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != grants.ScopeRead {
		t.Fatalf("scope = %v, want exactly one read", got)
	}
}

// Every capability lands under AppData/<app folder>/, never at the root: the
// root of a user's Drive stays theirs however many apps they approve. The
// folder is bound to the app id: a re-approval reuses it, a different app
// asking for the same label gets a suffixed one, and a folder without a
// usable label is named from the app id.
func TestCapabilityFolderIsConfinedToAppData(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)

	approve := func(appID, folder string) (status int, out struct {
		ServiceResult map[string]string `json:"service_result"`
	}) {
		req := `{"nonce":"n1","subject_app_id":"` + appID + `","binding_pubkey":"cGs=","permissions":["read","write"],"kind":"storage.folder","request":{"folder":"` + folder + `"}}`
		resp, b := doJSON(t, "POST", ts.URL+"/v1/capabilities", devAuth, req)
		_ = json.Unmarshal(b, &out)
		return resp.StatusCode, out
	}
	childNames := func(parent string) map[string]string {
		path := "/v1/tenants/" + tenant.ID + "/root"
		if parent != "" {
			path = "/v1/tenants/" + tenant.ID + "/folders/" + parent
		}
		_, b := doJSON(t, "GET", ts.URL+path, devAuth, "")
		var nodes []struct {
			ID, Name, Kind string
		}
		_ = json.Unmarshal(b, &nodes)
		m := map[string]string{}
		for _, n := range nodes {
			if n.Kind == "folder" {
				m[n.Name] = n.ID
			}
		}
		return m
	}

	appA := "0123456789abcdef0123456789abcdef"
	st, first := approve(appA, "Harness")
	if st != 201 {
		t.Fatalf("approve: %d", st)
	}
	if first.ServiceResult["path"] != "AppData/Harness" {
		t.Fatalf("path %q, want AppData/Harness", first.ServiceResult["path"])
	}
	root := childNames("")
	if _, ok := root["Harness"]; ok {
		t.Fatal("app folder was created at the root")
	}
	appData, ok := root["AppData"]
	if !ok {
		t.Fatal("AppData folder missing at the root")
	}
	if childNames(appData)["Harness"] != first.ServiceResult["node_id"] {
		t.Fatal("granted node is not AppData/Harness")
	}

	// Re-approval by the same app reuses the folder.
	st, again := approve(appA, "Harness")
	if st != 201 || again.ServiceResult["node_id"] != first.ServiceResult["node_id"] {
		t.Fatalf("re-approval: %d node %q vs %q", st, again.ServiceResult["node_id"], first.ServiceResult["node_id"])
	}

	// A different app asking for the same label cannot take it over.
	appB := "fedcba9876543210fedcba9876543210"
	st, other := approve(appB, "Harness")
	if st != 201 {
		t.Fatalf("second app approve: %d", st)
	}
	if other.ServiceResult["node_id"] == first.ServiceResult["node_id"] {
		t.Fatal("second app was granted the first app's folder")
	}
	if other.ServiceResult["path"] != "AppData/Harness (fedcba98)" {
		t.Fatalf("second app path %q", other.ServiceResult["path"])
	}

	// No usable label and no control plane to ask: named from the app id.
	appC := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	st, byID := approve(appC, "../")
	if st != 201 || byID.ServiceResult["path"] != "AppData/app-aaaaaaaa" {
		t.Fatalf("fallback: %d path %q", st, byID.ServiceResult["path"])
	}
}

func TestSanitiseFolderName(t *testing.T) {
	cases := map[string]string{
		"  Harness ":         "Harness",
		"a/b/c":              "a-b-c",
		"..":                 "",
		"../":                "",
		"-  -":               "",
		"...hidden":          "hidden",
		"":                   "",
		strings.Repeat("x", 120): strings.Repeat("x", 100),
	}
	for in, want := range cases {
		if got := sanitiseFolderName(in); got != want {
			t.Errorf("sanitiseFolderName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveAppDisplayNameFallsBackSilently(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/apps/0123456789abcdef0123456789abcdef/resolve" {
			_, _ = w.Write([]byte(`{"app_id":"0123456789abcdef0123456789abcdef","name":"harness","display_name":"Privasys Harness"}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	if got := resolveAppDisplayName(context.Background(), srv.URL, "0123456789abcdef0123456789abcdef"); got != "Privasys Harness" {
		t.Fatalf("resolved %q", got)
	}
	if got := resolveAppDisplayName(context.Background(), srv.URL, "unknown"); got != "" {
		t.Fatalf("unknown app resolved to %q", got)
	}
	if got := resolveAppDisplayName(context.Background(), "http://127.0.0.1:1", "x"); got != "" {
		t.Fatalf("unreachable control plane resolved to %q", got)
	}
}

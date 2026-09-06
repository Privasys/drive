package api

import (
	"encoding/json"
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

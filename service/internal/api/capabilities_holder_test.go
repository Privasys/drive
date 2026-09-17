package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A second holder, with their own personal tenant.
const otherAuth = "Bearer dev:user-2:other@example.com"

// The holder-facing pair. These exist because the wallet cannot call Drive's
// own grant routes: those name the tenant in the path, and the wallet is the
// one client that must never name an ownership boundary. Everything below is
// really testing that the boundary stays derived.

func mintCapability(t *testing.T, ts *httptest.Server, appID, folder string) string {
	t.Helper()
	req := `{"nonce":"n-` + appID + `","subject_app_id":"` + appID +
		`","binding_pubkey":"cGs=","permissions":["read","write"],"kind":"storage.folder",` +
		`"request":{"folder":"` + folder + `"}}`
	resp, b := doJSON(t, "POST", ts.URL+"/v1/capabilities", devAuth, req)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("mint = %d, want 201: %s", resp.StatusCode, b)
	}
	var out struct {
		CapabilityID string `json:"capability_id"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.CapabilityID == "" {
		t.Fatal("mint returned no capability id")
	}
	return out.CapabilityID
}

func listCapabilities(t *testing.T, ts *httptest.Server, auth string) (int, []capabilityView) {
	t.Helper()
	resp, b := doJSON(t, "GET", ts.URL+"/v1/capabilities", auth, "")
	var out struct {
		Capabilities []capabilityView `json:"capabilities"`
	}
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out.Capabilities
}

func TestHolderListsWhatTheyGranted(t *testing.T) {
	ts := newFullServer(t, nil)
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")

	id := mintCapability(t, ts, "3f6d1a0e-0000-4000-8000-000000000001", "Harness")

	status, caps := listCapabilities(t, ts, devAuth)
	if status != http.StatusOK {
		t.Fatalf("list = %d, want 200", status)
	}
	if len(caps) != 1 {
		t.Fatalf("listed %d capabilities, want 1", len(caps))
	}
	got := caps[0]
	if got.CapabilityID != id {
		t.Errorf("capability_id = %q, want %q", got.CapabilityID, id)
	}
	// The holder reads back the vocabulary their wallet showed them, not
	// Drive's internal scope names.
	if len(got.Permissions) != 2 || got.Permissions[0] != "read" || got.Permissions[1] != "write" {
		t.Errorf("permissions = %v, want [read write]", got.Permissions)
	}
	if got.Kind != "storage.folder" {
		t.Errorf("kind = %q, want storage.folder", got.Kind)
	}
	// The label, not the path: the holder approved a folder name.
	if got.ResourceLabel != "Harness" {
		t.Errorf("resource_label = %q, want Harness", got.ResourceLabel)
	}
}

// An empty list and a missing route are different answers, and the wallet
// renders them differently: one says "you have nothing here", the other says
// "this service cannot be asked". The route must therefore exist and answer 200
// even with nothing to report.
func TestHolderWithNoCapabilitiesGetsAnEmptyList(t *testing.T) {
	ts := newFullServer(t, nil)
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")

	status, caps := listCapabilities(t, ts, devAuth)
	if status != http.StatusOK {
		t.Fatalf("list = %d, want 200", status)
	}
	if len(caps) != 0 {
		t.Fatalf("listed %d capabilities, want none", len(caps))
	}
}

func TestHolderRevokesAndItIsGone(t *testing.T) {
	ts := newFullServer(t, nil)
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	id := mintCapability(t, ts, "3f6d1a0e-0000-4000-8000-000000000001", "Harness")

	resp, b := doJSON(t, "DELETE", ts.URL+"/v1/capabilities/"+id, devAuth, "")
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d, want 204: %s", resp.StatusCode, b)
	}

	_, caps := listCapabilities(t, ts, devAuth)
	if len(caps) != 0 {
		t.Fatalf("still listed after revoke: %v", caps)
	}

	// Revoking again is 410, not 404. The difference matters to the wallet:
	// "already gone" is the outcome the holder asked for and can be recorded as
	// a revocation, while 404 means the service does not have it, which is a
	// different row on their screen.
	resp2, _ := doJSON(t, "DELETE", ts.URL+"/v1/capabilities/"+id, devAuth, "")
	if resp2.StatusCode != http.StatusGone {
		t.Fatalf("second revoke = %d, want 410", resp2.StatusCode)
	}
}

// The reason these routes exist at all. The tenant is derived from the
// authenticated holder, so a capability id belonging to someone else is not
// theirs to end, and the answer does not confirm that the id exists either.
func TestRevokingSomeoneElsesCapabilityIsNotFound(t *testing.T) {
	ts := newFullServer(t, nil)
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")
	id := mintCapability(t, ts, "3f6d1a0e-0000-4000-8000-000000000001", "Harness")

	// A second holder, with their own personal tenant.
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", otherAuth, "")

	resp, _ := doJSON(t, "DELETE", ts.URL+"/v1/capabilities/"+id, otherAuth, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-holder revoke = %d, want 404", resp.StatusCode)
	}

	// And it is still there for the holder who granted it.
	_, caps := listCapabilities(t, ts, devAuth)
	if len(caps) != 1 {
		t.Fatalf("owner lost their capability to someone else's revoke: %v", caps)
	}
}

func TestRevokingAnUnknownCapabilityIsNotFound(t *testing.T) {
	ts := newFullServer(t, nil)
	_, _ = doJSON(t, "POST", ts.URL+"/v1/me/tenant", devAuth, "")

	resp, _ := doJSON(t, "DELETE", ts.URL+"/v1/capabilities/no-such-id", devAuth, "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown id = %d, want 404", resp.StatusCode)
	}
}

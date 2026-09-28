package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func listFolder(t *testing.T, url, tenantID, folderID, owner string) []nodeJSON {
	t.Helper()
	u := fmt.Sprintf("%s/v1/tenants/%s/root", url, tenantID)
	if folderID != "" {
		u = fmt.Sprintf("%s/v1/tenants/%s/folders/%s", url, tenantID, folderID)
	}
	code, b := doReq(t, bearerReq(t, "GET", u, owner, ""))
	if code != http.StatusOK {
		t.Fatalf("list folder: %d %s", code, b)
	}
	var out []nodeJSON
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode listing: %v (%s)", err, b)
	}
	return out
}

func sharedMark(t *testing.T, listing []nodeJSON, id string) bool {
	t.Helper()
	for _, n := range listing {
		if n.ID == id {
			return n.Shared
		}
	}
	t.Fatalf("node %s is not in the listing", id)
	return false
}

// TestListingMarksWhatIsShared: a folder anybody else can reach says so in
// the listing, so an owner can see what has left the drive without opening
// each folder's sharing panel in turn. The mark follows the grant: it
// appears when one is minted and goes when it is revoked.
func TestListingMarksWhatIsShared(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	quiet := mkFolder(t, ts.URL, tenantID, owner, "Company", "")
	shared := mkFolder(t, ts.URL, tenantID, owner, "Fundraising", "")

	if sharedMark(t, listFolder(t, ts.URL, tenantID, "", owner), shared) {
		t.Fatal("a folder nobody can reach must not be marked shared")
	}

	code, b := doReq(t, bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/links", ts.URL, tenantID, shared),
		owner, `{"mode":"open","scope":["read"]}`))
	if code != http.StatusCreated {
		t.Fatalf("create link: %d %s", code, b)
	}
	var link struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &link); err != nil {
		t.Fatal(err)
	}

	listing := listFolder(t, ts.URL, tenantID, "", owner)
	if !sharedMark(t, listing, shared) {
		t.Fatal("a folder with a live link must be marked shared")
	}
	// The mark belongs to the node the grant sits on, not to its siblings.
	if sharedMark(t, listing, quiet) {
		t.Fatal("sharing one folder must not mark another")
	}

	code, b = doReq(t, bearerReq(t, "DELETE",
		fmt.Sprintf("%s/v1/tenants/%s/grants/%s", ts.URL, tenantID, link.ID), owner, ""))
	if code != http.StatusOK && code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", code, b)
	}
	if sharedMark(t, listFolder(t, ts.URL, tenantID, "", owner), shared) {
		t.Fatal("a revoked link must take the mark with it")
	}
}

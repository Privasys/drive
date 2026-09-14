package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/Privasys/drive/service/internal/diff"
)

type diffResponse struct {
	NodeID    string      `json:"node_id"`
	FromRev   int64       `json:"from_rev"`
	ToRev     int64       `json:"to_rev"`
	Identical bool        `json:"identical"`
	Truncated bool        `json:"truncated"`
	Hunks     []diff.Hunk `json:"hunks"`
}

func getDiff(t *testing.T, url, tenantID, nodeID, owner, query string) (int, diffResponse) {
	t.Helper()
	u := fmt.Sprintf("%s/v1/tenants/%s/nodes/%s/diff", url, tenantID, nodeID)
	if query != "" {
		u += "?" + query
	}
	code, b := doReq(t, bearerReq(t, "GET", u, owner, ""))
	var out diffResponse
	if code == http.StatusOK {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("decode diff: %v (%s)", err, b)
		}
	}
	return code, out
}

func opsOf(h diff.Hunk) string {
	var s string
	for _, l := range h.Lines {
		s += string(l.Op)
	}
	return s
}

// TestDiffDefaultsToTheLastSave: asking for a file's diff with no bounds
// answers "what the last save changed".
func TestDiffDefaultsToTheLastSave(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	replaceContent(t, ts.URL, tenantID, fileID, owner, "alpha\nbravo\ncharlie\n")
	replaceContent(t, ts.URL, tenantID, fileID, owner, "alpha\nBRAVO\ncharlie\n")

	code, got := getDiff(t, ts.URL, tenantID, fileID, owner, "")
	if code != http.StatusOK {
		t.Fatalf("diff: %d", code)
	}
	versions := listVersions(t, ts.URL, tenantID, fileID, owner)
	if got.ToRev != versions.Rev {
		t.Fatalf("to_rev should be the current revision: %d vs %d", got.ToRev, versions.Rev)
	}
	if got.FromRev != versions.Versions[1].Rev {
		t.Fatalf("from_rev should be the revision before it: %d vs %d", got.FromRev, versions.Versions[1].Rev)
	}
	if got.Identical || len(got.Hunks) != 1 {
		t.Fatalf("one changed line gives one hunk: %+v", got)
	}
	if ops := opsOf(got.Hunks[0]); ops != " -+ " && ops != " +- " {
		t.Fatalf("hunk ops %q: %+v", ops, got.Hunks[0].Lines)
	}
}

// TestDiffAcrossExplicitRevisions: any two revisions can be compared, and
// comparing one with itself is not a change.
func TestDiffAcrossExplicitRevisions(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	replaceContent(t, ts.URL, tenantID, fileID, owner, "one\ntwo\n")
	replaceContent(t, ts.URL, tenantID, fileID, owner, "one\ntwo\nthree\n")
	replaceContent(t, ts.URL, tenantID, fileID, owner, "one\ntwo\nthree\nfour\n")

	v := listVersions(t, ts.URL, tenantID, fileID, owner)
	oldest, newest := v.Versions[2].Rev, v.Rev

	code, got := getDiff(t, ts.URL, tenantID, fileID, owner,
		fmt.Sprintf("from=%d&to=%d", oldest, newest))
	if code != http.StatusOK || got.Identical {
		t.Fatalf("across three saves: %d %+v", code, got)
	}
	inserted := 0
	for _, h := range got.Hunks {
		for _, l := range h.Lines {
			if l.Op == diff.OpInsert {
				inserted++
			}
		}
	}
	if inserted == 0 {
		t.Fatalf("appended lines should show as insertions: %+v", got.Hunks)
	}

	code, got = getDiff(t, ts.URL, tenantID, fileID, owner,
		fmt.Sprintf("from=%d&to=%d", newest, newest))
	if code != http.StatusOK || !got.Identical || len(got.Hunks) != 0 {
		t.Fatalf("a revision against itself is identical: %d %+v", code, got)
	}
}

// TestDiffContextParameter: the caller decides how much unchanged text
// frames a change.
func TestDiffContextParameter(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	replaceContent(t, ts.URL, tenantID, fileID, owner, "a\nb\nc\nd\ne\n")
	replaceContent(t, ts.URL, tenantID, fileID, owner, "a\nb\nC\nd\ne\n")

	code, got := getDiff(t, ts.URL, tenantID, fileID, owner, "context=0")
	if code != http.StatusOK || len(got.Hunks) != 1 {
		t.Fatalf("context=0: %d %+v", code, got)
	}
	for _, l := range got.Hunks[0].Lines {
		if l.Op == diff.OpEqual {
			t.Fatalf("context=0 should carry no unchanged lines: %+v", got.Hunks[0].Lines)
		}
	}
}

// TestDiffWithoutHistory: a file nobody has replaced has nothing to
// compare, and says so rather than inventing an empty answer.
func TestDiffWithoutHistory(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	if code, _ := getDiff(t, ts.URL, tenantID, fileID, owner, ""); code != http.StatusNotFound {
		t.Fatalf("no earlier revision: want 404, got %d", code)
	}
}

// TestDiffRefusesNonText: comparing two images line by line tells a reader
// nothing, and would hold both in memory to do it.
func TestDiffRefusesNonText(t *testing.T) {
	ts, _ := newTestServer(t)
	const owner = "user-1"
	tenantID, _, _ := ownerTenantWithFile(t, ts.URL, owner)

	req := bearerReq(t, "POST",
		fmt.Sprintf("%s/v1/tenants/%s/files?name=photo.png&mime=image/png", ts.URL, tenantID),
		owner, "\x89PNG\r\n\x1a\n not really a png")
	req.Header.Set("Content-Type", "application/octet-stream")
	code, b := doReq(t, req)
	if code != http.StatusCreated {
		t.Fatalf("upload png: %d %s", code, b)
	}
	var img nodeJSON
	_ = json.Unmarshal(b, &img)
	replaceContent(t, ts.URL, tenantID, img.ID, owner, "still not a png")

	if code, _ := getDiff(t, ts.URL, tenantID, img.ID, owner, ""); code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-text diff: want 415, got %d", code)
	}
}

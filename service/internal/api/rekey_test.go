package api

import (
	"context"
	"encoding/json"
	"testing"
)

// After a re-key the holder signs in with Drive's new subject and finds the
// same Drive; the old identifier finds nothing; a mapping that would merge
// two people, or chain one onto another, is refused.
func TestRekeySubjects(t *testing.T) {
	base, srv := newTestServer(t)
	ctx := context.Background()

	tenantOf := func(sub string) string {
		code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/me/tenant", sub, ""))
		if code != 200 && code != 201 {
			t.Fatalf("me/tenant for %s: %d %s", sub, code, b)
		}
		var tn struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(b, &tn)
		return tn.ID
	}
	before := tenantOf("acct-1")
	other := tenantOf("acct-2")

	subs, err := srv.Store.ListSubjects(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(subs) < 2 {
		t.Fatalf("subjects listed: %v", subs)
	}

	if _, err := srv.Store.RekeySubjects(ctx, map[string]string{"acct-1": "x", "acct-2": "x"}); err == nil {
		t.Fatal("a mapping merging two people was applied")
	}
	if _, err := srv.Store.RekeySubjects(ctx, map[string]string{"acct-1": "acct-2"}); err == nil {
		t.Fatal("a mapping onto an identifier in use was applied")
	}
	if _, err := srv.Store.RekeySubjects(ctx, map[string]string{"acct-1": "drive-1", "drive-1": "drive-2"}); err == nil {
		t.Fatal("a chained mapping was applied")
	}

	counts, err := srv.Store.RekeySubjects(ctx, map[string]string{"acct-1": "drive-sub-1"})
	if err != nil {
		t.Fatal(err)
	}
	if counts["members.user_sub"] == 0 {
		t.Fatalf("no membership moved: %v", counts)
	}
	if got := tenantOf("drive-sub-1"); got != before {
		t.Fatalf("after the re-key the holder found tenant %q, want their own %q", got, before)
	}
	if got := tenantOf("acct-2"); got != other {
		t.Fatal("another holder's Drive moved")
	}
}

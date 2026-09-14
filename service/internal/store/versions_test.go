package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

// newFileNode makes a file node whose name and name-HMAC are unique by
// construction. Deriving them from the clock is not safe here: Windows
// resolves time.Now() coarsely enough that two nodes seeded in the same
// millisecond collide on the uniqueness index.
func newFileNode(t *testing.T, s *Store, tenantID string, seq int) *Node {
	t.Helper()
	n := &Node{
		TenantID: tenantID,
		Kind:     NodeFile,
		Name:     fmt.Sprintf("notes-%d.md", seq),
		NameHMAC: []byte(fmt.Sprintf("%032d", seq)),
		MimeHint: "text/markdown",
	}
	if err := s.CreateNode(context.Background(), n, "u"); err != nil {
		t.Fatalf("create node %d: %v", seq, err)
	}
	return n
}

func TestFileVersionHistory(t *testing.T) { forEachStore(t, testFileVersionHistory) }

func testFileVersionHistory(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	if err := s.CreateTenant(ctx, tt, "u"); err != nil {
		t.Fatal(err)
	}
	n := newFileNode(t, s, tt.ID, 1)

	add := func(rev, size int64, age time.Duration) {
		t.Helper()
		id := n.ID + ".v" + strconv.FormatInt(rev, 10)
		v := &FileVersion{
			TenantID: tt.ID, NodeID: n.ID, Rev: rev,
			ObjectID: id, ManifestRef: "t/6162/m/" + id,
			WrappedCEK: []byte("cek"), MerkleRoot: []byte("root"),
			PlainSize: size, MimeHint: "text/markdown", Actor: "u",
			CreatedAt: time.Now().UTC().Add(-age),
		}
		if err := s.InsertFileVersion(ctx, v); err != nil {
			t.Fatalf("insert rev %d: %v", rev, err)
		}
	}
	add(1, 100, 90*24*time.Hour)
	add(2, 200, 40*24*time.Hour)
	add(3, 300, time.Hour)
	// The same (node, rev) twice is a no-op rather than an error: a retried
	// write must not fail here.
	add(3, 300, time.Hour)

	all, err := s.ListFileVersions(ctx, tt.ID, n.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Rev != 3 || all[2].Rev != 1 {
		t.Fatalf("versions: %d rows, order %v", len(all), revsOf(all))
	}
	if all[0].ObjectID != n.ID+".v3" || string(all[0].WrappedCEK) != "cek" {
		t.Fatalf("round trip: %+v", all[0])
	}
	if limited, err := s.ListFileVersions(ctx, tt.ID, n.ID, 2); err != nil || len(limited) != 2 {
		t.Fatalf("limit: %v %v", revsOf(limited), err)
	}

	got, err := s.GetFileVersion(ctx, tt.ID, n.ID, 2)
	if err != nil || got.PlainSize != 200 {
		t.Fatalf("get rev 2: %+v %v", got, err)
	}
	if _, err := s.GetFileVersion(ctx, tt.ID, n.ID, 99); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing rev: want ErrNotFound, got %v", err)
	}

	// Only superseded content counts as history: the row matching the
	// node's current rev is live content, which the quota already counts.
	if err := setNodeRevForTest(ctx, s, tt.ID, n.ID, 3); err != nil {
		t.Fatal(err)
	}
	if b, err := s.FileVersionsBytes(ctx, tt.ID); err != nil || b != 300 {
		t.Fatalf("history bytes: want 300 (revs 1+2), got %d %v", b, err)
	}
}

func TestFileVersionEviction(t *testing.T) { forEachStore(t, testFileVersionEviction) }

func testFileVersionEviction(t *testing.T, s *Store) {
	ctx := context.Background()
	tt := &Tenant{Kind: TenantUser, Name: "u"}
	if err := s.CreateTenant(ctx, tt, "u"); err != nil {
		t.Fatal(err)
	}
	seq := 0
	// Four versions, one per day, with rev 4 as the live content.
	seed := func() *Node {
		t.Helper()
		seq++
		n := newFileNode(t, s, tt.ID, seq)
		for i := int64(1); i <= 4; i++ {
			v := &FileVersion{
				TenantID: tt.ID, NodeID: n.ID, Rev: i,
				ObjectID:  n.ID + ".v" + strconv.FormatInt(i, 10),
				PlainSize: 10,
				CreatedAt: time.Now().UTC().Add(-time.Duration(5-i) * 24 * time.Hour),
			}
			if err := s.InsertFileVersion(ctx, v); err != nil {
				t.Fatal(err)
			}
		}
		return n
	}

	// Live content is never evicted, whatever the policy says.
	n := seed()
	doomed, err := s.EvictFileVersions(ctx, tt.ID, n.ID, 4, 0, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(doomed) != 3 || containsRev(doomed, 4) {
		t.Fatalf("evict all history: removed %v", revsOf(doomed))
	}
	left, _ := s.ListFileVersions(ctx, tt.ID, n.ID, 0)
	if len(left) != 1 || left[0].Rev != 4 {
		t.Fatalf("after evicting history: %v", revsOf(left))
	}

	// Keep the newest two superseded versions.
	n = seed()
	doomed, err = s.EvictFileVersions(ctx, tt.ID, n.ID, 4, 2, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(doomed) != 1 || doomed[0].Rev != 1 {
		t.Fatalf("keep 2: removed %v", revsOf(doomed))
	}

	// Age bounds too: with the count limit slack, the cutoff alone decides.
	// The seeded revisions are 4, 3 and 2 days old (rev 4 is live), so a
	// 2.5 day cutoff keeps rev 3 and sweeps revs 1 and 2.
	n = seed()
	doomed, err = s.EvictFileVersions(ctx, tt.ID, n.ID, 4, 10, time.Now().UTC().Add(-60*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(doomed) != 2 || !containsRev(doomed, 1) || !containsRev(doomed, 2) {
		t.Fatalf("age cutoff: removed %v", revsOf(doomed))
	}
	left, _ = s.ListFileVersions(ctx, tt.ID, n.ID, 0)
	if len(left) != 2 || left[0].Rev != 4 || left[1].Rev != 3 {
		t.Fatalf("after age cutoff: %v", revsOf(left))
	}
}

// setNodeRevForTest points a node at a rev so the history/live split can be
// asserted without going through a content write.
func setNodeRevForTest(ctx context.Context, s *Store, tenantID, nodeID string, rev int64) error {
	_, err := s.DB.ExecContext(ctx, s.q(
		`UPDATE nodes SET rev = ? WHERE tenant_id = ? AND id = ?`), rev, tenantID, nodeID)
	return err
}

func revsOf(vs []*FileVersion) []int64 {
	out := make([]int64, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Rev)
	}
	return out
}

func containsRev(vs []*FileVersion, rev int64) bool {
	for _, v := range vs {
		if v.Rev == rev {
			return true
		}
	}
	return false
}

package api

import (
	"testing"

	"github.com/Privasys/drive/service/internal/store"
)

// TestResetStaleProcessing: files orphaned in 'processing' by a restart are
// flipped back to 'pending' (the only status the retry sweep looks at), and
// terminal states are left alone. This is the boot-time recovery the prod
// stall exposed: without it, a file caught mid-index by a restart stayed
// "Indexing…" forever.
func TestResetStaleProcessing(t *testing.T) {
	ts, srv := newTestServer(t)
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)
	tenantB, fileB, _ := ownerTenantWithFile(t, ts.URL, "user-2")

	if err := srv.Store.SetIndexStatus(t.Context(), tenantID, fileID, store.IndexProcessing); err != nil {
		t.Fatal(err)
	}
	if err := srv.Store.SetIndexStatus(t.Context(), tenantB, fileB, store.IndexIndexed); err != nil {
		t.Fatal(err)
	}

	n, err := srv.Store.ResetStaleProcessing(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("reset %d rows, want exactly the orphaned one", n)
	}
	if st, _, _ := srv.Store.NodeIndexMeta(t.Context(), tenantID, fileID); st != store.IndexPending {
		t.Fatalf("orphaned file status %q, want pending", st)
	}
	if st, _, _ := srv.Store.NodeIndexMeta(t.Context(), tenantB, fileB); st != store.IndexIndexed {
		t.Fatalf("indexed file was touched: %q", st)
	}
}

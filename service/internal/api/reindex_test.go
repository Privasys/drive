package api

import (
	"testing"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/store"
)

// TestReindexOnEmbeddingSpaceChange: configuring a different embedding
// backend flips indexed files back to pending (the scheduled background
// reindex); re-saving the same config does not.
func TestReindexOnEmbeddingSpaceChange(t *testing.T) {
	ts, srv := newTestServer(t)
	srv.StateDir = t.TempDir()
	const owner = "user-1"
	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)

	// Simulate a lexical-space indexed file.
	if err := srv.Store.SetIndexStatus(t.Context(), tenantID, fileID, store.IndexIndexed); err != nil {
		t.Fatal(err)
	}
	base := &config.Config{Mode: config.ModeSovereign}
	srv.InstallConfig(base)

	// Same space (still lexical): no reset.
	if err := srv.SetConfig(&config.Config{Mode: config.ModeSovereign, QuotaDefaultBytes: 1 << 30}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := srv.Store.NodeIndexMeta(t.Context(), tenantID, fileID); st != store.IndexIndexed {
		t.Fatalf("same space reset the index: %q", st)
	}

	// Fleet model configured: space changes, file reset to pending.
	if err := srv.SetConfig(&config.Config{
		Mode:              config.ModeSovereign,
		EmbeddingsBaseURL: "https://fleet.example",
		EmbeddingsModel:   "qwen3-embedding-0.6b",
	}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := srv.Store.NodeIndexMeta(t.Context(), tenantID, fileID); st != store.IndexPending {
		t.Fatalf("space change did not schedule reindex: %q", st)
	}
}

package api

import (
	"context"
	"testing"

	"github.com/Privasys/drive/service/internal/store"
)

// A file the index marked failed gets one more attempt the first time a new
// build boots, and no more than that: a fix ships in a build, so a build is
// when a past failure may succeed, but a file that can never be indexed must
// not be retried on every restart.
func TestFailedFilesRetryOncePerBuild(t *testing.T) {
	ts, srv := newTestServer(t)
	srv.StateDir = t.TempDir() // where the per-build marker is kept
	const owner = "user-1"
	ctx := context.Background()

	tenantID, fileID, _ := ownerTenantWithFile(t, ts.URL, owner)
	status := func() string {
		t.Helper()
		meta, err := srv.Store.ListNodeMeta(ctx, tenantID, []string{fileID})
		if err != nil {
			t.Fatal(err)
		}
		return meta[fileID].IndexStatus
	}
	fail := func() {
		t.Helper()
		if err := srv.Store.SetIndexStatus(ctx, tenantID, fileID, store.IndexFailed); err != nil {
			t.Fatal(err)
		}
	}

	srv.Version = "build-1"
	fail()
	srv.retryFailedOncePerBuild()
	if got := status(); got != store.IndexPending {
		t.Fatalf("a new build must retry a failed file: status %q", got)
	}

	fail()
	srv.retryFailedOncePerBuild()
	if got := status(); got != store.IndexFailed {
		t.Fatalf("the same build must not retry it again on restart: status %q", got)
	}

	srv.Version = "build-2"
	srv.retryFailedOncePerBuild()
	if got := status(); got != store.IndexPending {
		t.Fatalf("the next build must retry it once more: status %q", got)
	}
}

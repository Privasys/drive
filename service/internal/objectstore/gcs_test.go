package objectstore

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

// TestGCS_RoundTrip runs the Backend contract against a real bucket when
// DRIVE_TEST_GCS_BUCKET (+ optional DRIVE_TEST_GCS_KEY_FILE) are set;
// skipped otherwise so the default test run needs no cloud access.
func TestGCS_RoundTrip(t *testing.T) {
	bucket := os.Getenv("DRIVE_TEST_GCS_BUCKET")
	if bucket == "" {
		t.Skip("set DRIVE_TEST_GCS_BUCKET to run the GCS integration test")
	}
	var creds []byte
	if kf := os.Getenv("DRIVE_TEST_GCS_KEY_FILE"); kf != "" {
		b, err := os.ReadFile(kf)
		if err != nil {
			t.Fatal(err)
		}
		creds = b
	}
	ctx := context.Background()
	g, err := NewGCS(ctx, GCSConfig{Bucket: bucket, CredentialsJSON: creds})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()

	key := "t/testprefix/c/ab/" + t.Name()
	defer g.Delete(ctx, key)

	// Missing key: Head/Get report ErrNotFound.
	if _, err := g.Head(ctx, key); err != ErrNotFound {
		t.Fatalf("head missing: want ErrNotFound, got %v", err)
	}
	if _, err := g.GetChunk(ctx, key); err != ErrNotFound {
		t.Fatalf("get missing: want ErrNotFound, got %v", err)
	}

	// Put, Head, Get.
	payload := []byte("privasys drive gcs backend — sealed ciphertext")
	if err := g.PutChunk(ctx, key, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("put: %v", err)
	}
	if sz, err := g.Head(ctx, key); err != nil || sz != int64(len(payload)) {
		t.Fatalf("head: sz=%d err=%v", sz, err)
	}
	rc, err := g.GetChunk(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}

	// Idempotent re-put of the same content.
	if err := g.PutChunk(ctx, key, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("re-put: %v", err)
	}

	// Delete, then it's gone; deleting again is not an error.
	if err := g.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := g.Head(ctx, key); err != ErrNotFound {
		t.Fatalf("head after delete: want ErrNotFound, got %v", err)
	}
	if err := g.Delete(ctx, key); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

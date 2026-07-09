package objectstore

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// mockS3 is a minimal in-memory S3-compatible server (path-style) that
// speaks enough of the protocol for the Backend contract: PUT/GET/HEAD/
// DELETE and a NoSuchKey 404. It ignores SigV4 (signing is a client
// concern), so it validates the adapter's request construction and, in
// particular, its 404/not-found handling against a real HTTP round-trip.
func mockS3(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	var mu sync.Mutex
	objects := map[string][]byte{}
	const bucket = "drivetest"

	h := func(w http.ResponseWriter, r *http.Request) {
		// path-style: /{bucket}/{key...}
		p := strings.TrimPrefix(r.URL.Path, "/"+bucket+"/")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			objects[p] = body
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			b, ok := objects[p]
			if !ok {
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprintf(w, `<?xml version="1.0"?><Error><Code>NoSuchKey</Code><Message>no</Message><Key>%s</Key></Error>`, p)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
			w.Write(b)
		case http.MethodHead:
			b, ok := objects[p]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(b)))
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(objects, p)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
	ts := httptest.NewServer(http.HandlerFunc(h))
	t.Cleanup(ts.Close)
	return ts, bucket
}

func TestS3_ContractAgainstMock(t *testing.T) {
	ts, bucket := mockS3(t)
	ctx := context.Background()
	b, err := NewS3(ctx, S3Config{
		Bucket: bucket, Region: "us-east-1", Endpoint: ts.URL,
		AccessKey: "ak", SecretKey: "sk", PathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	runBackendContract(t, ctx, b)
}

// runBackendContract exercises Put/Head/Get/Delete + not-found + a
// re-put on any Backend.
func runBackendContract(t *testing.T, ctx context.Context, b Backend) {
	t.Helper()
	key := "t/pfx/c/ab/deadbeef"

	if _, err := b.Head(ctx, key); err != ErrNotFound {
		t.Fatalf("head missing: want ErrNotFound, got %v", err)
	}
	if _, err := b.GetChunk(ctx, key); err != ErrNotFound {
		t.Fatalf("get missing: want ErrNotFound, got %v", err)
	}

	payload := []byte("s3 backend contract — opaque ciphertext")
	if err := b.PutChunk(ctx, key, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("put: %v", err)
	}
	if sz, err := b.Head(ctx, key); err != nil || sz != int64(len(payload)) {
		t.Fatalf("head: sz=%d err=%v", sz, err)
	}
	rc, err := b.GetChunk(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(rc)
	rc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("roundtrip mismatch: %q", got)
	}
	if err := b.PutChunk(ctx, key, bytes.NewReader(payload), int64(len(payload))); err != nil {
		t.Fatalf("re-put: %v", err)
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := b.Head(ctx, key); err != ErrNotFound {
		t.Fatalf("head after delete: want ErrNotFound, got %v", err)
	}
	if err := b.Delete(ctx, key); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

// TestS3_RoundTrip runs against a real S3-compatible endpoint when the
// env is set (MinIO, OVH, AWS). Skipped otherwise.
func TestS3_RoundTrip(t *testing.T) {
	bucket := os.Getenv("DRIVE_TEST_S3_BUCKET")
	if bucket == "" {
		t.Skip("set DRIVE_TEST_S3_BUCKET (+ endpoint/keys) to run the S3 integration test")
	}
	ctx := context.Background()
	b, err := NewS3(ctx, S3Config{
		Bucket:    bucket,
		Region:    os.Getenv("DRIVE_TEST_S3_REGION"),
		Endpoint:  os.Getenv("DRIVE_TEST_S3_ENDPOINT"),
		AccessKey: os.Getenv("DRIVE_TEST_S3_ACCESS_KEY"),
		SecretKey: os.Getenv("DRIVE_TEST_S3_SECRET_KEY"),
	})
	if err != nil {
		t.Fatal(err)
	}
	runBackendContract(t, ctx, b)
}

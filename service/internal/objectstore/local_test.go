package objectstore

import (
	"bytes"
	"context"
	"io"
	"path"
	"testing"
)

func TestLocalBackend_RoundTripAndDelete(t *testing.T) {
	dir := t.TempDir()
	b, err := NewLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	key := path.Join("t", "abc", "c", "ab", "abcdef0123")
	body := []byte("hello drive chunk")

	if err := b.PutChunk(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	size, err := b.Head(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if size != int64(len(body)) {
		t.Fatalf("Head size mismatch: got %d want %d", size, len(body))
	}
	r, err := b.GetChunk(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("get returned %q", got)
	}

	if err := b.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Head(ctx, key); err != ErrNotFound {
		t.Fatalf("Head after delete: got %v want ErrNotFound", err)
	}
	// Delete a missing key is OK.
	if err := b.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
}

func TestLocalBackend_RejectsTraversal(t *testing.T) {
	b, _ := NewLocal(t.TempDir())
	ctx := context.Background()
	if err := b.PutChunk(ctx, "../escape", bytes.NewReader([]byte("x")), 1); err == nil {
		t.Fatal("traversal must be rejected")
	}
}

func TestLocalBackend_PutOverwriteIsIdempotent(t *testing.T) {
	b, _ := NewLocal(t.TempDir())
	ctx := context.Background()
	key := "k"
	body := []byte("same")
	if err := b.PutChunk(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
	if err := b.PutChunk(ctx, key, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}
}

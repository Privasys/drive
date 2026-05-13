package manifest

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"testing"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/objectstore"
)

func newBackend(t *testing.T) objectstore.Backend {
	t.Helper()
	b, err := objectstore.NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTrip_SmallFile(t *testing.T) {
	b := newBackend(t)
	dek, _ := crypto.RandomKey()
	plain := []byte("hello, drive! this is a small file.")

	wr, err := Write(context.Background(), b, dek, "tenant-x", "file-1", "text/plain", 0, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if wr.Manifest.PlainSize != int64(len(plain)) {
		t.Fatalf("PlainSize = %d, want %d", wr.Manifest.PlainSize, len(plain))
	}
	if len(wr.Manifest.Chunks) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(wr.Manifest.Chunks))
	}
	if wr.Manifest.MerkleRoot == "" {
		t.Fatal("missing Merkle root")
	}

	_, rc, err := Read(context.Background(), b, dek, "tenant-x", "file-1", wr.WrappedCEK)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip plaintext mismatch")
	}
}

func TestRoundTrip_MultiChunk(t *testing.T) {
	b := newBackend(t)
	dek, _ := crypto.RandomKey()

	// 5 chunks at 1 KiB each.
	chunkSize := uint32(1024)
	plain := make([]byte, 5*int(chunkSize)+123)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}
	wr, err := Write(context.Background(), b, dek, "t", "f", "", chunkSize, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if len(wr.Manifest.Chunks) != 6 {
		t.Fatalf("want 6 chunks, got %d", len(wr.Manifest.Chunks))
	}
	_, rc, err := Read(context.Background(), b, dek, "t", "f", wr.WrappedCEK)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch (lengths %d vs %d)", len(got), len(plain))
	}
}

func TestRead_DetectsBackendTampering(t *testing.T) {
	b := newBackend(t)
	dek, _ := crypto.RandomKey()
	plain := bytes.Repeat([]byte("x"), 10_000)
	wr, err := Write(context.Background(), b, dek, "t", "f", "", 1024, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the first chunk on the backend.
	ck := chunkKey("t", wr.Manifest.Chunks[0].CipherHash)
	rc, err := b.GetChunk(context.Background(), ck)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rc)
	rc.Close()
	body[0] ^= 0x01
	if err := b.PutChunk(context.Background(), ck, bytes.NewReader(body), int64(len(body))); err != nil {
		t.Fatal(err)
	}

	_, pr, err := Read(context.Background(), b, dek, "t", "f", wr.WrappedCEK)
	if err != nil {
		// fail fast at manifest open is fine, but in our model the
		// chunk hash check fires inside the streaming goroutine.
		return
	}
	defer pr.Close()
	if _, err := io.ReadAll(pr); err == nil {
		t.Fatal("tampered chunk must surface an error")
	}
}

func TestDelete_RemovesChunks(t *testing.T) {
	b := newBackend(t)
	dek, _ := crypto.RandomKey()
	plain := bytes.Repeat([]byte("y"), 3000)
	wr, err := Write(context.Background(), b, dek, "t", "f", "", 1024, bytes.NewReader(plain))
	if err != nil {
		t.Fatal(err)
	}
	if err := Delete(context.Background(), b, dek, "t", "f", wr.WrappedCEK); err != nil {
		t.Fatal(err)
	}
	for _, c := range wr.Manifest.Chunks {
		if _, err := b.Head(context.Background(), chunkKey("t", c.CipherHash)); err != objectstore.ErrNotFound {
			t.Fatalf("chunk %d not deleted: %v", c.Index, err)
		}
	}
	if _, err := b.Head(context.Background(), manifestKey("t", "f")); err != objectstore.ErrNotFound {
		t.Fatal("manifest not deleted")
	}
}

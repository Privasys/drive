// Package manifest implements the per-file Privasys Drive manifest:
// chunk it, AEAD-seal it, content-address it, build a Merkle root, wrap
// the per-file CEK under a tenant DEK, and stream it back out.
package manifest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/objectstore"
)

// Chunk records a single sealed chunk inside a file's manifest.
type Chunk struct {
	Index      uint32 `json:"i"`
	CipherHash string `json:"h"` // hex(SHA256(ciphertext))
	Nonce      string `json:"n"` // hex(192-bit XChaCha20 nonce)
	Size       uint32 `json:"s"` // ciphertext length (incl. AEAD tag)
}

// Manifest is the canonical, deterministic per-file index. It is
// AEAD-sealed under the per-file CEK before being persisted.
type Manifest struct {
	Version    int     `json:"v"`
	PlainSize  int64   `json:"p"` // sum of plaintext chunk sizes
	ChunkSize  uint32  `json:"c"` // max plaintext per chunk
	MerkleRoot string  `json:"m"` // hex(MerkleRoot of CipherHashes)
	Chunks     []Chunk `json:"k"`
	MimeHint   string  `json:"t,omitempty"`
}

// WriteResult is what the API hands back to the caller after a write.
type WriteResult struct {
	Manifest    Manifest
	WrappedCEK  []byte // wrap(DEK_tenant, CEK_file)
	ManifestKey string // backend key where sealed manifest lives
	ManifestCT  []byte // sealed manifest bytes (also persisted)
}

const currentVersion = 1

// keyPrefix returns the per-tenant prefix used for every backend key.
// We hex-encode for case-insensitive bucket safety.
func keyPrefix(tenantID string) string {
	tp := hex.EncodeToString([]byte(tenantID))
	if len(tp) > 16 {
		tp = tp[:16]
	}
	return path.Join("t", tp)
}

func chunkKey(tenantID, hexHash string) string {
	// Two-level fan-out so a single bucket dir does not get pathological.
	return path.Join(keyPrefix(tenantID), "c", hexHash[:2], hexHash)
}

func manifestKey(tenantID, fileID string) string {
	return path.Join(keyPrefix(tenantID), "m", fileID)
}

// Write reads plaintext from r, chunks + AEAD-seals each chunk under a
// fresh per-file CEK, persists the chunks via backend, builds a Merkle
// root + sealed manifest, and persists the manifest.
//
// chunkSize is the maximum plaintext payload per chunk; pass
// crypto.MaxChunkSize unless you have a reason to override it.
func Write(
	ctx context.Context,
	backend objectstore.Backend,
	dek []byte,
	tenantID, fileID, mimeHint string,
	chunkSize uint32,
	r io.Reader,
) (*WriteResult, error) {
	if chunkSize == 0 || chunkSize > crypto.MaxChunkSize {
		chunkSize = crypto.MaxChunkSize
	}
	cek, err := crypto.RandomKey()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, chunkSize)
	var (
		chunks       []Chunk
		cipherHashes [][]byte
		index        uint32
		plainSize    int64
	)
	for {
		n, rerr := io.ReadFull(r, buf)
		if n == 0 {
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				break
			}
			if rerr != nil {
				return nil, rerr
			}
		}
		nonce, err := crypto.RandomNonce()
		if err != nil {
			return nil, err
		}
		// AAD binds chunk position + file id so a chunk cannot be moved
		// between slots or reused across files.
		aad := chunkAAD(fileID, index)
		ct, err := crypto.Seal(cek, nonce, buf[:n], aad)
		if err != nil {
			return nil, err
		}
		hash := crypto.HashChunk(ct)
		hexHash := hex.EncodeToString(hash)
		key := chunkKey(tenantID, hexHash)
		if err := backend.PutChunk(ctx, key, bytes.NewReader(ct), int64(len(ct))); err != nil {
			return nil, fmt.Errorf("manifest: put chunk %d: %w", index, err)
		}
		chunks = append(chunks, Chunk{
			Index:      index,
			CipherHash: hexHash,
			Nonce:      hex.EncodeToString(nonce),
			Size:       uint32(len(ct)),
		})
		cipherHashes = append(cipherHashes, hash)
		plainSize += int64(n)
		index++

		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}

	root := crypto.MerkleRoot(cipherHashes)
	man := Manifest{
		Version:    currentVersion,
		PlainSize:  plainSize,
		ChunkSize:  chunkSize,
		MerkleRoot: hex.EncodeToString(root),
		Chunks:     chunks,
		MimeHint:   mimeHint,
	}
	manBytes, err := json.Marshal(man)
	if err != nil {
		return nil, err
	}
	manNonce, err := crypto.RandomNonce()
	if err != nil {
		return nil, err
	}
	sealed, err := crypto.Seal(cek, manNonce, manBytes, manifestAAD(fileID))
	if err != nil {
		return nil, err
	}
	// Prepend the manifest nonce so we can persist a single blob.
	manBlob := append(append([]byte{}, manNonce...), sealed...)
	mk := manifestKey(tenantID, fileID)
	if err := backend.PutChunk(ctx, mk, bytes.NewReader(manBlob), int64(len(manBlob))); err != nil {
		return nil, fmt.Errorf("manifest: put manifest: %w", err)
	}

	wrapped, err := crypto.WrapKey(dek, cek)
	if err != nil {
		return nil, err
	}
	return &WriteResult{
		Manifest:    man,
		WrappedCEK:  wrapped,
		ManifestKey: mk,
		ManifestCT:  manBlob,
	}, nil
}

// Read returns a streaming io.ReadCloser over the plaintext file
// reconstructed from backend + the on-disk manifest.
func Read(
	ctx context.Context,
	backend objectstore.Backend,
	dek []byte,
	tenantID, fileID string,
	wrappedCEK []byte,
) (Manifest, io.ReadCloser, error) {
	cek, err := crypto.UnwrapKey(dek, wrappedCEK)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("manifest: unwrap CEK: %w", err)
	}
	mk := manifestKey(tenantID, fileID)
	rc, err := backend.GetChunk(ctx, mk)
	if err != nil {
		return Manifest{}, nil, err
	}
	defer rc.Close()
	manBlob, err := io.ReadAll(rc)
	if err != nil {
		return Manifest{}, nil, err
	}
	if len(manBlob) < crypto.NonceSize {
		return Manifest{}, nil, errors.New("manifest: short manifest blob")
	}
	manNonce := manBlob[:crypto.NonceSize]
	manCT := manBlob[crypto.NonceSize:]
	manBytes, err := crypto.Open(cek, manNonce, manCT, manifestAAD(fileID))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("manifest: open manifest: %w", err)
	}
	var man Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return Manifest{}, nil, err
	}
	if man.Version != currentVersion {
		return Manifest{}, nil, fmt.Errorf("manifest: unsupported version %d", man.Version)
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		for _, c := range man.Chunks {
			ct, err := readChunk(ctx, backend, tenantID, c)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			nonce, err := hex.DecodeString(c.Nonce)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			pt, err := crypto.Open(cek, nonce, ct, chunkAAD(fileID, c.Index))
			if err != nil {
				pw.CloseWithError(fmt.Errorf("manifest: open chunk %d: %w", c.Index, err))
				return
			}
			if _, err := pw.Write(pt); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
	}()
	return man, pr, nil
}

func readChunk(ctx context.Context, backend objectstore.Backend, tenantID string, c Chunk) ([]byte, error) {
	rc, err := backend.GetChunk(ctx, chunkKey(tenantID, c.CipherHash))
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	ct, err := io.ReadAll(rc)
	if err != nil {
		return nil, err
	}
	if uint32(len(ct)) != c.Size {
		return nil, fmt.Errorf("manifest: chunk %d size mismatch (got %d want %d)", c.Index, len(ct), c.Size)
	}
	if hex.EncodeToString(crypto.HashChunk(ct)) != c.CipherHash {
		return nil, fmt.Errorf("manifest: chunk %d hash mismatch (tampered backend)", c.Index)
	}
	return ct, nil
}

func chunkAAD(fileID string, index uint32) []byte {
	b := make([]byte, 0, len(fileID)+5)
	b = append(b, "f:"...)
	b = append(b, fileID...)
	b = append(b, ':')
	var ix [4]byte
	crypto.PutUint32(ix[:], index)
	b = append(b, ix[:]...)
	return b
}

func manifestAAD(fileID string) []byte {
	return []byte("m:" + fileID)
}

// Delete removes the manifest + every chunk it references. Best-effort:
// missing chunks are ignored so partial writes can be cleaned up.
func Delete(
	ctx context.Context,
	backend objectstore.Backend,
	dek []byte,
	tenantID, fileID string,
	wrappedCEK []byte,
) error {
	man, rc, err := Read(ctx, backend, dek, tenantID, fileID, wrappedCEK)
	if err != nil {
		// If we cannot decrypt, still drop the raw blobs we know about.
		_ = backend.Delete(ctx, manifestKey(tenantID, fileID))
		return err
	}
	rc.Close()
	for _, c := range man.Chunks {
		_ = backend.Delete(ctx, chunkKey(tenantID, c.CipherHash))
	}
	return backend.Delete(ctx, manifestKey(tenantID, fileID))
}

// ReadMeta opens a file's sealed manifest and returns it (plaintext size,
// chunk size, chunk table) plus the unwrapped CEK, without streaming any
// content. It is the cheap half of Read: a caller that only needs the size,
// or that will fetch a byte range, avoids decrypting the whole file.
func ReadMeta(ctx context.Context, backend objectstore.Backend, dek []byte, tenantID, fileID string, wrappedCEK []byte) (Manifest, []byte, error) {
	cek, err := crypto.UnwrapKey(dek, wrappedCEK)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("manifest: unwrap CEK: %w", err)
	}
	rc, err := backend.GetChunk(ctx, manifestKey(tenantID, fileID))
	if err != nil {
		return Manifest{}, nil, err
	}
	defer rc.Close()
	manBlob, err := io.ReadAll(rc)
	if err != nil {
		return Manifest{}, nil, err
	}
	if len(manBlob) < crypto.NonceSize {
		return Manifest{}, nil, errors.New("manifest: short manifest blob")
	}
	manBytes, err := crypto.Open(cek, manBlob[:crypto.NonceSize], manBlob[crypto.NonceSize:], manifestAAD(fileID))
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("manifest: open manifest: %w", err)
	}
	var man Manifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		return Manifest{}, nil, err
	}
	if man.Version != currentVersion {
		return Manifest{}, nil, fmt.Errorf("manifest: unsupported version %d", man.Version)
	}
	return man, cek, nil
}

// ReadRange streams length plaintext bytes starting at offset, decrypting only
// the chunks that cover the range (D4). A negative or zero length means "to
// the end". offset past the end yields an empty stream. The plaintext never
// touches a disk; only the covering chunks are fetched and opened.
func ReadRange(ctx context.Context, backend objectstore.Backend, dek []byte, tenantID, fileID string, wrappedCEK []byte, offset, length int64) (io.ReadCloser, int64, error) {
	man, cek, err := ReadMeta(ctx, backend, dek, tenantID, fileID, wrappedCEK)
	if err != nil {
		return nil, 0, err
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= man.PlainSize {
		return io.NopCloser(bytes.NewReader(nil)), 0, nil
	}
	end := man.PlainSize // exclusive
	if length > 0 && offset+length < end {
		end = offset + length
	}
	total := end - offset
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		// Chunk boundaries are not uniform once a file has been appended to
		// (the last chunk before an append may be short), so walk the
		// per-chunk plaintext lengths rather than dividing by ChunkSize.
		pos := int64(0)
		for _, c := range man.Chunks {
			plen := c.PlainLen()
			cstart, cend := pos, pos+plen
			pos = cend
			if cend <= offset {
				continue
			}
			if cstart >= end {
				break
			}
			ct, err := readChunk(ctx, backend, tenantID, c)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			nonce, err := hex.DecodeString(c.Nonce)
			if err != nil {
				pw.CloseWithError(err)
				return
			}
			pt, err := crypto.Open(cek, nonce, ct, chunkAAD(fileID, c.Index))
			if err != nil {
				pw.CloseWithError(fmt.Errorf("manifest: open chunk %d: %w", c.Index, err))
				return
			}
			if int64(len(pt)) != plen {
				pw.CloseWithError(fmt.Errorf("manifest: chunk %d plaintext length %d, expected %d", c.Index, len(pt), plen))
				return
			}
			lo := int64(0)
			if offset > cstart {
				lo = offset - cstart
			}
			hi := plen
			if end < cend {
				hi = end - cstart
			}
			if _, err := pw.Write(pt[lo:hi]); err != nil {
				pw.CloseWithError(err)
				return
			}
		}
	}()
	return pr, total, nil
}

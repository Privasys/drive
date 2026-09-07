package manifest

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/objectstore"
)

// chunkOverhead is the AEAD expansion of every sealed chunk (the
// XChaCha20-Poly1305 tag), so a chunk's plaintext length is recoverable
// from its ciphertext size without a manifest field: older manifests carry
// no per-chunk plaintext size and must keep reading.
const chunkOverhead = 16

// PlainLen is the plaintext length of a sealed chunk.
func (c Chunk) PlainLen() int64 {
	if int64(c.Size) < chunkOverhead {
		return 0
	}
	return int64(c.Size) - chunkOverhead
}

// Append seals the bytes from r as NEW chunks after a file's existing
// ones, under the file's existing CEK, and rewrites only the manifest (D3).
// Cost is proportional to the append, not the file: existing chunks are
// untouched and content-addressed. The last existing chunk may be shorter
// than ChunkSize, so chunk boundaries are no longer uniform; ReadRange
// walks per-chunk plaintext lengths rather than assuming them. The
// returned WriteResult re-wraps the same CEK (a fresh wrap of the same
// key, so a caller may store it unchanged).
func Append(
	ctx context.Context,
	backend objectstore.Backend,
	dek []byte,
	tenantID, fileID string,
	wrappedCEK []byte,
	r io.Reader,
) (*WriteResult, error) {
	man, cek, err := ReadMeta(ctx, backend, dek, tenantID, fileID, wrappedCEK)
	if err != nil {
		return nil, err
	}
	chunkSize := man.ChunkSize
	if chunkSize == 0 || chunkSize > crypto.MaxChunkSize {
		chunkSize = crypto.MaxChunkSize
	}
	cipherHashes := make([][]byte, 0, len(man.Chunks)+1)
	for _, c := range man.Chunks {
		h, herr := hex.DecodeString(c.CipherHash)
		if herr != nil {
			return nil, fmt.Errorf("manifest: bad chunk hash: %w", herr)
		}
		cipherHashes = append(cipherHashes, h)
	}
	buf := make([]byte, chunkSize)
	index := uint32(len(man.Chunks))
	var added int64
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
		ct, err := crypto.Seal(cek, nonce, buf[:n], chunkAAD(fileID, index))
		if err != nil {
			return nil, err
		}
		hash := crypto.HashChunk(ct)
		hexHash := hex.EncodeToString(hash)
		if err := backend.PutChunk(ctx, chunkKey(tenantID, hexHash), bytes.NewReader(ct), int64(len(ct))); err != nil {
			return nil, fmt.Errorf("manifest: put chunk %d: %w", index, err)
		}
		man.Chunks = append(man.Chunks, Chunk{
			Index: index, CipherHash: hexHash, Nonce: hex.EncodeToString(nonce), Size: uint32(len(ct)),
		})
		cipherHashes = append(cipherHashes, hash)
		added += int64(n)
		index++
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	man.PlainSize += added
	man.MerkleRoot = hex.EncodeToString(crypto.MerkleRoot(cipherHashes))

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
	manBlob := append(append([]byte{}, manNonce...), sealed...)
	mk := manifestKey(tenantID, fileID)
	if err := backend.PutChunk(ctx, mk, bytes.NewReader(manBlob), int64(len(manBlob))); err != nil {
		return nil, fmt.Errorf("manifest: put manifest: %w", err)
	}
	wrapped, err := crypto.WrapKey(dek, cek)
	if err != nil {
		return nil, err
	}
	return &WriteResult{Manifest: man, WrappedCEK: wrapped, ManifestKey: mk, ManifestCT: manBlob}, nil
}

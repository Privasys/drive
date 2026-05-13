// Package crypto provides the cryptographic primitives used by Privasys Drive:
// per-tenant DEK derivation, AEAD chunk sealing, name HMAC, Merkle root
// over chunk ciphertext, and per-file CEK wrapping.
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// KeySize is the byte length of every symmetric key in the system.
const KeySize = 32

// NonceSize is the byte length of XChaCha20-Poly1305 nonces.
const NonceSize = chacha20poly1305.NonceSizeX

// HMACSize is the byte length of a name HMAC tag (HMAC-SHA-256).
const HMACSize = sha256.Size

// HashSize is the byte length of chunk content hashes (SHA-256).
const HashSize = sha256.Size

// MaxChunkSize is the largest plaintext-byte payload allowed per chunk.
// 4 MiB is a good trade-off for parallel uploads + small manifests.
const MaxChunkSize = 4 * 1024 * 1024

// HKDF labels. Keep these stable. New uses get new labels (versioned).
const (
	LabelDEK      = "privasys-drive/dek/v1"
	LabelNameHMAC = "privasys-drive/name-hmac/v1"
	LabelLink     = "privasys-drive/link/v1"
)

// DeriveDEK returns the per-tenant data encryption key from a master key.
func DeriveDEK(mek []byte, tenantID string) ([]byte, error) {
	return hkdfExpand(mek, LabelDEK, []byte(tenantID), KeySize)
}

// DeriveNameHMACKey returns the per-tenant key used to HMAC node names.
func DeriveNameHMACKey(mek []byte, tenantID string) ([]byte, error) {
	return hkdfExpand(mek, LabelNameHMAC, []byte(tenantID), KeySize)
}

// DeriveLinkKey wraps a static-link secret into a CEK-wrap key.
func DeriveLinkKey(linkSecret []byte) ([]byte, error) {
	return hkdfExpand(linkSecret, LabelLink, nil, KeySize)
}

func hkdfExpand(secret []byte, label string, info []byte, n int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("crypto: empty secret")
	}
	r := hkdf.New(sha256.New, secret, []byte(label), info)
	out := make([]byte, n)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

// NameHMAC returns the fixed-length 32-byte HMAC of a node name (folded to
// lowercase). Used as the unique-key column for (tenant, parent, name).
func NameHMAC(key []byte, name string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strings.ToLower(name)))
	return h.Sum(nil)
}

// RandomKey returns a cryptographically random KeySize-byte key.
func RandomKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// RandomNonce returns a cryptographically random NonceSize-byte nonce.
func RandomNonce() ([]byte, error) {
	n := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, n); err != nil {
		return nil, err
	}
	return n, nil
}

// Seal AEAD-seals plaintext with key + nonce, optionally with associated data.
func Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("crypto: nonce length %d, want %d", len(nonce), aead.NonceSize())
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open is the inverse of Seal.
func Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

// HashChunk returns SHA-256(ciphertext). Used for content-addressing.
func HashChunk(ciphertext []byte) []byte {
	sum := sha256.Sum256(ciphertext)
	return sum[:]
}

// MerkleRoot returns the SHA-256 Merkle root over the ordered list of
// chunk ciphertext hashes. The construction is the standard binary
// pairing with the last odd node duplicated.
//
// For an empty list the root is the SHA-256 of the empty string so the
// function is total.
func MerkleRoot(chunkHashes [][]byte) []byte {
	if len(chunkHashes) == 0 {
		empty := sha256.Sum256(nil)
		return empty[:]
	}
	level := make([][]byte, len(chunkHashes))
	for i, h := range chunkHashes {
		if len(h) != HashSize {
			panic(fmt.Sprintf("crypto: chunk hash %d has length %d", i, len(h)))
		}
		level[i] = h
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		var pair [2 * HashSize]byte
		for i := 0; i < len(level); i += 2 {
			copy(pair[:HashSize], level[i])
			copy(pair[HashSize:], level[i+1])
			h := sha256New()
			h.Write(pair[:])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}

func sha256New() hash.Hash { return sha256.New() }

// WrapKey wraps a CEK under a wrapping key with a fresh random nonce.
// The returned slice is `nonce || sealedKey` so it can be stored as a
// single opaque blob inside the manifest.
func WrapKey(wrappingKey, cek []byte) ([]byte, error) {
	nonce, err := RandomNonce()
	if err != nil {
		return nil, err
	}
	ct, err := Seal(wrappingKey, nonce, cek, []byte("cek-wrap"))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// UnwrapKey is the inverse of WrapKey.
func UnwrapKey(wrappingKey, wrapped []byte) ([]byte, error) {
	if len(wrapped) < NonceSize+chacha20poly1305.Overhead {
		return nil, errors.New("crypto: wrapped key too short")
	}
	nonce := wrapped[:NonceSize]
	ct := wrapped[NonceSize:]
	return Open(wrappingKey, nonce, ct, []byte("cek-wrap"))
}

// PutUint32 / GetUint32 helpers used by manifest-related callers.
func PutUint32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func GetUint32(b []byte) uint32    { return binary.BigEndian.Uint32(b) }

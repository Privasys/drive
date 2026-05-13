// Package objectstore defines the pluggable backend interface that
// Privasys Drive uses to persist AEAD-sealed chunks and manifest blobs.
//
// Backends see only opaque, content-addressed bytes; they MUST NOT
// inspect, log, or mutate payloads. The drive service prefixes every
// key with a per-tenant component (`t/<tenant_prefix>/...`) so a single
// bucket can host many tenants safely.
package objectstore

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound is returned by Get/Head when the key does not exist.
var ErrNotFound = errors.New("objectstore: not found")

// Backend is the contract every storage driver implements. Calls must
// be safe for concurrent use; the service may issue many parallel
// PutChunk for a single upload.
type Backend interface {
	// PutChunk stores raw bytes under the given key. PutChunk MUST be
	// idempotent: writing the same key twice with the same content is a
	// no-op. Writing different content is undefined behaviour and a
	// caller bug — chunks are content-addressed.
	PutChunk(ctx context.Context, key string, body io.Reader, size int64) error

	// GetChunk returns a streaming reader for the value at key.
	GetChunk(ctx context.Context, key string) (io.ReadCloser, error)

	// Head returns the size of the value at key, or ErrNotFound.
	Head(ctx context.Context, key string) (int64, error)

	// Delete removes the value at key. Deleting a missing key is OK.
	Delete(ctx context.Context, key string) error

	// Name returns a stable identifier for the backend ("local",
	// "gcs", "ovh", "s3"…). Used in logs and audit records.
	Name() string
}

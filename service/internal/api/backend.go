package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/Privasys/drive/service/internal/objectstore"
)

// tenantBackends caches per-tenant BYO object backends (built from the
// tenant's sealed bucket credential, unwrapped in-enclave). Keyed by
// tenant id; invalidated when the credential changes.
type tenantBackends struct {
	mu    sync.Mutex
	byTID map[string]*tenantBackend
}

type tenantBackend struct {
	credRaw string // the stored SealedBucketCred JSON this backend was built from
	backend objectstore.Backend
}

func newTenantBackends() *tenantBackends {
	return &tenantBackends{byTID: map[string]*tenantBackend{}}
}

// backendFor returns the object backend for a tenant: the tenant's BYO
// bucket (when a sealed credential is set and unwraps to a supported
// content type) or the instance default. BYO backends are cached and
// rebuilt only when the stored credential changes.
func (s *Server) backendFor(ctx context.Context, tenantID string) (objectstore.Backend, error) {
	raw, err := s.Store.TenantBucketCred(ctx, tenantID)
	if err != nil || raw == "" {
		return s.Backend, nil // no BYO credential -> instance default
	}
	if s.MEKs == nil {
		return s.Backend, nil // BYO not available on this instance
	}
	s.backendsOnce.Do(func() { s.backends = newTenantBackends() })

	s.backends.mu.Lock()
	defer s.backends.mu.Unlock()
	if tb, ok := s.backends.byTID[tenantID]; ok && tb.credRaw == raw {
		return tb.backend, nil
	}

	// Build (or rebuild) from the current sealed credential.
	pt, ct, err := s.bucketCredential(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var cred SealedBucketCred
	if perr := json.Unmarshal([]byte(raw), &cred); perr != nil {
		return nil, perr
	}
	backend, err := buildBYOBackend(ctx, ct, cred.Bucket, pt)
	if err != nil {
		return nil, err
	}
	// Close a superseded backend if it exposes Close (rotation).
	if old, ok := s.backends.byTID[tenantID]; ok {
		if c, ok := old.backend.(interface{ Close() error }); ok {
			_ = c.Close()
		}
	}
	s.backends.byTID[tenantID] = &tenantBackend{credRaw: raw, backend: backend}
	return backend, nil
}

// buildBYOBackend constructs an object backend from an unwrapped BYO
// credential by content type. Currently GCS; S3/OVH follow.
func buildBYOBackend(ctx context.Context, contentType, bucket string, credential []byte) (objectstore.Backend, error) {
	switch contentType {
	case "gcs-sa-json":
		return objectstore.NewGCS(ctx, objectstore.GCSConfig{Bucket: bucket, CredentialsJSON: credential})
	default:
		return nil, fmt.Errorf("unsupported bucket credential content type %q", contentType)
	}
}

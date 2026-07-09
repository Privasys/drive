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

// s3Credential is the plaintext of an "s3-keypair" / "ovh-s3" sealed
// credential (the material the tenant sealed under the operator key).
type s3Credential struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
	Endpoint        string `json:"endpoint"` // empty for AWS; the provider URL for OVH/MinIO/R2
}

// buildBYOBackend constructs an object backend from an unwrapped BYO
// credential by content type: GCS service-account JSON, or an
// S3-compatible key pair (AWS S3 or OVH Object Storage via its
// S3-compatible endpoint).
func buildBYOBackend(ctx context.Context, contentType, bucket string, credential []byte) (objectstore.Backend, error) {
	switch contentType {
	case "gcs-sa-json":
		return objectstore.NewGCS(ctx, objectstore.GCSConfig{Bucket: bucket, CredentialsJSON: credential})
	case "s3-keypair", "ovh-s3":
		var c s3Credential
		if err := json.Unmarshal(credential, &c); err != nil {
			return nil, fmt.Errorf("parse %s credential: %w", contentType, err)
		}
		s3cfg := objectstore.S3Config{
			Bucket: bucket, Region: c.Region, Endpoint: c.Endpoint,
			AccessKey: c.AccessKeyID, SecretKey: c.SecretAccessKey,
		}
		if contentType == "ovh-s3" {
			return objectstore.NewOVH(ctx, s3cfg)
		}
		return objectstore.NewS3(ctx, s3cfg)
	default:
		return nil, fmt.Errorf("unsupported bucket credential content type %q", contentType)
	}
}

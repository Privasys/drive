package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/objectstore"
)

// instanceBackend returns the current instance object store under the
// read lock. The configure flow can swap Backend (applyObjectBackend), so
// every runtime reader must go through here to avoid a torn interface read.
func (s *Server) instanceBackend() objectstore.Backend {
	s.objectMu.RLock()
	defer s.objectMu.RUnlock()
	return s.Backend
}

// objectContentType maps a config object_backend value to the sealed
// credential content type understood by buildBYOBackend. The empty second
// return means "local" — keep the startup (sealed-volume) backend.
func objectContentType(backend string) (string, bool) {
	switch backend {
	case "gcs":
		return "gcs-sa-json", true
	case "s3":
		return "s3-keypair", true
	case "ovh":
		return "ovh-s3", true
	default: // "" / "local"
		return "", false
	}
}

// applyObjectBackend (re)builds the instance object store from the
// owner-set config when object_backend/bucket/credential change. It reuses
// buildBYOBackend — the same constructor the per-tenant BYO path uses — so
// GCS/S3/OVH behave identically at instance and tenant scope. A build
// failure keeps the previous backend and leaves objectKey stale so a
// corrected credential retries on the next configure. Never touches the
// backend for a "local"/empty selection (the startup volume store stands).
func (s *Server) applyObjectBackend(c *config.Config) {
	ct, remote := objectContentType(c.ObjectBackend)
	key := c.ObjectBackend + "\x00" + c.ObjectBucket + "\x00" + credFingerprint(c.ObjectCredential)

	s.objectMu.Lock()
	defer s.objectMu.Unlock()
	if key == s.objectKey {
		return
	}
	if !remote {
		// Local/unset: the startup sealed-volume backend stays in place.
		s.objectKey = key
		return
	}
	backend, err := buildBYOBackend(context.Background(), ct, c.ObjectBucket, []byte(c.ObjectCredential))
	if err != nil {
		log.Printf("object backend %q init failed, keeping previous store: %v", c.ObjectBackend, err)
		return // leave objectKey stale so a fixed credential retries
	}
	old := s.Backend
	s.Backend = backend
	s.objectKey = key
	if closer, ok := old.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	log.Printf("object backend switched to %s (bucket %q)", c.ObjectBackend, c.ObjectBucket)
}

// credFingerprint is a short non-reversible tag of the credential, used
// only to detect a change (never logged in full).
func credFingerprint(cred string) string {
	if cred == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(cred))
	return hex.EncodeToString(sum[:8])
}

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
		return s.instanceBackend(), nil // no BYO credential -> instance default
	}
	if s.MEKs == nil {
		return s.instanceBackend(), nil // BYO not available on this instance
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

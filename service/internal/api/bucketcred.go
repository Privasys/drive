package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/Privasys/drive/service/internal/vaultmek"
)

// SealedBucketCred is a BYO cloud-bucket credential a tenant sealed
// under a vault "wrapped-secret" operator key (an Aes256GcmKey whose
// policy grants Drive's app TEE Unwrap only — never Wrap or DeleteKey).
// The tenant/owner sealed the plaintext with an in-enclave Wrap RPC to
// the vault; Drive stores only the ciphertext and unwraps it in-enclave
// per session, so the platform, the operator and a non-promoted build
// never see the credential.
type SealedBucketCred struct {
	// KeyRef addresses the operator key on the constellation (handle,
	// endpoints, MRENCLAVE, attestation server + token).
	KeyRef vaultmek.Ref `json:"key_ref"`
	// CiphertextB64 / IvB64 are the sealed credential (raw-url base64).
	CiphertextB64 string `json:"ciphertext_b64"`
	IvB64         string `json:"iv_b64"`
	// ContentType labels the credential for the object backend
	// (e.g. "gcs-sa-json", "s3-keypair", "ovh-token").
	ContentType string `json:"content_type"`
	// Bucket is the target bucket name (plaintext metadata, not secret);
	// the sealed plaintext holds only the credential material.
	Bucket string `json:"bucket"`
}

// bucketCredential unwraps the tenant's sealed bucket credential
// in-enclave. Returns the plaintext + its content type, or ErrNotFound
// (as a store error) when the tenant has no BYO credential (the
// platform-managed bucket is used instead). The plaintext is never
// persisted or logged.
func (s *Server) bucketCredential(ctx context.Context, tenantID string) ([]byte, string, error) {
	raw, err := s.Store.TenantBucketCred(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	if raw == "" {
		return nil, "", errBucketCredUnset
	}
	if s.MEKs == nil {
		return nil, "", errors.New("no vault client to unwrap the bucket credential")
	}
	var c SealedBucketCred
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, "", fmt.Errorf("parse sealed bucket credential: %w", err)
	}
	ct, err := base64.RawURLEncoding.DecodeString(c.CiphertextB64)
	if err != nil {
		return nil, "", fmt.Errorf("bad ciphertext_b64: %w", err)
	}
	iv, err := base64.RawURLEncoding.DecodeString(c.IvB64)
	if err != nil {
		return nil, "", fmt.Errorf("bad iv_b64: %w", err)
	}
	pt, err := s.MEKs.Unwrap(ctx, c.KeyRef, ct, iv)
	if err != nil {
		return nil, "", err
	}
	return pt, c.ContentType, nil
}

var errBucketCredUnset = errors.New("tenant has no BYO bucket credential")

// setBucketCred validates and stores (or swaps, for rotation) a
// tenant's sealed bucket credential. Owner/admin only. Shared by the
// REST handler and the manifest tool.
func (s *Server) setBucketCred(ctx context.Context, p *Principal, tenantID string, c SealedBucketCred) (int, error) {
	if !p.IsUser() || !s.canAdmin(ctx, tenantID, p.Sub) {
		return http.StatusForbidden, errors.New("owner/admin only")
	}
	if c.CiphertextB64 == "" || c.IvB64 == "" || c.KeyRef.Handle == "" || len(c.KeyRef.Endpoints) == 0 {
		return http.StatusBadRequest,
			errors.New("ciphertext_b64, iv_b64, key_ref.handle and key_ref.endpoints are required")
	}
	blob, err := json.Marshal(c)
	if err != nil {
		return http.StatusInternalServerError, err
	}
	if err := s.Store.SetTenantBucketCred(ctx, tenantID, string(blob)); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// bucketCredMeta reports whether a BYO credential is set plus its
// non-secret metadata (never the ciphertext or plaintext). Any tenant
// reader may ask. Shared by the REST handler and the manifest tool.
func (s *Server) bucketCredMeta(ctx context.Context, p *Principal, tenantID string) (map[string]any, int, error) {
	if !p.IsUser() || !s.canRead(ctx, tenantID, p.Sub) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	raw, err := s.Store.TenantBucketCred(ctx, tenantID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if raw == "" {
		return map[string]any{"configured": false}, http.StatusOK, nil
	}
	var c SealedBucketCred
	_ = json.Unmarshal([]byte(raw), &c)
	return map[string]any{
		"configured":   true,
		"content_type": c.ContentType,
		"bucket":       c.Bucket,
		"key_handle":   c.KeyRef.Handle,
	}, http.StatusOK, nil
}

// clearBucketCred removes the BYO credential (falls back to the
// platform-managed bucket). Owner/admin only.
func (s *Server) clearBucketCred(ctx context.Context, p *Principal, tenantID string) (int, error) {
	if !p.IsUser() || !s.canAdmin(ctx, tenantID, p.Sub) {
		return http.StatusForbidden, errors.New("owner/admin only")
	}
	if err := s.Store.SetTenantBucketCred(ctx, tenantID, ""); err != nil {
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// handleSetBucketCred stores or swaps (rotation) the tenant's sealed
// bucket credential. Owner-only. The body is a SealedBucketCred; the
// plaintext credential is never sent here — only the vault-sealed
// ciphertext + the operator key ref.
func (s *Server) handleSetBucketCred(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	var c SealedBucketCred
	if err := readJSON(r, &c); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if status, err := s.setBucketCred(r.Context(), p, tenantID, c); err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "stored", "content_type": c.ContentType})
}

// handleGetBucketCred reports whether a BYO credential is set and its
// metadata (never the ciphertext or plaintext).
func (s *Server) handleGetBucketCred(w http.ResponseWriter, r *http.Request, p *Principal) {
	meta, status, err := s.bucketCredMeta(r.Context(), p, r.PathValue("tenantID"))
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

// handleDeleteBucketCred clears the BYO credential (falls back to the
// platform-managed bucket).
func (s *Server) handleDeleteBucketCred(w http.ResponseWriter, r *http.Request, p *Principal) {
	if status, err := s.clearBucketCred(r.Context(), p, r.PathValue("tenantID")); err != nil {
		httpError(w, status, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}


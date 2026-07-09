package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/store"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// MEKProvider is the vault-side of per-tenant keys and sealed
// credentials (vaultmek.Client in production; faked in tests).
type MEKProvider interface {
	Provision(ctx context.Context, b vaultmek.Bundle) (vaultmek.Ref, error)
	Load(ctx context.Context, ref vaultmek.Ref) ([]byte, error)
	Unwrap(ctx context.Context, ref vaultmek.Ref, ciphertext, iv []byte) ([]byte, error)
}

// tenantMEK resolves the master key protecting a tenant's content: the
// tenant's own vault-held MEK when provisioned, else the instance MEK
// (the pre-vault interim, kept as fallback so old tenants keep working).
func (s *Server) tenantMEK(ctx context.Context, tenantID string) ([]byte, error) {
	ref, err := s.Store.TenantMekRef(ctx, tenantID)
	if err != nil || ref == "" {
		return s.MEK, nil
	}
	if s.MEKs == nil {
		return nil, errors.New("tenant has a vault MEK but no vault client is available")
	}
	r, perr := vaultmek.ParseRef(ref)
	if perr != nil {
		return nil, perr
	}
	return s.MEKs.Load(ctx, r)
}

type tenantKeyRequest struct {
	Grant            string `json:"grant"`
	Handle           string `json:"handle"`
	AttestationToken string `json:"attestation_token"`
	Constellation    struct {
		Endpoints         []string `json:"endpoints"`
		Mrenclave         string   `json:"mrenclave"`
		AttestationServer string   `json:"attestation_server"`
		Threshold         int      `json:"threshold"`
	} `json:"constellation"`
}

// handleTenantKey provisions (or re-arms) the caller's personal-tenant
// vault MEK. First call with a fresh grant bundle: the enclave
// generates the MEK, Shamir-splits it across the constellation under
// the caller-owned, app-id-bound grant, and switches the tenant to it
// (201). Later calls refresh the stored attestation token and warm the
// in-memory MEK cache (200) — the wallet does this on login so a
// restarted instance can read shares back.
func (s *Server) handleTenantKey(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("user principals only"))
		return
	}
	if s.MEKs == nil {
		httpError(w, http.StatusNotImplemented, errors.New("vault-held tenant keys are not available on this instance"))
		return
	}
	t, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, http.StatusNotFound, errors.New("no personal tenant; call POST /v1/me/tenant first"))
		return
	}
	var req tenantKeyRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}

	if existing, _ := s.Store.TenantMekRef(r.Context(), t.ID); existing != "" {
		ref, perr := vaultmek.ParseRef(existing)
		if perr != nil {
			httpError(w, http.StatusInternalServerError, perr)
			return
		}
		if req.AttestationToken != "" {
			ref.AttToken = req.AttestationToken
			if err := s.Store.SetTenantMekRef(r.Context(), t.ID, vaultmek.RefJSON(ref)); err != nil {
				writeStoreError(w, err)
				return
			}
		}
		if _, err := s.MEKs.Load(r.Context(), ref); err != nil {
			httpError(w, http.StatusBadGateway, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "loaded", "handle": ref.Handle})
		return
	}

	if req.Grant == "" || req.Handle == "" || len(req.Constellation.Endpoints) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("grant, handle and constellation.endpoints are required"))
		return
	}
	bundle := vaultmek.Bundle{
		Grant:        req.Grant,
		Handle:       req.Handle,
		Endpoints:    req.Constellation.Endpoints,
		MrenclaveHex: req.Constellation.Mrenclave,
		AttServer:    req.Constellation.AttestationServer,
		AttToken:     req.AttestationToken,
		Threshold:    req.Constellation.Threshold,
	}
	ref, err := s.MEKs.Provision(r.Context(), bundle)
	if err != nil {
		// A crash after share creation but before the index commit
		// leaves the key on the vaults with no local ref; recover it by
		// reading the shares back instead of failing forever.
		if !strings.Contains(strings.ToLower(err.Error()), "exist") {
			httpError(w, http.StatusBadGateway, err)
			return
		}
		ref = vaultmek.Ref{
			Handle: bundle.Handle, Endpoints: bundle.Endpoints,
			MrenclaveHex: bundle.MrenclaveHex, AttServer: bundle.AttServer,
			AttToken: bundle.AttToken, Threshold: bundle.Threshold,
		}
	}
	newMek, err := s.MEKs.Load(r.Context(), ref)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}

	// Migrate existing content: content stays sealed under its per-file
	// CEKs, so switching MEK is a metadata sweep (re-wrap each file's
	// CEK, recompute every node's name HMAC), committed atomically with
	// the tenant's mek_ref.
	oldDEK, err := crypto.DeriveDEK(s.MEK, t.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	newDEK, err := crypto.DeriveDEK(newMek, t.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	newHMAC, err := crypto.DeriveNameHMACKey(newMek, t.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	rewrapped, err := s.Store.SwitchTenantKeys(r.Context(), t.ID, vaultmek.RefJSON(ref), func(n *store.Node) error {
		n.NameHMAC = crypto.NameHMAC(newHMAC, n.Name)
		if len(n.WrappedCEK) == 0 {
			return nil // folders carry no CEK
		}
		cek, uerr := crypto.UnwrapKey(oldDEK, n.WrappedCEK)
		if uerr != nil {
			return uerr
		}
		wrapped, werr := crypto.WrapKey(newDEK, cek)
		if werr != nil {
			return werr
		}
		n.WrappedCEK = wrapped
		return nil
	})
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "provisioned", "handle": ref.Handle, "rewrapped_nodes": rewrapped,
	})
}

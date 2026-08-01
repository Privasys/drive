package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/config"
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

// ErrVaultKeyStale means the tenant's vault MEK could not be loaded
// (typically the stored attestation token expired since the last
// re-arm). It is recoverable: the owner re-arms via
// POST /v1/me/tenant/key with a fresh grant bundle. Callers surface it
// as 409 with a machine-readable code so a client auto-re-arms rather
// than treating it as a hard failure.
var ErrVaultKeyStale = errors.New("tenant vault key unavailable; re-arm via POST /v1/me/tenant/key")

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
	mek, lerr := s.MEKs.Load(ctx, r)
	if lerr != nil {
		// A tenant with a vault ref whose Load fails is recoverable by
		// re-arming (the wallet does this on login; the stored
		// attestation token expires ~15 min after the last re-arm).
		return nil, fmt.Errorf("%w: %v", ErrVaultKeyStale, lerr)
	}
	return mek, nil
}

// rearmTenantKey refreshes the stored attestation token on a tenant's
// existing MEK ref (when a fresh one is supplied) and warms the
// in-memory MEK cache by loading the key. This is the recovery for
// ErrVaultKeyStale; the wallet runs it on login and agents via the
// rearm_tenant_key tool.
func (s *Server) rearmTenantKey(ctx context.Context, tenantID, existingRef, attToken string) (handle string, status int, err error) {
	ref, perr := vaultmek.ParseRef(existingRef)
	if perr != nil {
		return "", http.StatusInternalServerError, perr
	}
	if attToken != "" {
		ref.AttToken = attToken
		if err := s.Store.SetTenantMekRef(ctx, tenantID, vaultmek.RefJSON(ref)); err != nil {
			return "", http.StatusInternalServerError, err
		}
	}
	if _, err := s.MEKs.Load(ctx, ref); err != nil {
		return "", http.StatusBadGateway, err
	}
	return ref.Handle, http.StatusOK, nil
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
		handle, status, rerr := s.rearmTenantKey(r.Context(), t.ID, existing, req.AttestationToken)
		if rerr != nil {
			httpError(w, status, rerr)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "loaded", "handle": handle})
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

	// Escrowed mode: every tenant MEK carries an escrow wrap under
	// MEK_org so the audited recover_tenant path can reach it. Fail the
	// provision if the wrap cannot be produced — an un-escrowed tenant
	// would violate the escrowed contract.
	if cfg := s.CurrentConfig(); cfg != nil && cfg.Mode == config.ModeEscrowed {
		if err := s.escrowWrapTenant(r.Context(), t.ID, newMek, p.Sub); err != nil {
			httpError(w, http.StatusBadGateway, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "provisioned", "handle": ref.Handle, "rewrapped_nodes": rewrapped,
	})
}

type tenantKeyRevaultRequest struct {
	tenantKeyRequest
	// RecoveredMekB64 is the tenant's CURRENT MEK, exported by the data
	// owner from the old constellation (`ExportKey` is owner-gated by an
	// operation-bound WebAuthn step-up — the sovereign contract's
	// walk-away right). Standard base64.
	RecoveredMekB64 string `json:"recovered_mek_b64"`
}

// handleTenantKeyRevault moves a tenant's MEK to a NEW vault constellation
// when the old one can no longer serve it (a constellation rotation the
// per-tenant key could not ride). The data owner supplies their exported
// MEK plus a fresh grant bundle for the active constellation; the enclave
// provisions a NEW MEK there and atomically re-wraps every CEK from the
// recovered key to the new one (same sweep as first-time provisioning).
// The recovered key is proven correct by the sweep itself: any CEK that
// fails to unwrap aborts the switch with nothing committed.
func (s *Server) handleTenantKeyRevault(w http.ResponseWriter, r *http.Request, p *Principal) {
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
		httpError(w, http.StatusNotFound, errors.New("no personal tenant"))
		return
	}
	existing, _ := s.Store.TenantMekRef(r.Context(), t.ID)
	if existing == "" {
		httpError(w, http.StatusConflict, errors.New("tenant has no vault MEK; use POST /v1/me/tenant/key"))
		return
	}
	var req tenantKeyRevaultRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	recovered, err := base64.StdEncoding.DecodeString(req.RecoveredMekB64)
	if err != nil || len(recovered) != 32 {
		httpError(w, http.StatusBadRequest, errors.New("recovered_mek_b64 must be 32 bytes of base64"))
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

	oldDEK, err := crypto.DeriveDEK(recovered, t.ID)
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
			return nil
		}
		cek, uerr := crypto.UnwrapKey(oldDEK, n.WrappedCEK)
		if uerr != nil {
			return fmt.Errorf("recovered key does not open this tenant's content: %w", uerr)
		}
		wrapped, werr := crypto.WrapKey(newDEK, cek)
		if werr != nil {
			return werr
		}
		n.WrappedCEK = wrapped
		return nil
	})
	if err != nil {
		httpError(w, http.StatusConflict, err)
		return
	}

	if cfg := s.CurrentConfig(); cfg != nil && cfg.Mode == config.ModeEscrowed {
		if err := s.escrowWrapTenant(r.Context(), t.ID, newMek, p.Sub); err != nil {
			httpError(w, http.StatusBadGateway, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "revaulted", "handle": ref.Handle, "rewrapped_nodes": rewrapped,
	})
}

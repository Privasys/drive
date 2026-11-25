package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

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
	// RefreshTees is the data owner's measurement approval: replace the
	// key's pinned TEE profile with the grant's (the app's current
	// measurement), authenticated as the key owner.
	RefreshTees(ctx context.Context, ref vaultmek.Ref, grant, ownerBearer string) error
	// Regenerate re-creates the tenant's key (same material) at the next
	// handle generation under a fresh grant — the renewal for the vault's
	// fixed expires_at, and the ride off a retiring constellation.
	Regenerate(ctx context.Context, ref vaultmek.Ref, b vaultmek.Bundle) (vaultmek.Ref, error)
}

// mekRotateAfter is how old a tenant key's handle generation may grow
// before a rearm opportunistically regenerates it. Vault key records
// expire at a FIXED expires_at (90-day cap) that no operation extends, so
// rotating well before expiry is the only renewal there is. Rotation keeps
// the same material (no content re-wrap) and rides the fresh grant the
// wallet already sends at each login. A constellation change on the
// bundle also triggers, so keys move off retiring constellations.
const mekRotateAfter = 30 * 24 * time.Hour

// switchTenantMEK re-keys a tenant's stored metadata from oldMEK to newMEK
// and commits the new mek_ref in the same transaction.
//
// Content is never re-encrypted: chunks stay sealed under their per-file
// CEKs and manifests under those same CEKs, so a MEK switch only has to
// re-wrap every CEK and recompute every name HMAC. That covers both the
// current content (nodes) and every retained revision (file_versions,
// which carries its own wrapped CEK) — miss the latter and previous
// versions silently become undecryptable.
//
// The three callers differ only in where oldMEK comes from: the instance
// MEK (first-time provisioning of a pre-vault tenant), the owner's
// exported key (revault), or the old constellation read by the app's own
// TEE principal (the operator re-sweep).
func (s *Server) switchTenantMEK(ctx context.Context, tenantID string, oldMEK, newMEK []byte, newRef vaultmek.Ref) (store.TenantKeySwitchCounts, error) {
	var zero store.TenantKeySwitchCounts
	oldDEK, err := crypto.DeriveDEK(oldMEK, tenantID)
	if err != nil {
		return zero, err
	}
	newDEK, err := crypto.DeriveDEK(newMEK, tenantID)
	if err != nil {
		return zero, err
	}
	newHMAC, err := crypto.DeriveNameHMACKey(newMEK, tenantID)
	if err != nil {
		return zero, err
	}
	rewrapCEK := func(wrapped []byte) ([]byte, error) {
		cek, uerr := crypto.UnwrapKey(oldDEK, wrapped)
		if uerr != nil {
			return nil, uerr
		}
		return crypto.WrapKey(newDEK, cek)
	}
	return s.Store.SwitchTenantKeys(ctx, tenantID, vaultmek.RefJSON(newRef), store.TenantKeySwitch{
		Node: func(n *store.Node) error {
			n.NameHMAC = crypto.NameHMAC(newHMAC, n.Name)
			if len(n.WrappedCEK) == 0 {
				return nil // folders carry no CEK
			}
			wrapped, werr := rewrapCEK(n.WrappedCEK)
			if werr != nil {
				return werr
			}
			n.WrappedCEK = wrapped
			return nil
		},
		CEK: rewrapCEK,
	})
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
	// The enclave just opened the key, so it is a principal: record the
	// policy if it is not on record yet (keys from before the record).
	s.recordKeyPolicy(ctx, tenantID, false)
	return ref.Handle, http.StatusOK, nil
}

// maybeRotateTenantKey opportunistically regenerates a tenant's vault key
// at rearm (same material, next handle generation, the request's fresh
// grant) when the current generation has aged past mekRotateAfter — or
// when the bundle addresses a different constellation than the ref, so
// the key rides off a retiring one before it strands. Best-effort: a
// failure keeps the current ref and the login succeeds regardless; the
// next login retries. A legacy ref (RotatedAt zero, minted before
// rotation existed) is due immediately, which sweeps every existing
// tenant onto the active constellation and the current 90-day policy at
// their next login.
func (s *Server) maybeRotateTenantKey(ctx context.Context, tenantID, existingRef string, req *tenantKeyRequest) (bool, string) {
	if req.Grant == "" || len(req.Constellation.Endpoints) == 0 {
		return false, ""
	}
	ref, err := vaultmek.ParseRef(existingRef)
	if err != nil {
		return false, ""
	}
	aged := ref.RotatedAt == 0 || time.Since(time.Unix(ref.RotatedAt, 0)) > mekRotateAfter
	moved := ref.MrenclaveHex != req.Constellation.Mrenclave ||
		!sameEndpointSet(ref.Endpoints, req.Constellation.Endpoints)
	if !aged && !moved {
		return false, ""
	}
	b := vaultmek.Bundle{
		Grant:        req.Grant,
		Endpoints:    req.Constellation.Endpoints,
		MrenclaveHex: req.Constellation.Mrenclave,
		AttServer:    req.Constellation.AttestationServer,
		AttToken:     req.AttestationToken,
		Threshold:    req.Constellation.Threshold,
		Audience:     req.Constellation.OIDCAudience,
		Issuer:       req.Constellation.OIDCIssuer,
	}
	newRef, rerr := s.MEKs.Regenerate(ctx, ref, b)
	if rerr != nil {
		log.Printf("tenantkey: rotation of %s skipped: %v", ref.Handle, rerr)
		return false, ""
	}
	if serr := s.Store.SetTenantMekRef(ctx, tenantID, vaultmek.RefJSON(newRef)); serr != nil {
		// The new generation exists on the vaults but the index still
		// points at the old one; the old key stays valid, and the next
		// login adopts the new generation (Regenerate verifies the
		// material matches before adopting an existing handle).
		log.Printf("tenantkey: rotated %s -> %s but persisting the ref failed: %v", ref.Handle, newRef.Handle, serr)
		return false, ""
	}
	log.Printf("tenantkey: rotated %s -> %s (aged=%t constellation_changed=%t)", ref.Handle, newRef.Handle, aged, moved)
	return true, newRef.Handle
}

// sameEndpointSet reports whether two endpoint lists name the same set,
// order-insensitively.
func sameEndpointSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, e := range a {
		seen[e]++
	}
	for _, e := range b {
		if seen[e] == 0 {
			return false
		}
		seen[e]--
	}
	return true
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
		OIDCAudience      string   `json:"oidc_audience"`
		OIDCIssuer        string   `json:"oidc_issuer"`
	} `json:"constellation"`
	// OwnerToken is no longer accepted: it carried the person's platform
	// token into the app. Present only so a request that still sends it is
	// refused (400), never silently ignored.
	OwnerToken string `json:"owner_token,omitempty"`
	// ApprovalToken is the vault-approval token the caller obtained from
	// privasys.id for the approval this endpoint described (409
	// owner_approval_required). It is the only authority Drive presents to
	// the vaults for a measurement change.
	ApprovalToken string `json:"approval_token,omitempty"`
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
	if p.Guest {
		httpError(w, http.StatusForbidden, errGuestOwnsNothing)
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
	if req.OwnerToken != "" {
		httpError(w, http.StatusBadRequest, errors.New(
			"owner_token is not accepted: an app never receives a platform token"))
		return
	}

	if existing, _ := s.Store.TenantMekRef(r.Context(), t.ID); existing != "" {
		handle, status, rerr := s.rearmTenantKey(r.Context(), t.ID, existing, req.AttestationToken)
		if rerr == nil {
			resp := map[string]any{"status": "loaded", "handle": handle}
			if rotated, newHandle := s.maybeRotateTenantKey(r.Context(), t.ID, existing, &req); rotated {
				resp["handle"] = newHandle
				resp["rotated"] = true
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		// The vault refusing the enclave's identity against the key's
		// principals means the app's measurement changed (an upgrade) and
		// the key's holder has not approved it yet. Drive never holds the
		// holder's credential: it answers with what to approve, the CALLER
		// (web front, wallet, CLI) asks privasys.id for the approval with
		// its own session, and re-posts the approval token, which is the
		// only authority Drive presents to the vaults.
		if vaultmek.PrincipalMismatch(rerr) {
			if req.Grant == "" {
				httpError(w, http.StatusConflict, errors.New(
					"measurement_approval_required: the Drive app was upgraded; re-arm with a fresh grant bundle to approve the new measurement for your key"))
				return
			}
			ref, perr := vaultmek.ParseRef(existing)
			if perr != nil {
				httpError(w, http.StatusInternalServerError, perr)
				return
			}
			if req.AttestationToken != "" {
				ref.AttToken = req.AttestationToken
			}
			audience := ref.Audience
			if audience == "" {
				audience = req.Constellation.OIDCAudience
			}
			// The binding version is the KEY's own rule, as its vaults last
			// confirmed it. If it is not on record, or a binding-2 plan
			// cannot be built, Drive fails closed: no approval is asked for,
			// and never a v1 one for a binding-2 key.
			v2p, hasV2 := s.MEKs.(teesV2Provider)
			var plan *vaultmek.TeesApprovalV2
			if hasV2 {
				var verr error
				plan, verr = v2p.PrepareTeesApprovalV2(r.Context(), ref, req.Grant)
				if errors.Is(verr, vaultmek.ErrRestageNeeded) {
					log.Printf("tenant-key: measurement approval for tenant %.8s… needs a re-stage: the key's policy is not on record", t.ID)
					httpError(w, http.StatusConflict, errors.New(
						"restage_needed: this key's policy is not on record, so its measurement cannot be approved; it must be re-staged by the operator"))
					return
				}
				if verr != nil {
					log.Printf("tenant-key: measurement approval for tenant %.8s… refused: %v", t.ID, verr)
					httpError(w, http.StatusBadGateway, verr)
					return
				}
			}
			if req.ApprovalToken == "" {
				// What the holder approves: the caller sends this body to
				// privasys.id's vault-approval begin with its own session.
				writeJSON(w, http.StatusConflict, map[string]any{
					"error":    "owner_approval_required: approve the Privasys Drive key update in your Privasys Wallet, then re-arm with the approval token",
					"approval": approvalRequest(ref.Handle, audience, plan),
				})
				return
			}
			if !isApprovalToken(req.ApprovalToken) {
				httpError(w, http.StatusBadRequest, errors.New(
					"approval_token must be a vault-approval token (bound to the operation)"))
				return
			}
			var aerr error
			if plan != nil {
				aerr = v2p.RefreshTeesV2(r.Context(), ref, plan, req.ApprovalToken)
			} else {
				aerr = s.MEKs.RefreshTees(r.Context(), ref, req.Grant, req.ApprovalToken)
			}
			if aerr != nil {
				httpError(w, http.StatusBadGateway, aerr)
				return
			}
			handle, status, rerr = s.rearmTenantKey(r.Context(), t.ID, existing, req.AttestationToken)
			if rerr != nil {
				httpError(w, status, rerr)
				return
			}
			// The policy changed: record what the vaults now hold.
			s.recordKeyPolicy(r.Context(), t.ID, true)
			resp := map[string]any{
				"status": "loaded", "handle": handle, "measurement_approved": true,
			}
			if rotated, newHandle := s.maybeRotateTenantKey(r.Context(), t.ID, existing, &req); rotated {
				resp["handle"] = newHandle
				resp["rotated"] = true
			}
			writeJSON(w, http.StatusOK, resp)
			return
		}
		if ref, ok := s.freshStartEmptyTenant(r.Context(), t.ID, existing, &req, p.Sub, rerr); ok {
			writeJSON(w, http.StatusCreated, map[string]any{
				"status": "provisioned", "handle": ref.Handle, "fresh_start": true,
			})
			return
		}
		httpError(w, status, rerr)
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
		Audience:     req.Constellation.OIDCAudience,
		Issuer:       req.Constellation.OIDCIssuer,
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
			AttToken: bundle.AttToken, Threshold: bundle.Threshold, Audience: bundle.Audience, Issuer: bundle.Issuer,
		}
	}
	newMek, err := s.MEKs.Load(r.Context(), ref)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}

	// Migrate existing content from the instance MEK to the tenant's own:
	// content stays sealed under its per-file CEKs, so this is a metadata
	// sweep committed atomically with the tenant's mek_ref.
	counts, err := s.switchTenantMEK(r.Context(), t.ID, s.MEK, newMek, ref)
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
		"status": "provisioned", "handle": ref.Handle,
		"rewrapped_nodes": counts.Nodes, "rewrapped_versions": counts.Versions,
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
		Audience:     req.Constellation.OIDCAudience,
		Issuer:       req.Constellation.OIDCIssuer,
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
			AttToken: bundle.AttToken, Threshold: bundle.Threshold, Audience: bundle.Audience, Issuer: bundle.Issuer,
		}
	}
	newMek, err := s.MEKs.Load(r.Context(), ref)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}

	// The recovered key is proven by the sweep itself: any CEK it fails to
	// open aborts the switch with nothing committed.
	counts, err := s.switchTenantMEK(r.Context(), t.ID, recovered, newMek, ref)
	if err != nil {
		httpError(w, http.StatusConflict,
			fmt.Errorf("recovered key does not open this tenant's content: %w", err))
		return
	}

	if cfg := s.CurrentConfig(); cfg != nil && cfg.Mode == config.ModeEscrowed {
		if err := s.escrowWrapTenant(r.Context(), t.ID, newMek, p.Sub); err != nil {
			httpError(w, http.StatusBadGateway, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "revaulted", "handle": ref.Handle,
		"rewrapped_nodes": counts.Nodes, "rewrapped_versions": counts.Versions,
	})
}

// errFreshStartNotEmpty aborts a fresh-start key switch the moment the
// tenant turns out to hold anything the old key protects.
var errFreshStartNotEmpty = errors.New("tenant holds content under its current key")

// freshStartEmptyTenant gives an EMPTY tenant whose key can no longer be
// read a new key, so its owner is not locked out for good. It covers a key
// whose shares lived only on a constellation that has since been retired
// (its owner never signed in to ride it off). An empty tenant loses
// nothing: no node, name HMAC or file version depends on the old key. A
// tenant holding anything keeps failing; recovering it is the owner's
// revault (exported MEK) or nothing. Needs the caller's fresh grant
// bundle; the new key is the next handle generation, so it never collides
// with the lost one.
func (s *Server) freshStartEmptyTenant(ctx context.Context, tenantID, existingRef string, req *tenantKeyRequest, sub string, loadErr error) (vaultmek.Ref, bool) {
	if req.Grant == "" || len(req.Constellation.Endpoints) == 0 {
		return vaultmek.Ref{}, false
	}
	empty, err := s.Store.TenantIsEmpty(ctx, tenantID)
	if err != nil || !empty {
		return vaultmek.Ref{}, false
	}
	old, err := vaultmek.ParseRef(existingRef)
	if err != nil {
		return vaultmek.Ref{}, false
	}
	handle, err := vaultmek.NextGeneration(old.Handle)
	if err != nil {
		return vaultmek.Ref{}, false
	}
	ref, err := s.MEKs.Provision(ctx, vaultmek.Bundle{
		Grant:        req.Grant,
		Handle:       handle,
		Endpoints:    req.Constellation.Endpoints,
		MrenclaveHex: req.Constellation.Mrenclave,
		AttServer:    req.Constellation.AttestationServer,
		AttToken:     req.AttestationToken,
		Threshold:    req.Constellation.Threshold,
		Audience:     req.Constellation.OIDCAudience,
		Issuer:       req.Constellation.OIDCIssuer,
	})
	if err != nil {
		log.Printf("tenantkey: fresh start for tenant %s refused: provision: %v", tenantID, err)
		return vaultmek.Ref{}, false
	}
	newMek, err := s.MEKs.Load(ctx, ref)
	if err != nil {
		log.Printf("tenantkey: fresh start for tenant %s refused: load: %v", tenantID, err)
		return vaultmek.Ref{}, false
	}
	// The switch re-checks emptiness inside its transaction: any row
	// that appeared since aborts it with nothing committed.
	refuse := func() error { return errFreshStartNotEmpty }
	if _, err := s.Store.SwitchTenantKeys(ctx, tenantID, vaultmek.RefJSON(ref), store.TenantKeySwitch{
		Node: func(*store.Node) error { return refuse() },
		CEK:  func([]byte) ([]byte, error) { return nil, refuse() },
	}); err != nil {
		log.Printf("tenantkey: fresh start for tenant %s refused: switch: %v", tenantID, err)
		return vaultmek.Ref{}, false
	}
	if cfg := s.CurrentConfig(); cfg != nil && cfg.Mode == config.ModeEscrowed {
		if err := s.escrowWrapTenant(ctx, tenantID, newMek, sub); err != nil {
			log.Printf("tenantkey: fresh start for tenant %s: escrow wrap: %v", tenantID, err)
		}
	}
	log.Printf("tenantkey: fresh start for empty tenant %s: %s -> %s (old key unreadable: %v)", tenantID, old.Handle, ref.Handle, loadErr)
	return ref, true
}

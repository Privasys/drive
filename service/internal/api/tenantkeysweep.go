package api

// Operator-driven re-keying of per-tenant MEKs.
//
// A tenant's MEK normally moves constellation on its own: at each login the
// owner presents a fresh grant bundle and maybeRotateTenantKey regenerates
// the key — same material, next handle generation — onto whatever
// constellation the control plane now addresses. That is enough for a planned
// rotation, and it re-wraps nothing.
//
// It is NOT enough in two cases:
//
//   - A tenant who does not come back. Their key stays on the old
//     constellation, which must therefore keep running, and vault records
//     expire at an absolute expires_at that no operation extends — so an idle
//     tenant eventually loses the key outright.
//   - A constellation retired because its shares must be treated as
//     compromised. Re-splitting the SAME material onto new vaults does not
//     help: whoever holds the old shares holds that MEK. The tenant needs a
//     NEW MEK value, which makes the move a metadata sweep (re-wrap every
//     CEK, recompute every name HMAC) rather than a re-split.
//
// This surface does both without the tenant present. The one input it cannot
// produce itself is a key-creation grant owned by the tenant, so the operator
// mints those at the control plane (manager-gated, owner identified by the
// hashed ref this API reports) and hands them back here. Everything else is
// already owner-free: the app's TEE principal holds ExportKey on the old key,
// which is how it reads a tenant's MEK back after a restart.

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// tenantKeySweepEntry is one tenant's re-keying state, as reported to the
// operator. It deliberately carries the HASHED owner ref and never the raw
// subject: the control plane can already derive the ref for any user it
// knows, so this discloses nothing about who a sovereign instance's tenants
// are.
type tenantKeySweepEntry struct {
	TenantID   string   `json:"tenant_id"`
	OwnerRef   string   `json:"owner_ref"`
	Handle     string   `json:"handle"`
	NextHandle string   `json:"next_handle"`
	Mrenclave  string   `json:"mrenclave"`
	Endpoints  []string `json:"endpoints"`
	RotatedAt  int64    `json:"rotated_at"`
}

// handleTenantKeysPending lists the tenants whose MEK is not on the
// constellation named by the query (?mrenclave=<hex>), i.e. what a sweep
// still has to move. With no mrenclave it lists every vault-backed tenant.
func (s *Server) handleTenantKeysPending(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.sweepAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	target := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mrenclave")))
	holders, err := s.Store.ListTenantMekRefs(r.Context())
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]tenantKeySweepEntry, 0, len(holders))
	for _, h := range holders {
		ref, perr := vaultmek.ParseRef(h.MekRef)
		if perr != nil {
			// A tenant whose ref will not parse cannot be swept by this
			// path; surface it rather than skipping it silently.
			log.Printf("tenantkeysweep: tenant %s has an unparsable mek_ref: %v", h.TenantID, perr)
			continue
		}
		if target != "" && strings.EqualFold(ref.MrenclaveHex, target) {
			continue // already there
		}
		next, nerr := vaultmek.NextGeneration(ref.Handle)
		if nerr != nil {
			log.Printf("tenantkeysweep: tenant %s handle %q has no generation suffix: %v", h.TenantID, ref.Handle, nerr)
			continue
		}
		out = append(out, tenantKeySweepEntry{
			TenantID:   h.TenantID,
			OwnerRef:   ownerRefFromHandle(ref.Handle),
			Handle:     ref.Handle,
			NextHandle: next,
			Mrenclave:  ref.MrenclaveHex,
			Endpoints:  ref.Endpoints,
			RotatedAt:  ref.RotatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"pending": out, "count": len(out)})
}

// tenantKeyResweepRequest carries one grant bundle per tenant to re-key.
type tenantKeyResweepRequest struct {
	// DryRun proves the path without committing: the old MEK is read back
	// from its current constellation and the new one is NOT created.
	DryRun bool                   `json:"dry_run"`
	Items  []tenantKeyResweepItem `json:"items"`
}

type tenantKeyResweepItem struct {
	TenantID string `json:"tenant_id"`
	// Handle is where the new key is created. It must be the next
	// generation of the tenant's current handle, so a sweep can never be
	// pointed at another tenant's namespace.
	Handle           string `json:"handle"`
	Grant            string `json:"grant"`
	AttestationToken string `json:"attestation_token"`
	Constellation    struct {
		Endpoints         []string `json:"endpoints"`
		Mrenclave         string   `json:"mrenclave"`
		AttestationServer string   `json:"attestation_server"`
		Threshold         int      `json:"threshold"`
	} `json:"constellation"`
}

type tenantKeyResweepResult struct {
	TenantID string `json:"tenant_id"`
	Status   string `json:"status"`
	Handle   string `json:"handle,omitempty"`
	Nodes    int    `json:"rewrapped_nodes,omitempty"`
	Versions int    `json:"rewrapped_versions,omitempty"`
	Error    string `json:"error,omitempty"`
}

// handleTenantKeysResweep re-keys each named tenant onto a NEW MEK on the
// constellation its bundle addresses.
//
// Per tenant, in order: read the current MEK from its existing ref (the app's
// own TEE principal, no owner present); create a fresh MEK at the next handle
// generation under the supplied grant; re-wrap every CEK and recompute every
// name HMAC from old to new, committing the new mek_ref in the SAME
// transaction; and, in escrowed mode, re-produce the escrow wrap.
//
// Tenants are independent: one failure is reported and the sweep continues,
// leaving that tenant whole on its old key. Nothing here can half-migrate a
// tenant — the store commits the re-wrap and the ref together.
func (s *Server) handleTenantKeysResweep(w http.ResponseWriter, r *http.Request, p *Principal) {
	if err := s.sweepAllowed(p); err != nil {
		httpError(w, http.StatusForbidden, err)
		return
	}
	var req tenantKeyResweepRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.Items) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("items is required"))
		return
	}
	if s.MEKs == nil {
		httpError(w, http.StatusBadGateway, errors.New("no vault client available"))
		return
	}

	results := make([]tenantKeyResweepResult, 0, len(req.Items))
	moved := 0
	for _, item := range req.Items {
		res := s.resweepOneTenant(r, item, req.DryRun, p.Sub)
		if res.Status == "rekeyed" {
			moved++
		}
		results = append(results, res)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dry_run": req.DryRun, "rekeyed": moved, "results": results,
	})
}

func (s *Server) resweepOneTenant(r *http.Request, item tenantKeyResweepItem, dryRun bool, actor string) tenantKeyResweepResult {
	out := tenantKeyResweepResult{TenantID: item.TenantID, Status: "failed"}
	ctx := r.Context()

	existing, err := s.Store.TenantMekRef(ctx, item.TenantID)
	if err != nil {
		out.Error = "read current ref: " + err.Error()
		return out
	}
	if existing == "" {
		out.Status = "skipped"
		out.Error = "tenant has no vault MEK (still on the instance key)"
		return out
	}
	oldRef, err := vaultmek.ParseRef(existing)
	if err != nil {
		out.Error = "parse current ref: " + err.Error()
		return out
	}

	// The new handle must be exactly the next generation of THIS tenant's
	// handle. Without this an operator could point a tenant's row at a key
	// minted in someone else's namespace.
	wantHandle, err := vaultmek.NextGeneration(oldRef.Handle)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	if item.Handle != "" && item.Handle != wantHandle {
		out.Error = fmt.Sprintf("handle %q is not this tenant's next generation (%q)", item.Handle, wantHandle)
		return out
	}

	// Read the outgoing MEK while its constellation still serves it. This is
	// the app's own TEE principal exercising ExportKey — the same read that
	// happens after a restart — so no owner has to be present.
	oldMEK, err := s.MEKs.Load(ctx, oldRef)
	if err != nil {
		out.Error = "load current MEK: " + err.Error()
		return out
	}
	if dryRun {
		out.Status = "ready"
		out.Handle = wantHandle
		return out
	}

	if item.Grant == "" || len(item.Constellation.Endpoints) == 0 {
		out.Error = "grant and constellation.endpoints are required"
		return out
	}
	bundle := vaultmek.Bundle{
		Grant:        item.Grant,
		Handle:       wantHandle,
		Endpoints:    item.Constellation.Endpoints,
		MrenclaveHex: item.Constellation.Mrenclave,
		AttServer:    item.Constellation.AttestationServer,
		AttToken:     item.AttestationToken,
		Threshold:    item.Constellation.Threshold,
	}
	// Provision generates fresh material — the point of this sweep. A key
	// already at that handle from an interrupted run is adopted by reading
	// it back, so a retry converges instead of failing forever.
	newRef, err := s.MEKs.Provision(ctx, bundle)
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "exist") {
			out.Error = "provision new MEK: " + err.Error()
			return out
		}
		newRef = vaultmek.Ref{
			Handle: bundle.Handle, Endpoints: bundle.Endpoints,
			MrenclaveHex: bundle.MrenclaveHex, AttServer: bundle.AttServer,
			AttToken: bundle.AttToken, Threshold: bundle.Threshold,
		}
	}
	newMEK, err := s.MEKs.Load(ctx, newRef)
	if err != nil {
		out.Error = "read back new MEK: " + err.Error()
		return out
	}

	counts, err := s.switchTenantMEK(ctx, item.TenantID, oldMEK, newMEK, newRef)
	if err != nil {
		// Nothing was committed: the tenant is still whole on its old key.
		out.Error = "re-key sweep: " + err.Error()
		return out
	}

	// Escrowed mode: the escrow wrap is of the MEK itself, so a new MEK
	// needs a new wrap or the audited recovery path would reach a key the
	// tenant no longer uses.
	if cfg := s.CurrentConfig(); cfg != nil && cfg.Mode == config.ModeEscrowed {
		if eerr := s.escrowWrapTenant(ctx, item.TenantID, newMEK, actor); eerr != nil {
			// The re-key is committed and correct; only the escrow wrap is
			// stale. Report it loudly — an un-escrowed tenant violates the
			// escrowed contract and must be re-wrapped before the incident
			// is closed.
			out.Status = "rekeyed_escrow_failed"
			out.Handle = newRef.Handle
			out.Nodes, out.Versions = counts.Nodes, counts.Versions
			out.Error = "escrow re-wrap failed: " + eerr.Error()
			log.Printf("tenantkeysweep: tenant %s re-keyed to %s but escrow re-wrap FAILED: %v",
				item.TenantID, newRef.Handle, eerr)
			return out
		}
	}

	log.Printf("tenantkeysweep: tenant %s re-keyed %s -> %s (%d nodes, %d revisions)",
		item.TenantID, oldRef.Handle, newRef.Handle, counts.Nodes, counts.Versions)
	out.Status = "rekeyed"
	out.Handle = newRef.Handle
	out.Nodes, out.Versions = counts.Nodes, counts.Versions
	return out
}

// sweepAllowed restricts the re-keying surface to an authenticated,
// non-sealed user principal — the same floor as configure, for the same
// reason: app grants and sealed-transport sessions carry no operator
// authority. The effective authority for the mutating call is the
// manager-minted grant each item carries: the vault verifies its IdP
// signature, so possession cannot be faked here.
func (s *Server) sweepAllowed(p *Principal) error {
	if !p.IsUser() {
		return errors.New("app grants cannot re-key tenant vault keys")
	}
	if p.Via == viaSealed {
		return errors.New("sealed-transport sessions cannot re-key tenant vault keys")
	}
	return nil
}

// ownerRefFromHandle pulls the data owner's hashed namespace segment out of a
// key handle (apps.privasys.org/<app>/data/<owner-ref>/mek/vN). Taking it
// from the handle rather than re-hashing a subject keeps this consistent with
// what the constellation actually holds, and keeps raw subjects out of the
// operator surface entirely.
func ownerRefFromHandle(handle string) string {
	const marker = "/data/"
	i := strings.Index(handle, marker)
	if i < 0 {
		return ""
	}
	rest := handle[i+len(marker):]
	if j := strings.Index(rest, "/"); j >= 0 {
		return rest[:j]
	}
	return rest
}

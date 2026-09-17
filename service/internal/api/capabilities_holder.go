package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/grants"
)

// The holder-facing half of the capability endpoint: what do I have here, and
// take it back.
//
// Drive could already list and revoke these. `GET /v1/grants/mine` returns
// them and `DELETE /v1/tenants/{tenantID}/grants/{grantID}` ends them, which is
// what the Drive web UI uses. The wallet cannot call that pair, because the
// revoke names the tenant in its path and the wallet is the one client that
// must never name an ownership boundary (S4). It would have to learn which
// tenant is the holder's in order to ask, and that is precisely the knowledge
// the capability design keeps out of it.
//
// So these two do the same work with the boundary DERIVED from the
// authenticated holder, exactly as the mint already does. The wallet sends a
// capability id and nothing else.
//
// The list route also serves as the wallet's probe for whether a service
// speaks this contract at all: a 404 here means "cannot be asked", which is a
// different thing from "you have nothing", and the wallet renders them
// differently rather than telling a holder their access is gone when it is not.

// capabilityView is one capability as its holder sees it.
type capabilityView struct {
	CapabilityID  string   `json:"capability_id"`
	Kind          string   `json:"kind"`
	Permissions   []string `json:"permissions"`
	ResourceLabel string   `json:"resource_label,omitempty"`
	SubjectAppID  string   `json:"subject_app_id"`
	CreatedUnix   int64    `json:"created_unix"`
	ExpiresUnix   int64    `json:"expires_unix,omitempty"`
}

// permissionsFromScopes is the inverse of scopesFromPermissions, so the holder
// reads back the same closed vocabulary their wallet showed them when they
// approved it rather than Drive's internal scope names.
func permissionsFromScopes(scopes []grants.Scope) []string {
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		switch s {
		case grants.ScopeRead:
			out = append(out, "read")
		case grants.ScopeWrite:
			out = append(out, "write")
		case grants.ScopeDelete:
			out = append(out, "delete")
		}
	}
	return out
}

// capabilityViewOf renders a grant, or reports that it is not one of these.
//
// Only grants minted through the wallet are returned. A grant made some other
// way is real access and belongs in Drive's own list, but it has no capability
// id the wallet could match, and showing it under a button the wallet cannot
// honour would be worse than leaving it where it is managed.
func capabilityViewOf(g *grants.Grant) (capabilityView, bool) {
	var meta struct {
		Kind   string `json:"kind"`
		Folder string `json:"folder"`
		AppID  string `json:"app_id"`
		Via    string `json:"via"`
	}
	if g.Meta == "" || json.Unmarshal([]byte(g.Meta), &meta) != nil {
		return capabilityView{}, false
	}
	if meta.Via != "wallet-capability" {
		return capabilityView{}, false
	}
	label := meta.Folder
	if i := strings.LastIndex(label, "/"); i >= 0 {
		label = label[i+1:]
	}
	view := capabilityView{
		CapabilityID:  g.ID,
		Kind:          meta.Kind,
		Permissions:   permissionsFromScopes(g.Scope),
		ResourceLabel: label,
		SubjectAppID:  grants.NormaliseAppSubject(g.Subject),
		CreatedUnix:   g.CreatedAt.Unix(),
	}
	if view.Kind == "" {
		view.Kind = capabilityKindStorageFolder
	}
	if g.ExpiresAt != nil {
		view.ExpiresUnix = g.ExpiresAt.Unix()
	}
	return view, true
}

// handleListCapabilities answers what the holder currently has with Drive.
//
// The tenant is derived, never read from the request, for the same reason the
// mint derives it: a caller that could name one could ask about a tenant the
// holder merely belongs to.
func (s *Server) handleListCapabilities(w http.ResponseWriter, r *http.Request, p *Principal) {
	// A capability is held BY a person over their own data, so only a person
	// may ask what they hold. An app asking would be asking about someone else.
	if !p.IsUser() {
		http.Error(w, "only a user may list their capabilities", http.StatusForbidden)
		return
	}
	tenant, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}
	rows, err := s.Grants.ListAppGrantsForTenant(r.Context(), tenant.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]capabilityView, 0, len(rows))
	for _, g := range rows {
		if view, ok := capabilityViewOf(g); ok {
			out = append(out, view)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"capabilities": out})
}

// handleRevokeCapability ends one, on the holder's instruction.
//
// 404 rather than 403 when the capability belongs to someone else: whether a
// given id exists is not something to confirm to a caller who does not hold it.
func (s *Server) handleRevokeCapability(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsUser() {
		http.Error(w, "only a user may revoke their capabilities", http.StatusForbidden)
		return
	}
	id := strings.TrimSpace(r.PathValue("capabilityID"))
	if id == "" {
		http.Error(w, "capability id required", http.StatusBadRequest)
		return
	}
	tenant, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}
	g, err := s.Grants.Get(r.Context(), id)
	if err != nil || g == nil {
		http.Error(w, "no such capability", http.StatusNotFound)
		return
	}
	// The boundary check. Derived tenant on one side, the grant's own tenant on
	// the other, and nothing from the request in between.
	if g.TenantID != tenant.ID {
		http.Error(w, "no such capability", http.StatusNotFound)
		return
	}
	if _, ok := capabilityViewOf(g); !ok {
		// Real access, but not one of these, so not something this route may
		// end. Drive's own list owns it.
		http.Error(w, "no such capability", http.StatusNotFound)
		return
	}
	if g.RevokedAt != nil {
		// Already gone, which is the outcome asked for. Distinct from 404 so
		// the wallet can record the revocation rather than a disappearance.
		w.WriteHeader(http.StatusGone)
		return
	}
	if err := s.Grants.Revoke(r.Context(), tenant.ID, g.ID); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	// Anything the service sealed for this capability goes with it. A
	// credential kept after the grant that justified it is gone is a credential
	// nobody authorised. Drive seals nothing of the sort today, so this is a
	// no-op here and a real obligation for services that do.
	if err := s.dropCapabilitySetup(r.Context(), g); err != nil {
		// The grant IS revoked; the app can no longer use it. Say so rather
		// than reporting a failure that would invite the holder to try again.
		log.Printf("capability %s revoked but its stored setup could not be dropped: %v", g.ID, err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// dropCapabilitySetup removes anything sealed on the holder's behalf for this
// capability. Drive stores no setup values, so there is nothing to drop. The
// hook exists so the obligation is visible where revocation happens rather than
// only in a document: a service that seals a credential for a capability has to
// destroy it here, or it is holding something nobody authorised.
func (s *Server) dropCapabilitySetup(_ context.Context, _ *grants.Grant) error {
	return nil
}

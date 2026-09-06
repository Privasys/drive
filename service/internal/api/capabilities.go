package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// The wallet-facing capability endpoint.
//
// An attested app asks a user for a scoped, revocable capability on a resource
// the user owns; the wallet verifies who is asking, renders it, captures the
// decision and POSTs here. See plans/wallet-resource-capabilities.md.
//
// Drive owns everything the wallet deliberately does not know: which tenant is
// the user's, whether the folder exists, and how a grant is minted. The wallet
// sends only what it can vouch for.
//
// The first version of this flow had the wallet resolve the personal tenant,
// create the folder and compose the grant body itself. That put Drive's data
// model in the wallet, and the next service would have needed a second screen.

const capabilityKindStorageFolder = "storage.folder"

// Keys that would let a caller select WHOSE data the capability lands on. The
// boundary is derived from the authenticated user and never supplied: Drive's
// rule for creating a grant is a user principal with WRITE rights on the
// tenant (canShare is canWrite), which includes enterprise tenants the user
// merely belongs to. A request carrying one of these could therefore aim a
// capability at a tenant the holder never had in mind, while the wallet screen
// said "a folder in your Drive" and was, as far as it knew, telling the truth.
var boundarySelectors = []string{"tenant", "tenant_id", "tenantid", "owner", "owner_sub", "sub", "user", "user_sub"}

type capabilityRequest struct {
	// Correlates the app's pending request with this approval. Opaque to
	// Drive; recorded for audit and echoed back so the wallet can match.
	Nonce string `json:"nonce"`
	// The app id the WALLET verified from attestation (OID
	// 1.3.6.1.4.1.65230.4.1), never a value the requesting app supplied.
	SubjectAppID string `json:"subject_app_id"`
	// The key proved inside the attested channel. This is the credential the
	// capability authenticates; the app identity is the second, independent
	// check on the data plane.
	BindingPubkey string `json:"binding_pubkey"`
	// Chosen by the wallet, never by the requester, so nobody can ask for an
	// unbounded capability.
	ExpiresUnix int64 `json:"expires_unix"`
	// Exactly what the wallet DISPLAYED, from its closed vocabulary. Sent so
	// the capability minted here cannot be wider than the one approved: without
	// it, Drive would be choosing a scope the user never saw.
	Permissions []string `json:"permissions"`
	Kind        string   `json:"kind"`
	// Service-specific and opaque to the wallet, which forwards it verbatim.
	// Subject to the boundary rule above.
	Request json.RawMessage `json:"request"`
}

type storageFolderRequest struct {
	Folder string `json:"folder"`
}

type capabilityResponse struct {
	CapabilityID string `json:"capability_id"`
	Nonce        string `json:"nonce,omitempty"`
	ExpiresUnix  int64  `json:"expires_unix,omitempty"`
	// Opaque to the wallet, forwarded verbatim to the requesting app. This is
	// how the app learns the coordinates it needs (tenant and node) without the
	// wallet ever handling them as meaningful values.
	ServiceResult map[string]string `json:"service_result,omitempty"`
}

// namesOwnershipBoundary reports whether a raw request object contains a key
// that would select whose data this is, at any depth.
func namesOwnershipBoundary(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var probe any
	if err := json.Unmarshal(raw, &probe); err != nil {
		// Undecodable is refused by the caller anyway; treat as unsafe.
		return true
	}
	return walkForBoundary(probe)
}

func walkForBoundary(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			lower := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
			for _, bad := range boundarySelectors {
				if lower == bad {
					return true
				}
			}
			if walkForBoundary(child) {
				return true
			}
		}
	case []any:
		for _, child := range t {
			if walkForBoundary(child) {
				return true
			}
		}
	}
	return false
}

// scopesFromPermissions maps the wallet's closed vocabulary onto Drive's.
// Anything outside it is refused rather than dropped: silently narrowing a
// scope the user approved is as wrong as silently widening it.
func scopesFromPermissions(perms []string) ([]grants.Scope, error) {
	if len(perms) == 0 {
		return nil, errors.New("permissions required")
	}
	out := make([]grants.Scope, 0, len(perms))
	seen := map[grants.Scope]bool{}
	for _, p := range perms {
		var s grants.Scope
		switch strings.ToLower(strings.TrimSpace(p)) {
		case "read":
			s = grants.ScopeRead
		case "write":
			s = grants.ScopeWrite
		case "delete":
			s = grants.ScopeDelete
		default:
			return nil, errors.New("unknown permission: " + p)
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out, nil
}

func (s *Server) handleCreateCapability(w http.ResponseWriter, r *http.Request, p *Principal) {
	// A capability is granted BY a person over their own data. An app or
	// assistant principal cannot create one, the same rule handleCreateGrant
	// already enforces.
	if !p.IsUser() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	var req capabilityRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Kind != "" && req.Kind != capabilityKindStorageFolder {
		http.Error(w, "unsupported capability kind", http.StatusBadRequest)
		return
	}
	if req.BindingPubkey == "" {
		http.Error(w, "binding_pubkey required", http.StatusBadRequest)
		return
	}
	if req.SubjectAppID == "" {
		http.Error(w, "subject_app_id required", http.StatusBadRequest)
		return
	}
	// Normalised so the data-plane match against the attested peer identity is
	// exact. Rejects anything that is not an app id or code hash.
	appID := grants.NormaliseAppSubject(grants.SubjectApp + req.SubjectAppID)
	if appID == "" {
		http.Error(w, "subject_app_id must be an app id", http.StatusBadRequest)
		return
	}
	scope, err := scopesFromPermissions(req.Permissions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// S4. Refuse before doing anything, and say why: this is the check that
	// makes it safe for the wallet to forward a payload it never read.
	if namesOwnershipBoundary(req.Request) {
		http.Error(w,
			"request must not name an ownership boundary; the tenant is derived from the authenticated user",
			http.StatusBadRequest)
		return
	}

	var body storageFolderRequest
	if len(req.Request) > 0 {
		if err := json.Unmarshal(req.Request, &body); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
	}
	if strings.TrimSpace(body.Folder) == "" {
		http.Error(w, "request.folder required", http.StatusBadRequest)
		return
	}

	// The boundary, derived. Not read from anywhere in the request.
	tenant, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}

	node, status, err := s.ensureFolder(r, p, tenant.ID, strings.TrimSpace(body.Folder))
	if err != nil {
		httpError(w, status, err)
		return
	}

	g := &grants.Grant{
		TenantID:      tenant.ID,
		NodeID:        node.ID,
		Subject:       grants.SubjectApp + appID,
		Scope:         scope,
		CreatedBy:     p.Sub,
		BindingPubkey: req.BindingPubkey,
		Meta:          capabilityMeta(req, node.Name),
	}
	if req.ExpiresUnix > 0 {
		t := time.Unix(req.ExpiresUnix, 0).UTC()
		g.ExpiresAt = &t
	}
	if err := s.Grants.Create(r.Context(), g); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusCreated, capabilityResponse{
		CapabilityID: g.ID,
		Nonce:        req.Nonce,
		ExpiresUnix:  req.ExpiresUnix,
		// Opaque to the wallet; the app needs these to address Drive.
		ServiceResult: map[string]string{
			"tenant_id": tenant.ID,
			"node_id":   node.ID,
			"grant_id":  g.ID,
		},
	})
}

// ensureFolder returns the named folder at the tenant root, creating it only if
// it is absent. Idempotent so a re-approval does not produce a second folder,
// and so the "already exists" case is not an error the holder has to interpret.
func (s *Server) ensureFolder(r *http.Request, p *Principal, tenantID, name string) (*store.Node, int, error) {
	kids, err := s.Store.ListChildren(r.Context(), tenantID, "")
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	for _, n := range kids {
		if n.Kind == store.NodeFolder && n.Name == name {
			return n, http.StatusOK, nil
		}
	}
	return s.createFolder(r.Context(), p, tenantID, "", name)
}

// capabilityMeta is what a later "apps with access to my Drive" list shows.
// Populated rather than left empty, since an unexplained grant in that list is
// worse than no list.
func capabilityMeta(req capabilityRequest, folder string) string {
	m := map[string]string{
		"kind":   capabilityKindStorageFolder,
		"folder": folder,
		"via":    "wallet-capability",
	}
	if req.Nonce != "" {
		m["nonce"] = req.Nonce
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(raw)
}

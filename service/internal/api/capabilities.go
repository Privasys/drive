package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// appDataRoot is the one folder in a personal Drive that apps may be granted
// into. Every capability lands at AppData/<app folder>/: the root of a user's
// Drive stays theirs however many apps they approve, and the storage gauge
// can break AppData down by app. First-party Drive roots ("Chat
// conversations", "Memory") are Drive's own features, not app grants, and
// live where they always did.
const appDataRoot = "AppData"

// The wallet-facing capability endpoint.
//
// An attested app asks a user for a scoped, revocable capability on a resource
// the user owns; the wallet verifies who is asking, renders it, captures the
// decision and POSTs here.
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
	// Label is the app's declared resource label, forwarded by the runtime in
	// a kind-agnostic envelope. Drive is what turns a label into a folder
	// name; the runtime does not know what a folder is and should not.
	Label string `json:"label"`
	// Folder is the older spelling of the same value, from a runtime that
	// still emits Drive's own vocabulary. Accepted so the two can be rolled
	// independently; remove once no fleet sends it.
	Folder string `json:"folder"`
}

// name is the label the holder approved, under whichever spelling arrived.
func (r storageFolderRequest) name() string {
	if r.Label != "" {
		return r.Label
	}
	return r.Folder
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
	// The app's folder name: the label the holder approved on the wallet screen
	// (the app's resource_label, forwarded as request.label, or request.folder
	// from an older runtime), else the app's display name as the control plane
	// knows it, else the app id. Never a path: the app is confined to its one
	// folder under AppData.
	label := sanitiseFolderName(body.name())

	// The boundary, derived. Not read from anywhere in the request.
	tenant, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}

	if label == "" {
		if cfg := s.CurrentConfig(); cfg != nil && cfg.MgmtBaseURL != "" {
			label = sanitiseFolderName(resolveAppDisplayName(r.Context(), cfg.MgmtBaseURL, appID))
		}
	}
	if label == "" {
		label = "app-" + appID[:8]
	}

	appData, status, err := s.ensureChild(r, p, tenant.ID, "", appDataRoot)
	if err != nil {
		httpError(w, status, err)
		return
	}
	node, status, err := s.appFolder(r, p, tenant.ID, appData.ID, label, appID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	path := appDataRoot + "/" + node.Name

	g := &grants.Grant{
		TenantID:      tenant.ID,
		NodeID:        node.ID,
		Subject:       grants.SubjectApp + appID,
		Scope:         scope,
		CreatedBy:     p.Sub,
		BindingPubkey: req.BindingPubkey,
		Meta:          capabilityMeta(req, path, appID),
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
		// Opaque to the wallet; the app needs these to address Drive. The path
		// is informational, so the app can tell the user where it writes.
		ServiceResult: map[string]string{
			"tenant_id": tenant.ID,
			"node_id":   node.ID,
			"grant_id":  g.ID,
			"path":      path,
		},
	})
}

// ensureChild returns the named folder under parentID ("" = tenant root),
// creating it only if it is absent. Idempotent so a re-approval does not
// produce a second folder.
func (s *Server) ensureChild(r *http.Request, p *Principal, tenantID, parentID, name string) (*store.Node, int, error) {
	kids, err := s.Store.ListChildren(r.Context(), tenantID, parentID)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	for _, n := range kids {
		if n.Kind == store.NodeFolder && n.Name == name {
			return n, http.StatusOK, nil
		}
	}
	return s.createFolder(r.Context(), p, tenantID, parentID, name)
}

// appFolder returns the app's folder under AppData, bound to that app id. A
// folder is reused only when a grant on it already names this app (a
// re-approval, including after a revoke); a folder of the same name that
// belongs to another app, or that the user made themselves, is never handed
// over: the app gets "<label> (<8 hex of its id>)" instead. Two apps can share
// a label, and a label is what the holder approved, so the name is a UX fact
// and the app id is the identity.
func (s *Server) appFolder(r *http.Request, p *Principal, tenantID, parentID, label, appID string) (*store.Node, int, error) {
	kids, err := s.Store.ListChildren(r.Context(), tenantID, parentID)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	for _, name := range []string{label, label + " (" + appID[:8] + ")"} {
		var existing *store.Node
		for _, n := range kids {
			if n.Kind == store.NodeFolder && n.Name == name {
				existing = n
				break
			}
		}
		if existing == nil {
			created, status, err := s.createFolder(r.Context(), p, tenantID, parentID, name)
			if err == nil {
				// An app's folder is not part of the user's searchable memory
				// unless the user says so: apps cannot mark their own folder,
				// so Drive excludes it at creation (the user can re-enable it).
				_ = s.Store.SetNoIndex(r.Context(), tenantID, created.ID, true)
			}
			return created, status, err
		}
		owned, err := s.Grants.ListForNode(r.Context(), tenantID, existing.ID)
		if err != nil {
			return nil, http.StatusInternalServerError, err
		}
		for _, g := range owned {
			if grantNamesApp(g, appID) {
				return existing, http.StatusOK, nil
			}
		}
	}
	return nil, http.StatusConflict, errors.New("the app's folder name is already taken in AppData")
}

// sanitiseFolderName turns a requested label into one folder name: no path
// separators, no dot-names, bounded length. Empty when nothing usable remains,
// so the caller falls back rather than creating a folder called "..".
func sanitiseFolderName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.NewReplacer("/", "-", "\\", "-", "\x00", "").Replace(s)
	s = strings.TrimLeft(s, ".")
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 100 {
		s = strings.TrimSpace(string(r[:100]))
	}
	// A name made only of separators and punctuation ("../" → "-") is not a
	// name; require something a person could recognise.
	if !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) {
		return ""
	}
	return s
}

// resolveAppDisplayName asks the control plane's public resolve endpoint for
// the app's display name (falling back to its canonical name). Best effort:
// any failure returns "" and the caller falls back, so an unreachable control
// plane never blocks an approval the holder already made.
func resolveAppDisplayName(ctx context.Context, mgmtBaseURL, appID string) string {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u := strings.TrimRight(mgmtBaseURL, "/") + "/api/v1/apps/" + url.PathEscape(appID) + "/resolve"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var out struct {
		DisplayName string `json:"display_name"`
		Name        string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ""
	}
	if strings.TrimSpace(out.DisplayName) != "" {
		return out.DisplayName
	}
	return out.Name
}

// capabilityMeta is what a later "apps with access to my Drive" list shows.
// Populated rather than left empty, since an unexplained grant in that list is
// worse than no list.
func capabilityMeta(req capabilityRequest, path, appID string) string {
	m := map[string]string{
		"kind":   capabilityKindStorageFolder,
		"folder": path,
		"app_id": appID,
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

// grantNamesApp reports whether a grant on a folder belongs to appID: by its
// subject through the normaliser (older grants carry a code digest or a
// dashed id) or by the app id its capability meta recorded. Comparing the raw
// subject string once left an app with two folders.
func grantNamesApp(g *grants.Grant, appID string) bool {
	if grants.NormaliseAppSubject(g.Subject) == appID {
		return true
	}
	var meta struct {
		AppID string `json:"app_id"`
	}
	if g.Meta != "" && json.Unmarshal([]byte(g.Meta), &meta) == nil && meta.AppID == appID {
		return true
	}
	return false
}

// Package api glues the storage primitives behind the Privasys Drive
// REST surface. The handlers are intentionally thin — every operation
// has a matching public function in the underlying packages so the
// manifest-tool surface (tools.go) can call them directly without going
// through HTTP.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/config"
	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/deptls"
	"github.com/Privasys/drive/service/internal/export"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/notify"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/oidc"
	"github.com/Privasys/drive/service/internal/platform"
	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

// appGrantAudience is the aud an AppGrant envelope must carry.
const appGrantAudience = "privasys-drive"

// Server bundles the handlers + their dependencies.
type Server struct {
	Store    *store.Store
	Backend  objectstore.Backend
	Grants   *grants.Repo
	Verifier oidc.Verifier
	MEK      []byte // single tenant MEK for `--dev`. Production: fetched per tenant from vault.

	// Revoked rejects tokens whose IdP session was revoked (long-lived
	// API keys). Nil disables the check.
	Revoked *oidc.RevokedSet

	// MEKs provisions and loads per-tenant vault-held MEKs. Nil
	// disables vault-held tenant keys (tenants stay on the instance
	// MEK).
	MEKs MEKProvider

	// Platform is the enclave-manager environment (empty off-platform).
	Platform platform.Env
	// StateDir persists the instance config (the sealed /data volume on
	// the platform).
	StateDir string
	// DevMode relaxes the configure-authz role check (dev verifier runs
	// without platform roles).
	DevMode bool
	Version string

	cfgMu sync.RWMutex
	cfg   *config.Config

	// uploads holds in-flight chunked upload sessions (large files
	// arrive as sequential sealed parts staged on /data).
	uploads uploadRegistry

	backendsOnce sync.Once
	backends     *tenantBackends

	// fleetHTTP is the attested-dependency HTTP client for the
	// embeddings fleet, rebuilt by applyConfigSideEffects whenever the
	// pin changes. Nil when no dependency is configured (plain HTTPS).
	fleetMu   sync.Mutex
	fleetHTTP *http.Client
	fleetKey  string

	// notifier pushes wallet notifications via the control plane
	// (share requests/decisions). Nil off-platform or before configure.
	notifyMu sync.Mutex
	notifier *notify.Client

	// recVer caches per-issuer JWKS verifiers for recovery approvals.
	recVerMu sync.Mutex
	recVer   map[string]oidc.Verifier

	// bg tracks fire-and-forget background writes (access metrics) so a
	// shutdown — or a test — can drain them before the store closes.
	bg sync.WaitGroup
}

// WaitBackground blocks until in-flight background writes (access
// metrics) have drained. Call before closing the store.
func (s *Server) WaitBackground() { s.bg.Wait() }

// authVia records how a principal authenticated.
type authVia string

const (
	viaBearer   authVia = "bearer"   // platform OIDC at+jwt
	viaAppGrant authVia = "appgrant" // Ed25519 AppGrant token
	viaSealed   authVia = "sealed"   // session-relay sealed transport (X-Privasys-Sub)
)

// relaySubHeader is the relay-asserted subject. The enclave-os
// session-relay middleware strips any inbound value and sets it only
// from an authenticated sealed session, so a present value is
// trustworthy for data-plane attribution (it carries no roles, which
// is why it is never accepted for configure).
const relaySubHeader = "X-Privasys-Sub"

// Principal is an authenticated caller: a platform user (OIDC bearer or
// sealed-transport session) or a third-party app presenting an
// AppGrant token.
type Principal struct {
	Sub   string
	Via   authVia
	ID    *oidc.Identity   // non-nil for users
	Grant *grants.Grant    // non-nil for app principals
	Env   *grants.Envelope // non-nil for app principals
}

// IsUser reports whether p is a user (OIDC bearer or sealed session).
func (p *Principal) IsUser() bool { return p.ID != nil }

// SetConfig installs (and persists) the instance configuration.
func (s *Server) SetConfig(c *config.Config) error {
	if c.EmbeddingsDependency != "" {
		if _, err := deptls.ParseDependencySet(c.EmbeddingsDependency); err != nil {
			return fmt.Errorf("embeddings_dependency: %w", err)
		}
	}
	if err := c.Save(s.StateDir); err != nil {
		return err
	}
	s.cfgMu.Lock()
	prev := s.cfg
	s.cfg = c
	s.cfgMu.Unlock()
	s.applyConfigSideEffects(c)
	// An embedding-space change (model cutover or upgrade) schedules the
	// background reindex: indexed files flip to pending and the sweep
	// re-embeds them into the new space. Boot-time re-apply goes through
	// InstallConfig and never triggers this (prev == nil here means the
	// FIRST configure of a fresh instance, where nothing is indexed yet
	// anyway — resetting is a no-op).
	if embedSpaceOf(prev) != embedSpaceOf(c) {
		if n, err := s.Store.ResetIndexedForReindex(context.Background()); err == nil && n > 0 {
			log.Printf("search: embedding space changed (%s -> %s), %d files scheduled for reindex",
				embedSpaceOf(prev), embedSpaceOf(c), n)
			s.indexer() // ensure the sweep goroutine is running
		}
	}
	return nil
}

// embedSpaceOf mirrors activeEmbedder's space selection for a config.
func embedSpaceOf(c *config.Config) string {
	if c != nil && c.EmbeddingsBaseURL != "" {
		model := c.EmbeddingsModel
		if model == "" {
			model = "qwen3-embedding-0.6b"
		}
		return (&search.FleetEmbedder{Model: model}).Space()
	}
	return search.LocalEmbedder{}.Space()
}

// InstallConfig sets the in-memory config without persisting (boot-time
// re-apply of an already-persisted config).
func (s *Server) InstallConfig(c *config.Config) {
	s.cfgMu.Lock()
	s.cfg = c
	s.cfgMu.Unlock()
	s.applyConfigSideEffects(c)
}

// applyConfigSideEffects wires config-driven runtime behaviour. With a
// control-plane base URL configured, the vault client self-heals stale
// attestation tokens via the app's manager-minted identity; with an
// embeddings dependency pinned, the fleet HTTP client is (re)built to
// dial RA-TLS and refuse any peer that is not the pinned identity.
func (s *Server) applyConfigSideEffects(c *config.Config) {
	if c == nil || c.MgmtBaseURL == "" {
		return
	}
	var v *vaultmek.Client
	if vc, ok := s.MEKs.(*vaultmek.Client); ok && vc != nil {
		v = vc
		if r := v.MgmtTokenRefresher(c.MgmtBaseURL); r != nil {
			v.SetTokenRefresher(r)
		}
	}
	s.notifyMu.Lock()
	s.notifier = nil // rebuilt lazily against the (possibly new) base URL
	s.notifyMu.Unlock()
	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()
	key := fmt.Sprintf("%s|%t", c.EmbeddingsDependency, c.EmbeddingsAllowDebug)
	if key == s.fleetKey {
		return
	}
	s.fleetHTTP, s.fleetKey = nil, key
	if c.EmbeddingsDependency == "" || v == nil {
		return
	}
	set, err := deptls.ParseDependencySet(c.EmbeddingsDependency)
	if err != nil {
		// SetConfig validates before persisting; a bad stored set stays
		// fail-closed (no client => fleet calls error, files park).
		log.Printf("search: embeddings_dependency invalid, fleet dialling disabled: %v", err)
		return
	}
	s.fleetHTTP = deptls.NewHTTPClient(set, v.AttestationCredentials, c.EmbeddingsAllowDebug)
}

// Notifier returns the wallet-push client, building it lazily from the
// current config's control-plane base URL and the app's manager-minted
// identity. Nil when either is unavailable (off-platform / unconfigured):
// notifications degrade to silence, never to an error.
func (s *Server) Notifier() *notify.Client {
	s.notifyMu.Lock()
	defer s.notifyMu.Unlock()
	if s.notifier != nil {
		return s.notifier
	}
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.MgmtBaseURL == "" {
		return nil
	}
	v, ok := s.MEKs.(*vaultmek.Client)
	if !ok || v == nil {
		return nil
	}
	s.notifier = notify.New(cfg.MgmtBaseURL, v.AppIdentityHeaders)
	return s.notifier
}

// fleetClient returns the pinned attested-dependency HTTP client, or
// nil when no pin is configured.
func (s *Server) fleetClient() *http.Client {
	s.fleetMu.Lock()
	defer s.fleetMu.Unlock()
	return s.fleetHTTP
}

// CurrentConfig returns the active config, or nil before configure.
func (s *Server) CurrentConfig() *config.Config {
	s.cfgMu.RLock()
	defer s.cfgMu.RUnlock()
	return s.cfg
}

// Handler returns the full HTTP surface: health/status/configure, the
// REST API under /v1, the manifest tools under /tools, and the manifest
// document endpoints.
func (s *Server) Handler(manifestPath string) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/", s.Routes())
	mux.Handle("/tools/", s.Tools())
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /readiness", s.handleReadiness)
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.Handle("POST /status", s.auth(s.handleStatusTool))
	mux.Handle("POST /configure", s.auth(s.handleConfigure))
	if manifestPath != "" {
		mux.HandleFunc("GET /privasys.json", func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, manifestPath)
		})
		mux.Handle("/mcp/", legacyToolCatalog(manifestPath))
	}
	return loggingMiddleware(mux)
}

// Routes returns the HTTP handler with all REST routes mounted under /v1.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.Handle("GET /v1/me", s.auth(s.handleMe))
	mux.Handle("POST /v1/me/tenant", s.auth(s.handleEnsurePersonalTenant))
	mux.Handle("POST /v1/me/tenant/key", s.auth(s.handleTenantKey))
	mux.Handle("GET /v1/shared", s.auth(s.handleSharedWithMe))
	mux.Handle("POST /v1/tenants", s.auth(s.handleCreateTenant))
	mux.Handle("POST /v1/tenants/{tenantID}/members", s.auth(s.handleAddMember))
	mux.Handle("GET /v1/tenants/{tenantID}/members", s.auth(s.handleListMembers))
	mux.Handle("PATCH /v1/tenants/{tenantID}/members/{sub}", s.auth(s.handleSetMemberRole))
	mux.Handle("DELETE /v1/tenants/{tenantID}/members/{sub}", s.auth(s.handleRemoveMember))
	mux.Handle("POST /v1/tenants/{tenantID}/folders", s.auth(s.handleCreateFolder))
	mux.Handle("GET /v1/tenants/{tenantID}/folders/{folderID}", s.auth(s.handleListFolder))
	mux.Handle("GET /v1/tenants/{tenantID}/root", s.auth(s.handleListRoot))
	mux.Handle("POST /v1/tenants/{tenantID}/files", s.auth(s.handleUploadFile))
	// Chunked uploads: large files arrive as an upload session with
	// sequential parts, finalized through the same seal path.
	mux.Handle("POST /v1/tenants/{tenantID}/uploads", s.auth(s.handleCreateUpload))
	mux.Handle("PUT /v1/tenants/{tenantID}/uploads/{uploadID}/chunks/{index}", s.auth(s.handleUploadPart))
	mux.Handle("POST /v1/tenants/{tenantID}/uploads/{uploadID}/finalize", s.auth(s.handleFinalizeUpload))
	mux.Handle("DELETE /v1/tenants/{tenantID}/uploads/{uploadID}", s.auth(s.handleAbortUpload))
	mux.Handle("GET /v1/tenants/{tenantID}/files/{fileID}", s.auth(s.handleDownloadFile))
	mux.Handle("GET /v1/tenants/{tenantID}/metrics", s.auth(s.handleTenantMetrics))
	// Conversations in Drive (§8.7).
	mux.Handle("POST /v1/tenants/{tenantID}/conversations", s.auth(s.handleCreateConversation))
	mux.Handle("GET /v1/tenants/{tenantID}/conversations", s.auth(s.handleListConversations))
	mux.Handle("GET /v1/tenants/{tenantID}/conversations/{convID}", s.auth(s.handleGetConversation))
	mux.Handle("DELETE /v1/tenants/{tenantID}/conversations/{convID}", s.auth(s.handleDeleteConversation))
	mux.Handle("POST /v1/tenants/{tenantID}/conversations/{convID}/turns", s.auth(s.handleAppendTurn))
	mux.Handle("POST /v1/tenants/{tenantID}/conversations/{convID}/attach", s.auth(s.handleAttachToConversation))
	// Folder tree + Memory (§8.7).
	mux.Handle("GET /v1/tenants/{tenantID}/tree", s.auth(s.handleFolderTree))
	mux.Handle("GET /v1/tenants/{tenantID}/folders/{folderID}/tree", s.auth(s.handleFolderTree))
	mux.Handle("GET /v1/tenants/{tenantID}/memory", s.auth(s.handleGetMemory))
	mux.Handle("POST /v1/tenants/{tenantID}/memory", s.auth(s.handleWriteMemory))
	mux.Handle("POST /v1/tenants/{tenantID}/conversations/{convID}/finalize", s.auth(s.handleFinalizeConversation))
	// Links, graph & wiki-lint (§8.7).
	mux.Handle("GET /v1/tenants/{tenantID}/graph", s.auth(s.handleGraph))
	mux.Handle("GET /v1/tenants/{tenantID}/nodes/{nodeID}/backlinks", s.auth(s.handleBacklinks))
	mux.Handle("GET /v1/tenants/{tenantID}/lint", s.auth(s.handleLint))
	// AI scope (§8.7): enable/disable/list the assistant's subtree grants.
	mux.Handle("POST /v1/tenants/{tenantID}/nodes/{nodeID}/ai-scope", s.auth(s.handleEnableAI))
	mux.Handle("DELETE /v1/tenants/{tenantID}/nodes/{nodeID}/ai-scope", s.auth(s.handleDisableAI))
	mux.Handle("GET /v1/tenants/{tenantID}/ai-scope", s.auth(s.handleListAIScope))
	// Whole-Drive assistant scope (tenant-wide grant).
	mux.Handle("POST /v1/tenants/{tenantID}/ai-scope/all", s.auth(s.handleEnableAIAll))
	mux.Handle("DELETE /v1/tenants/{tenantID}/ai-scope/all", s.auth(s.handleDisableAIAll))
	mux.Handle("DELETE /v1/tenants/{tenantID}/nodes/{nodeID}", s.auth(s.handleDeleteNode))
	mux.Handle("POST /v1/tenants/{tenantID}/nodes/{nodeID}/move", s.auth(s.handleMoveNode))

	// Semantic index: per-tenant search + node searchability toggle +
	// the agentic retrieval legs (doc tree, whole-section reads).
	mux.Handle("GET /v1/tenants/{tenantID}/search", s.auth(s.handleSearch))
	mux.Handle("PUT /v1/tenants/{tenantID}/nodes/{nodeID}/indexing", s.auth(s.handleSetIndexing))
	mux.Handle("GET /v1/tenants/{tenantID}/files/{fileID}/tree", s.auth(s.handleDocTree))
	mux.Handle("GET /v1/tenants/{tenantID}/files/{fileID}/sections/{sectionID}", s.auth(s.handleReadSection))
	mux.Handle("PUT /v1/tenants/{tenantID}/nodes/{nodeID}/acl", s.auth(s.handleSetNodeACL))
	mux.Handle("GET /v1/tenants/{tenantID}/nodes/{nodeID}/permissions", s.auth(s.handleNodePermissions))
	mux.Handle("POST /v1/tenants/{tenantID}/nodes/{nodeID}/grants", s.auth(s.handleCreateGrant))
	mux.Handle("DELETE /v1/tenants/{tenantID}/grants/{grantID}", s.auth(s.handleRevokeGrant))
	// Share links: owner mints/lists on a node (revoke reuses the grant
	// route above, since a link is a grant); the recipient resolves and
	// redeems by link id after signing in.
	mux.Handle("POST /v1/tenants/{tenantID}/nodes/{nodeID}/links", s.auth(s.handleCreateLink))
	mux.Handle("GET /v1/tenants/{tenantID}/nodes/{nodeID}/links", s.auth(s.handleListLinks))
	mux.Handle("POST /v1/links/{linkID}/resolve", s.auth(s.handleResolveLink))
	mux.Handle("POST /v1/links/{linkID}/redeem", s.auth(s.handleRedeemLink))
	mux.Handle("GET /v1/tenants/{tenantID}/link-requests", s.auth(s.handleListLinkRequests))
	mux.Handle("POST /v1/tenants/{tenantID}/link-requests/{reqID}/{decision}", s.auth(s.handleDecideLinkRequest))
	mux.Handle("GET /v1/tenants/{tenantID}/changes", s.auth(s.handleChanges))
	mux.Handle("GET /v1/tenants/{tenantID}/quota", s.auth(s.handleQuota))
	mux.Handle("GET /v1/tenants/{tenantID}/audit", s.auth(s.handleAudit))
	mux.Handle("POST /v1/tenants/{tenantID}/recover", s.auth(s.handleRecoverTenant))
	mux.Handle("POST /v1/tenants/{tenantID}/recover/{recoveryID}/approve", s.auth(s.handleApproveRecovery))
	mux.Handle("GET /v1/tenants/{tenantID}/recover/{recoveryID}", s.auth(s.handleRecoveryStatus))
	mux.Handle("POST /v1/tenants/{tenantID}/exports", s.auth(s.handleExport))

	mux.Handle("PUT /v1/tenants/{tenantID}/bucket-cred", s.auth(s.handleSetBucketCred))
	mux.Handle("GET /v1/tenants/{tenantID}/bucket-cred", s.auth(s.handleGetBucketCred))
	mux.Handle("DELETE /v1/tenants/{tenantID}/bucket-cred", s.auth(s.handleDeleteBucketCred))

	return mux
}

// auth authenticates the caller: `Bearer <oidc token>` for users,
// `AppGrant <envelope>.<sig>` for third-party apps holding a grant, or
// the relay-asserted `X-Privasys-Sub` for a session-relay sealed
// session (browser / wallet). The sealed identity is trustworthy
// because the enclave-os middleware in front of the app strips any
// inbound value and sets it only from an authenticated session; it
// carries no roles, so it is a data-plane identity (never configure).
func (s *Server) auth(next func(http.ResponseWriter, *http.Request, *Principal)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		switch {
		case strings.HasPrefix(h, "Bearer "):
			id, err := s.Verifier.Verify(r.Context(), strings.TrimPrefix(h, "Bearer "))
			if err != nil {
				http.Error(w, "invalid token: "+err.Error(), http.StatusUnauthorized)
				return
			}
			if s.Revoked.Has(id.SID) {
				http.Error(w, "credential revoked", http.StatusUnauthorized)
				return
			}
			next(w, r, &Principal{Sub: id.Sub, Via: viaBearer, ID: id})
		case strings.HasPrefix(h, "AppGrant "):
			p, err := s.verifyAppGrant(r.Context(), strings.TrimSpace(strings.TrimPrefix(h, "AppGrant ")))
			if err != nil {
				http.Error(w, "invalid app grant: "+err.Error(), http.StatusUnauthorized)
				return
			}
			next(w, r, p)
		case r.Header.Get(relaySubHeader) != "":
			sub := r.Header.Get(relaySubHeader)
			next(w, r, &Principal{Sub: sub, Via: viaSealed, ID: &oidc.Identity{Sub: sub, Issuer: "session-relay"}})
		default:
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
	})
}

// verifyAppGrant checks an AppGrant token end-to-end: signature (against
// the embedded key), envelope validity window and audience, then the
// persisted grant row — active, same tenant/node, and the signing key
// matches the one the grant was bound to at creation.
func (s *Server) verifyAppGrant(ctx context.Context, tok string) (*Principal, error) {
	env, err := grants.ParseToken(tok)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if env.Exp > 0 && now.Unix() > env.Exp {
		return nil, errors.New("token expired")
	}
	if env.Aud != appGrantAudience {
		return nil, fmt.Errorf("audience %q != %q", env.Aud, appGrantAudience)
	}
	if env.JTI == "" {
		return nil, errors.New("token has no jti")
	}
	g, err := s.Grants.Get(ctx, env.JTI)
	if err != nil {
		return nil, errors.New("grant not found")
	}
	if !g.IsActive(now) {
		return nil, errors.New("grant revoked or expired")
	}
	if !strings.HasPrefix(g.Subject, grants.SubjectApp) {
		return nil, errors.New("grant is not an app grant")
	}
	if g.TenantID != env.Sub || g.NodeID != env.Node {
		return nil, errors.New("token does not match the grant")
	}
	bound, err := decodePubkey(g.BindingPubkey)
	if err != nil || len(bound) == 0 {
		return nil, errors.New("grant has no binding key")
	}
	presented, err := decodePubkey(env.PK)
	if err != nil || !bytes.Equal(bound, presented) {
		return nil, errors.New("signing key does not match the grant binding")
	}
	return &Principal{Sub: g.Subject, Via: viaAppGrant, Grant: g, Env: env}, nil
}

// decodePubkey accepts raw-std or std base64 (wallets vary).
func decodePubkey(s string) ([]byte, error) {
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

// --- handlers ---------------------------------------------------------

type createTenantRequest struct {
	Kind store.TenantKind `json:"kind"`
	Name string           `json:"name"`
}

func (s *Server) handleCreateTenant(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsUser() {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createTenantRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Kind == "" {
		req.Kind = store.TenantUser
	}
	t := &store.Tenant{Kind: req.Kind, Name: req.Name}
	if err := s.Store.CreateTenant(r.Context(), t, p.Sub); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

type addMemberRequest struct {
	UserSub string           `json:"user_sub"`
	Role    store.MemberRole `json:"role"`
}

func (s *Server) handleAddMember(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	var req addMemberRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !p.IsUser() || !s.canAdmin(r.Context(), tenantID, p.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.Store.AddMember(r.Context(), &store.Member{TenantID: tenantID, UserSub: req.UserSub, Role: req.Role}); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createFolderRequest struct {
	ParentID string `json:"parent_id"`
	Name     string `json:"name"`
}

func (s *Server) handleCreateFolder(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	var req createFolderRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	n, status, err := s.createFolder(r.Context(), p, tenantID, req.ParentID, req.Name)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusCreated, nodeView(n))
}

func (s *Server) createFolder(ctx context.Context, p *Principal, tenantID, parentID, name string) (*store.Node, int, error) {
	if !s.allowNode(ctx, p, tenantID, parentID, grants.ScopeWrite) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	hmacKey, err := crypto.DeriveNameHMACKey(mek, tenantID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	n := &store.Node{
		TenantID: tenantID,
		Kind:     store.NodeFolder,
		Name:     name,
		NameHMAC: crypto.NameHMAC(hmacKey, name),
	}
	if parentID != "" {
		n.ParentID.String = parentID
		n.ParentID.Valid = true
	}
	if err := s.Store.CreateNode(ctx, n, p.Sub); err != nil {
		return nil, storeErrorStatus(err), err
	}
	return n, http.StatusCreated, nil
}

func (s *Server) handleListRoot(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	kids, status, err := s.listChildren(r.Context(), p, tenantID, "")
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mapNodesWithIndex(r.Context(), tenantID, kids))
}

func (s *Server) handleListFolder(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	folderID := r.PathValue("folderID")
	kids, status, err := s.listChildren(r.Context(), p, tenantID, folderID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, s.mapNodesWithIndex(r.Context(), tenantID, kids))
}

// mapNodesWithIndex attaches each node's listing extras (one batched
// query): the semantic-index state for the searchable indicator
// ("excluded" for no_index nodes, folders included, so the toggle
// shows its real state) and the creator for the Owner column.
func (s *Server) mapNodesWithIndex(ctx context.Context, tenantID string, ns []*store.Node) []nodeJSON {
	out := mapNodes(ns)
	ids := make([]string, 0, len(ns))
	for _, n := range ns {
		ids = append(ids, n.ID)
	}
	meta, err := s.Store.ListNodeMeta(ctx, tenantID, ids)
	if err != nil {
		return out
	}
	for i := range out {
		m := meta[out[i].ID]
		out[i].IndexStatus = m.IndexStatus
		out[i].CreatedBy = m.CreatedBy
	}
	return out
}

func (s *Server) listChildren(ctx context.Context, p *Principal, tenantID, folderID string) ([]*store.Node, int, error) {
	if !s.allowNode(ctx, p, tenantID, folderID, grants.ScopeRead) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	kids, err := s.Store.ListChildren(ctx, tenantID, folderID)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	return kids, http.StatusOK, nil
}

// handleUploadFile expects the file body in the request body. The
// metadata (parent, name, mime) come from query parameters so the body
// stream is exactly the plaintext.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	q := r.URL.Query()
	name := q.Get("name")
	if name == "" {
		http.Error(w, "name query parameter required", http.StatusBadRequest)
		return
	}
	n, status, err := s.uploadFile(r.Context(), p, tenantID, q.Get("parent_id"), name, q.Get("mime"), r.Body, q.Get("index") == "false")
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusCreated, nodeView(n))
}

func (s *Server) uploadFile(ctx context.Context, p *Principal, tenantID, parentID, name, mime string, body io.Reader, noIndex bool) (*store.Node, int, error) {
	if !s.allowNode(ctx, p, tenantID, parentID, grants.ScopeWrite) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	// Quota: a 0 limit is unlimited. Fast-reject when already at/over the
	// ceiling; otherwise cap the upload so a streamed body cannot blow
	// past it, and make the precise check after the write.
	limit := s.quotaLimit()
	var remaining int64
	if limit > 0 {
		used, uerr := s.Store.TenantUsageBytes(ctx, tenantID)
		if uerr != nil {
			return nil, http.StatusInternalServerError, uerr
		}
		remaining = limit - used
		if remaining <= 0 {
			return nil, http.StatusRequestEntityTooLarge,
				fmt.Errorf("tenant storage quota reached (%d bytes)", limit)
		}
		body = io.LimitReader(body, remaining+1)
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	hmacKey, err := crypto.DeriveNameHMACKey(mek, tenantID)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	n := &store.Node{
		TenantID: tenantID,
		Kind:     store.NodeFile,
		Name:     name,
		NameHMAC: crypto.NameHMAC(hmacKey, name),
		MimeHint: mime,
	}
	n.ID = store.NewID()
	if parentID != "" {
		n.ParentID.String = parentID
		n.ParentID.Valid = true
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	wr, err := manifest.Write(ctx, bk, dek, tenantID, n.ID, mime, 0, body)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	root, err := hex.DecodeString(wr.Manifest.MerkleRoot)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	n.MerkleRoot = root
	n.WrappedCEK = wr.WrappedCEK
	n.ManifestRef = wr.ManifestKey
	n.PlainSize = wr.Manifest.PlainSize
	// Precise quota check now that the true size is known: the capped
	// reader let at most remaining+1 bytes through, so a file exactly at
	// remaining passes and anything larger is rejected and cleaned up.
	if limit > 0 && n.PlainSize > remaining {
		_ = manifest.Delete(ctx, bk, dek, tenantID, n.ID, n.WrappedCEK)
		return nil, http.StatusRequestEntityTooLarge,
			fmt.Errorf("upload would exceed the tenant storage quota (%d bytes)", limit)
	}
	if err := s.Store.CreateNode(ctx, n, p.Sub); err != nil {
		return nil, storeErrorStatus(err), err
	}
	// Searchable by default: schedule semantic indexing unless the
	// upload opted out (folder exclusions re-check inside the worker).
	s.scheduleIndexing(ctx, n, noIndex)
	return n, http.StatusCreated, nil
}

// quotaLimit returns the per-tenant byte ceiling from the instance
// config (0 = unlimited). A per-tenant override can layer on later.
func (s *Server) quotaLimit() int64 {
	if cfg := s.CurrentConfig(); cfg != nil {
		return cfg.QuotaDefaultBytes
	}
	return 0
}

func (s *Server) handleDownloadFile(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	fileID := r.PathValue("fileID")
	n, rc, status, err := s.openFile(r.Context(), p, tenantID, fileID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	defer rc.Close()
	if n.MimeHint != "" {
		w.Header().Set("Content-Type", n.MimeHint)
	}
	w.Header().Set("Content-Length", strconv.FormatInt(n.PlainSize, 10))
	w.Header().Set("X-Drive-Merkle-Root", hex.EncodeToString(n.MerkleRoot))
	start := time.Now()
	written, err := io.Copy(w, rc)
	// Access telemetry (§7.6): subject, node, bytes, stream span. The
	// front marks explicit downloads with ?ctx=download; everything
	// else counts as a view. Recorded best-effort after the stream.
	s.recordAccess(p, tenantID, fileID, r.URL.Query().Get("ctx"), written, time.Since(start))
	if err != nil {
		// Best-effort: response already started.
		return
	}
}

// recordAccess writes one access event for a user principal. Internal
// readers (the indexer) never come through here, and app principals
// are attributed by their grant subject.
func (s *Server) recordAccess(p *Principal, tenantID, nodeID, ctxKind string, bytes int64, d time.Duration) {
	if p == nil || p.Sub == "" {
		return
	}
	event := "view"
	if ctxKind == "download" {
		event = "download"
	} else if !p.IsUser() {
		event = "tool"
	}
	s.bg.Add(1)
	go func() {
		defer s.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := s.Store.RecordAccessEvent(ctx, store.AccessEvent{
			TenantID: tenantID, Sub: p.Sub, Event: event, NodeID: nodeID,
			DurationMS: d.Milliseconds(), Bytes: bytes,
		}); err != nil {
			log.Printf("metrics: record access: %v", err)
		}
	}()
}

// handleTenantMetrics serves the owner's Insights aggregates: per-day
// series, top nodes, per-sub table. Subs are opaque — the wallet
// decorates them client-side; no PII lives here.
func (s *Server) handleTenantMetrics(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil && v > 0 && v <= 365 {
		days = v
	}
	series, err := s.Store.MetricsSeries(r.Context(), tenantID, days)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	topNodes, err := s.Store.MetricsTopNodes(r.Context(), tenantID, days, 20)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	subs, err := s.Store.MetricsSubs(r.Context(), tenantID, days, 100)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	uniq, err := s.Store.MetricsUniqueSubs(r.Context(), tenantID, days)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if series == nil {
		series = []store.MetricsDay{}
	}
	if topNodes == nil {
		topNodes = []store.MetricsNode{}
	}
	if subs == nil {
		subs = []store.MetricsSub{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"days": days, "series": series, "top_nodes": topNodes, "subs": subs,
		"unique_subs": uniq,
	})
}

func (s *Server) openFile(ctx context.Context, p *Principal, tenantID, fileID string) (*store.Node, io.ReadCloser, int, error) {
	if !s.allowNode(ctx, p, tenantID, fileID, grants.ScopeRead) {
		return nil, nil, http.StatusForbidden, errors.New("forbidden")
	}
	n, err := s.Store.GetNode(ctx, tenantID, fileID)
	if err != nil {
		return nil, nil, storeErrorStatus(err), err
	}
	if n.Kind != store.NodeFile {
		return nil, nil, http.StatusBadRequest, errors.New("not a file")
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, nil, http.StatusBadGateway, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return nil, nil, http.StatusBadGateway, err
	}
	_, rc, err := manifest.Read(ctx, bk, dek, tenantID, n.ID, n.WrappedCEK)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	return n, rc, http.StatusOK, nil
}

func (s *Server) handleDeleteNode(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	status, err := s.deleteNode(r.Context(), p, tenantID, nodeID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) deleteNode(ctx context.Context, p *Principal, tenantID, nodeID string) (int, error) {
	// Users delete with their write permission; apps need an explicit
	// delete scope on the grant.
	need := grants.ScopeWrite
	if !p.IsUser() {
		need = grants.ScopeDelete
	}
	if !s.allowNode(ctx, p, tenantID, nodeID, need) {
		return http.StatusForbidden, errors.New("forbidden")
	}
	n, err := s.Store.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return storeErrorStatus(err), err
	}
	// Reclaim the sealed blob of every file in the subtree. Deleting a folder
	// (a conversation, a UI folder) otherwise removes the rows but leaves the
	// descendants' object-store bytes orphaned forever.
	files := []*store.Node{n}
	if n.Kind == store.NodeFolder {
		if files, err = s.Store.ListSubtreeFiles(ctx, tenantID, nodeID); err != nil {
			return http.StatusInternalServerError, err
		}
	}
	s.deleteFileBlobs(ctx, tenantID, files)
	if err := s.Store.DeleteNode(ctx, tenantID, nodeID, p.Sub); err != nil {
		return storeErrorStatus(err), err
	}
	return http.StatusNoContent, nil
}

// deleteFileBlobs reclaims the sealed object-store bytes of the given file
// nodes. Best-effort: a failed unlink leaves a harmless orphan rather than
// blocking the delete. The tenant DEK is derived once for the whole batch.
func (s *Server) deleteFileBlobs(ctx context.Context, tenantID string, files []*store.Node) {
	has := false
	for _, n := range files {
		if n != nil && n.Kind == store.NodeFile && n.WrappedCEK != nil {
			has = true
			break
		}
	}
	if !has {
		return
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return
	}
	for _, n := range files {
		if n == nil || n.Kind != store.NodeFile || n.WrappedCEK == nil {
			continue
		}
		_ = manifest.Delete(ctx, bk, dek, tenantID, n.ID, n.WrappedCEK)
	}
}

type createGrantRequest struct {
	Subject       string         `json:"subject"`
	Scope         []grants.Scope `json:"scope"`
	BindingPubkey string         `json:"binding_pubkey,omitempty"`
	ExpiresUnix   int64          `json:"expires_unix,omitempty"`
	Meta          string         `json:"meta,omitempty"`
}

func (s *Server) handleCreateGrant(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req createGrantRequest
	if err := readJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Subject == "" {
		http.Error(w, "subject required", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(req.Subject, grants.SubjectApp) && req.BindingPubkey == "" {
		http.Error(w, "app grants require binding_pubkey", http.StatusBadRequest)
		return
	}
	g := &grants.Grant{
		TenantID:      tenantID,
		NodeID:        nodeID,
		Subject:       req.Subject,
		Scope:         req.Scope,
		CreatedBy:     p.Sub,
		BindingPubkey: req.BindingPubkey,
		Meta:          req.Meta,
	}
	if req.ExpiresUnix > 0 {
		t := time.Unix(req.ExpiresUnix, 0).UTC()
		g.ExpiresAt = &t
	}
	if err := s.Grants.Create(r.Context(), g); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (s *Server) handleRevokeGrant(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	grantID := r.PathValue("grantID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := s.Grants.Revoke(r.Context(), tenantID, grantID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleChanges(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, status, err := s.listChanges(r.Context(), p, tenantID, since, limit)
	if err != nil {
		httpError(w, status, err)
		return
	}
	writeJSON(w, http.StatusOK, rows)
}

func (s *Server) listChanges(ctx context.Context, p *Principal, tenantID string, since int64, limit int) ([]store.ChangeRow, int, error) {
	if !p.IsUser() || !s.canRead(ctx, tenantID, p.Sub) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	rows, err := s.Store.ListChanges(ctx, tenantID, since, limit)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	return rows, http.StatusOK, nil
}

func (s *Server) handleQuota(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	used, err := s.Store.TenantUsageBytes(r.Context(), tenantID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	limit := s.quotaLimit()
	out := map[string]any{"used_bytes": used, "limit_bytes": limit, "unlimited": limit == 0}
	if limit > 0 {
		out["remaining_bytes"] = max64(0, limit-used)
	}
	writeJSON(w, http.StatusOK, out)
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

type exportRequest struct {
	Mode export.Mode `json:"mode"`
	// Obsidian rewrites markdown drive:// citations to relative links so
	// the export opens as an Obsidian vault, graph included (§8.7).
	Obsidian bool `json:"obsidian"`
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	var req exportRequest
	if r.ContentLength > 0 {
		if err := readJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Mode == "" {
		req.Mode = export.ModePlaintext
	}
	mek, err := s.tenantMEK(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	bk, err := s.backendFor(r.Context(), tenantID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="drive-export.zip"`)
	if _, err := export.WriteZip(r.Context(), s.Store, bk, dek, tenantID, req.Mode, req.Obsidian, w); err != nil {
		// Headers already sent — best effort.
		return
	}
}

// --- access control ---------------------------------------------------

// memberRole returns the caller's role in the tenant, or "" when not a
// member. User tenants have exactly one member: the owner, recorded at
// tenant creation.
func (s *Server) memberRole(ctx context.Context, tenantID, sub string) store.MemberRole {
	r, err := s.Store.MemberRoleOf(ctx, tenantID, sub)
	if err != nil {
		return ""
	}
	return r
}

// tenantKind returns the tenant's kind, or "" on error.
func (s *Server) tenantKind(ctx context.Context, tenantID string) store.TenantKind {
	t, err := s.Store.GetTenant(ctx, tenantID)
	if err != nil {
		return ""
	}
	return t.Kind
}

func (s *Server) canRead(ctx context.Context, tenantID, sub string) bool {
	return s.memberRole(ctx, tenantID, sub) != ""
}

func (s *Server) canWrite(ctx context.Context, tenantID, sub string) bool {
	r := s.memberRole(ctx, tenantID, sub)
	return r != "" && r != store.RoleReader
}

func (s *Server) canShare(ctx context.Context, tenantID, sub string) bool {
	return s.canWrite(ctx, tenantID, sub)
}

func (s *Server) canAdmin(ctx context.Context, tenantID, sub string) bool {
	r := s.memberRole(ctx, tenantID, sub)
	return r == store.RoleOwner || r == store.RoleAdmin
}

// allowNode is the per-node access check for both principal kinds.
// nodeID may be "" for root-level operations (list root, create at
// root); app principals are always confined to their granted node's
// subtree, so a root-level operation is never allowed on a grant.
func (s *Server) allowNode(ctx context.Context, p *Principal, tenantID, nodeID string, need grants.Scope) bool {
	if p.IsUser() {
		if need == grants.ScopeRead {
			if s.canRead(ctx, tenantID, p.Sub) && s.aclAllows(ctx, tenantID, nodeID, p.Sub) {
				return true
			}
			// A user-to-user share grants the recipient read access to the
			// shared node (or its subtree), independent of tenant
			// membership and folder ACLs — the owner's explicit share is
			// the authorisation.
			return s.hasReadShare(ctx, tenantID, nodeID, p.Sub)
		}
		return s.canWrite(ctx, tenantID, p.Sub) && s.aclAllows(ctx, tenantID, nodeID, p.Sub)
	}
	// App principal: exact tenant, granted scope, node inside the
	// granted subtree.
	if p.Grant == nil || p.Grant.TenantID != tenantID {
		return false
	}
	if !p.Grant.HasScope(need) && !(need == grants.ScopeWrite && p.Grant.HasScope("read-write")) {
		return false
	}
	if nodeID == "" {
		return false
	}
	ok, err := s.Store.IsDescendantOrSelf(ctx, tenantID, p.Grant.NodeID, nodeID)
	return err == nil && ok
}

// aclAllows applies enterprise folder ACL overrides: if the nearest
// ancestor of nodeID (or nodeID itself) carries an override, the
// caller's role must be in its permitted set. The tenant owner is
// always allowed (an override cannot lock the owner out). User tenants
// and paths with no override inherit the tenant ACL unchanged (allow).
func (s *Server) aclAllows(ctx context.Context, tenantID, nodeID, sub string) bool {
	if nodeID == "" || s.tenantKind(ctx, tenantID) != store.TenantEnterprise {
		return true
	}
	roles, err := s.Store.EffectiveACL(ctx, tenantID, nodeID)
	if err != nil {
		return false
	}
	if roles == nil {
		return true // no override in the path
	}
	role := s.memberRole(ctx, tenantID, sub)
	if role == store.RoleOwner {
		return true
	}
	for _, r := range roles {
		if store.MemberRole(r) == role {
			return true
		}
	}
	return false
}

// handleSetNodeACL sets or clears a folder's ACL override (owner/admin).
// Body: {"roles": ["owner","admin","contributor"]}; an empty/absent
// roles list clears the override (inherit the tenant ACL).
func (s *Server) handleSetNodeACL(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canAdmin(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("owner/admin only"))
		return
	}
	var req struct {
		Roles []string `json:"roles"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	for _, role := range req.Roles {
		switch store.MemberRole(role) {
		case store.RoleOwner, store.RoleAdmin, store.RoleContributor, store.RoleReader:
		default:
			httpError(w, http.StatusBadRequest, fmt.Errorf("unknown role %q", role))
			return
		}
	}
	if err := s.Store.SetNodeACL(r.Context(), tenantID, nodeID, req.Roles); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "roles": req.Roles})
}

// --- helpers ----------------------------------------------------------

type nodeJSON struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	ParentID    string `json:"parent_id,omitempty"`
	Kind        string `json:"kind"`
	Name        string `json:"name"`
	MimeHint    string `json:"mime_hint,omitempty"`
	PlainSize   int64  `json:"size_bytes"`
	MerkleRoot  string `json:"merkle_root_hex,omitempty"`
	ManifestRef string `json:"manifest_ref,omitempty"`
	// IndexStatus: '' | pending | processing | indexed | skipped |
	// failed | excluded — drives the searchable indicator in listings.
	IndexStatus string `json:"index_status,omitempty"`
	// CreatedBy is the creator's sub (the Owner column); UpdatedAt is
	// RFC3339 (the Modified column).
	CreatedBy string `json:"created_by,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func nodeView(n *store.Node) nodeJSON {
	v := nodeJSON{
		ID: n.ID, TenantID: n.TenantID, Kind: string(n.Kind),
		Name: n.Name, MimeHint: n.MimeHint, PlainSize: n.PlainSize,
		ManifestRef: n.ManifestRef,
	}
	if !n.UpdatedAt.IsZero() {
		v.UpdatedAt = n.UpdatedAt.UTC().Format(time.RFC3339)
	}
	if n.ParentID.Valid {
		v.ParentID = n.ParentID.String
	}
	if len(n.MerkleRoot) > 0 {
		v.MerkleRoot = hex.EncodeToString(n.MerkleRoot)
	}
	return v
}

func mapNodes(ns []*store.Node) []nodeJSON {
	out := make([]nodeJSON, 0, len(ns))
	for _, n := range ns {
		out = append(out, nodeView(n))
	}
	return out
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func readJSON(r *http.Request, dst any) error {
	if r.Body == nil {
		return errors.New("empty request body")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	return json.Unmarshal(body, dst)
}

func httpError(w http.ResponseWriter, status int, err error) {
	// A stale/unavailable vault MEK is recoverable by re-arming; emit a
	// machine-readable 409 so a client re-arms and retries rather than
	// treating it as a hard failure, regardless of the status the caller
	// mapped it to.
	if errors.Is(err, ErrVaultKeyStale) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": err.Error(), "code": "vault_key_stale",
		})
		return
	}
	http.Error(w, err.Error(), status)
}

func storeErrorStatus(err error) int {
	switch {
	case errors.Is(err, store.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict
	case errors.Is(err, store.ErrInvalidInput):
		return http.StatusBadRequest
	case errors.Is(err, store.ErrForbidden):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

func writeStoreError(w http.ResponseWriter, err error) {
	httpError(w, storeErrorStatus(err), err)
}

// statusRecorder captures the response status for the request log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

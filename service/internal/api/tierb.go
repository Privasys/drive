package api

// Tier B — Drive as a filesystem for tool code (no processes): revision
// tokens and conditional writes (D1), path addressing under a grant root
// (D2), range reads (D4, the helper here; the download handler wires it),
// and grant lookup by binding key (D7). See
// plans/drive-as-remote-disk.md. Every route is additive; node-id
// addressing and the existing surface are untouched.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/store"
)

// maxInlineWrite caps a content body carried inline on a tier-B write
// (PUT content, PUT path). Larger objects use the chunked upload route,
// which streams to a fresh node. 64 MiB is comfortably above a document
// and well under a memory hazard.
const maxInlineWrite = 64 << 20

// fileReadCtx authorises a read of fileID and returns the node plus the
// backend and unwrapped tenant DEK needed to stream it — shared by the full
// and range read paths so both make the same access decision.
func (s *Server) fileReadCtx(ctx context.Context, p *Principal, tenantID, fileID string) (*store.Node, objectstore.Backend, []byte, int, error) {
	if !s.allowNode(ctx, p, tenantID, fileID, grants.ScopeRead) {
		return nil, nil, nil, http.StatusForbidden, errors.New("forbidden")
	}
	n, err := s.Store.GetNode(ctx, tenantID, fileID)
	if err != nil {
		return nil, nil, nil, storeErrorStatus(err), err
	}
	if n.Kind != store.NodeFile {
		return nil, nil, nil, http.StatusBadRequest, errors.New("not a file")
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, http.StatusBadGateway, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return nil, nil, nil, http.StatusInternalServerError, err
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return nil, nil, nil, http.StatusBadGateway, err
	}
	return n, bk, dek, http.StatusOK, nil
}

// writeNodeContent replaces an existing file node's bytes, enforcing the
// tenant quota on the size delta and, when ifRev >= 0, the D1 revision
// fence. Returns the node's new rev.
func (s *Server) writeNodeContent(ctx context.Context, p *Principal, tenantID, nodeID string, content []byte, ifRev int64) (int64, int, error) {
	if !s.allowNode(ctx, p, tenantID, nodeID, grants.ScopeWrite) {
		return 0, http.StatusForbidden, errors.New("forbidden")
	}
	// One writer per node at a time: the manifest sits at a fixed key, so
	// the rev check below and the manifest write must not interleave with
	// another writer's, or a refused writer could still clobber the blob.
	muAny, _ := s.nodeWriteMu.LoadOrStore(tenantID+"/"+nodeID, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	n, err := s.Store.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return 0, storeErrorStatus(err), err
	}
	if n.Kind != store.NodeFile {
		return 0, http.StatusBadRequest, errors.New("not a file")
	}
	// Refuse a stale writer BEFORE touching storage. The row update below
	// re-checks under the same condition as belt-and-braces.
	if ifRev >= 0 && n.Rev != ifRev {
		return 0, http.StatusPreconditionFailed, store.ErrStale
	}
	if limit := s.quotaLimit(); limit > 0 {
		used, uerr := s.Store.TenantUsageBytes(ctx, tenantID)
		if uerr != nil {
			return 0, http.StatusInternalServerError, uerr
		}
		if used-n.PlainSize+int64(len(content)) > limit {
			return 0, http.StatusRequestEntityTooLarge,
				fmt.Errorf("write would exceed the tenant storage quota (%d bytes)", limit)
		}
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return 0, http.StatusBadGateway, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return 0, http.StatusInternalServerError, err
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return 0, http.StatusBadGateway, err
	}
	wr, err := manifest.Write(ctx, bk, dek, tenantID, n.ID, n.MimeHint, 0, strings.NewReader(string(content)))
	if err != nil {
		return 0, http.StatusInternalServerError, err
	}
	root, _ := hex.DecodeString(wr.Manifest.MerkleRoot)
	newRev, err := s.Store.UpdateNodeContentCond(ctx, tenantID, n.ID, wr.WrappedCEK, root, wr.ManifestKey, wr.Manifest.PlainSize, p.Sub, ifRev)
	if err != nil {
		if errors.Is(err, store.ErrStale) {
			return 0, http.StatusPreconditionFailed, err
		}
		return 0, storeErrorStatus(err), err
	}
	if _, noIndex, merr := s.Store.NodeIndexMeta(ctx, tenantID, n.ID); merr == nil && !noIndex {
		n.WrappedCEK, n.ManifestRef, n.PlainSize, n.MerkleRoot = wr.WrappedCEK, wr.ManifestKey, wr.Manifest.PlainSize, root
		s.scheduleIndexing(ctx, n, false)
	}
	return newRev, http.StatusOK, nil
}

// parseIfMatch reads a quoted-decimal If-Match / If-None-Match header. It
// returns (rev, present, star). If-None-Match: * is the create-if-absent
// guard; If-Match: "<rev>" is the conditional-write fence.
func parseIfMatch(h string) (rev int64, present, star bool) {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0, false, false
	}
	if h == "*" {
		return 0, true, true
	}
	h = strings.Trim(h, `"`)
	n, err := strconv.ParseInt(h, 10, 64)
	if err != nil {
		return 0, false, false
	}
	return n, true, false
}

// handleReplaceContent — D1. PUT /v1/tenants/{t}/nodes/{id}/content replaces
// a file's bytes, honouring an optional If-Match: "<rev>" fence. The new rev
// is returned as the ETag and in the body.
func (s *Server) handleReplaceContent(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	ifRev := int64(-1)
	if rev, present, star := parseIfMatch(r.Header.Get("If-Match")); present && !star {
		ifRev = rev
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInlineWrite+1))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) > maxInlineWrite {
		httpError(w, http.StatusRequestEntityTooLarge, errors.New("body too large; use the chunked upload route"))
		return
	}
	newRev, status, err := s.writeNodeContent(r.Context(), p, tenantID, nodeID, body, ifRev)
	if err != nil {
		if status == http.StatusPreconditionFailed {
			writeStale(w, tenantID, nodeID, s)
			return
		}
		httpError(w, status, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(newRev, 10)))
	writeJSON(w, http.StatusOK, map[string]any{"rev": newRev})
}

// writeStale answers 412 with the node's current rev so a client re-reads
// and retries in one round trip.
func writeStale(w http.ResponseWriter, tenantID, nodeID string, s *Server) {
	cur := int64(-1)
	if n, err := s.Store.GetNode(context.Background(), tenantID, nodeID); err == nil {
		cur = n.Rev
	}
	writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": "stale", "rev": cur})
}

// serveRange answers a single-range GET with 206 and Content-Range,
// decrypting only the covering chunks (D4). It supports "bytes=off-",
// "bytes=off-end" and the suffix form "bytes=-N"; a multi-range request
// falls back to 200 (a full body is a valid response to any Range).
func (s *Server) serveRange(w http.ResponseWriter, r *http.Request, p *Principal, tenantID, fileID, rangeHdr string) {
	n, bk, dek, status, err := s.fileReadCtx(r.Context(), p, tenantID, fileID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	spec := strings.TrimPrefix(strings.TrimSpace(rangeHdr), "bytes=")
	if strings.Contains(spec, ",") {
		// Multi-range: serve the whole object instead (spec-permitted).
		s.streamFull(w, r, p, n, bk, dek, tenantID, fileID)
		return
	}
	dash := strings.IndexByte(spec, '-')
	if dash < 0 {
		httpError(w, http.StatusBadRequest, errors.New("invalid Range"))
		return
	}
	var off, length int64
	if dash == 0 { // suffix: last N bytes
		nsuf, perr := strconv.ParseInt(spec[1:], 10, 64)
		if perr != nil || nsuf <= 0 {
			httpError(w, http.StatusBadRequest, errors.New("invalid Range suffix"))
			return
		}
		if nsuf > n.PlainSize {
			nsuf = n.PlainSize
		}
		off, length = n.PlainSize-nsuf, nsuf
	} else {
		o, perr := strconv.ParseInt(spec[:dash], 10, 64)
		if perr != nil || o < 0 {
			httpError(w, http.StatusBadRequest, errors.New("invalid Range start"))
			return
		}
		off = o
		if end := strings.TrimSpace(spec[dash+1:]); end != "" {
			e, eerr := strconv.ParseInt(end, 10, 64)
			if eerr != nil || e < off {
				httpError(w, http.StatusBadRequest, errors.New("invalid Range end"))
				return
			}
			length = e - off + 1
		}
	}
	if off >= n.PlainSize {
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", n.PlainSize))
		httpError(w, http.StatusRequestedRangeNotSatisfiable, errors.New("range beyond end"))
		return
	}
	rc, total, err := manifest.ReadRange(r.Context(), bk, dek, tenantID, fileID, n.WrappedCEK, off, length)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	defer rc.Close()
	if n.MimeHint != "" {
		w.Header().Set("Content-Type", n.MimeHint)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Rev, 10)))
	w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", off, off+total-1, n.PlainSize))
	w.Header().Set("Content-Length", strconv.FormatInt(total, 10))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = io.Copy(w, rc)
}

// streamFull writes the whole decrypted file (the multi-range fallback).
func (s *Server) streamFull(w http.ResponseWriter, r *http.Request, p *Principal, n *store.Node, bk objectstore.Backend, dek []byte, tenantID, fileID string) {
	_, rc, err := manifest.Read(r.Context(), bk, dek, tenantID, fileID, n.WrappedCEK)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	defer rc.Close()
	if n.MimeHint != "" {
		w.Header().Set("Content-Type", n.MimeHint)
	}
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Rev, 10)))
	w.Header().Set("Content-Length", strconv.FormatInt(n.PlainSize, 10))
	_, _ = io.Copy(w, rc)
}

// ---- D2: path addressing under a grant root -----------------------------

// resolvePath walks path segments from rootID by name, using the existing
// (parent, name) uniqueness. rootID "" is the tenant root. Returns the
// final node, or ErrNotFound if any segment is missing. Segments are
// validated against traversal and NUL.
func (s *Server) resolvePath(ctx context.Context, tenantID, rootID string, segs []string) (*store.Node, error) {
	parent := rootID
	var node *store.Node
	for i, seg := range segs {
		kids, err := s.Store.ListChildren(ctx, tenantID, parent)
		if err != nil {
			return nil, err
		}
		var found *store.Node
		for _, n := range kids {
			if n.Name == seg {
				found = n
				break
			}
		}
		if found == nil {
			return nil, store.ErrNotFound
		}
		if i < len(segs)-1 && found.Kind != store.NodeFolder {
			return nil, store.ErrNotFound
		}
		node = found
		parent = found.ID
	}
	return node, nil
}

// splitPath validates and splits a slash path. Empty, "..", "." and NUL are
// refused so a path can never escape its root.
func splitPath(p string) ([]string, error) {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return nil, errors.New("empty path")
	}
	segs := strings.Split(p, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." || strings.ContainsRune(s, 0) {
			return nil, errors.New("invalid path segment")
		}
	}
	return segs, nil
}

// handleStatPath — D2. GET /v1/tenants/{t}/path?root=&path= resolves a path
// under a root the caller may read, returning the node view (with rev) or
// 404, so a client resolves and reads metadata in one round trip.
func (s *Server) handleStatPath(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	root := r.URL.Query().Get("root")
	segs, err := splitPath(r.URL.Query().Get("path"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !s.allowNode(r.Context(), p, tenantID, root, grants.ScopeRead) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	node, err := s.resolvePath(r.Context(), tenantID, root, segs)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}
	writeJSON(w, http.StatusOK, nodeView(node))
}

// handleWritePath — D2. PUT /v1/tenants/{t}/path?root=&path= upserts file
// content at a path under a root the caller may write. X-Drive-Parents:
// create makes intermediate folders (mkdir -p). If-Match / If-None-Match as
// D1.
func (s *Server) handleWritePath(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	root := r.URL.Query().Get("root")
	segs, err := splitPath(r.URL.Query().Get("path"))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !s.allowNode(r.Context(), p, tenantID, root, grants.ScopeWrite) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxInlineWrite+1))
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(body) > maxInlineWrite {
		httpError(w, http.StatusRequestEntityTooLarge, errors.New("body too large; use the chunked upload route"))
		return
	}

	// Resolve (and optionally create) the parent chain.
	parent := root
	makeParents := strings.EqualFold(r.Header.Get("X-Drive-Parents"), "create")
	for _, seg := range segs[:len(segs)-1] {
		next, ferr := s.childFolder(r.Context(), p, tenantID, parent, seg, makeParents)
		if ferr != nil {
			httpError(w, storeErrorStatus(ferr), ferr)
			return
		}
		parent = next
	}
	leaf := segs[len(segs)-1]

	// Existing leaf → conditional overwrite; absent → create (honouring
	// If-None-Match: * as create-if-absent).
	existing, rerr := s.resolvePath(r.Context(), tenantID, parent, []string{leaf})
	_, inmPresent, inmStar := parseIfMatch(r.Header.Get("If-None-Match"))
	switch {
	case rerr == nil:
		if inmPresent && inmStar {
			writeJSON(w, http.StatusPreconditionFailed, map[string]any{"error": "exists", "rev": existing.Rev})
			return
		}
		ifRev := int64(-1)
		if rev, present, star := parseIfMatch(r.Header.Get("If-Match")); present && !star {
			ifRev = rev
		}
		newRev, status, werr := s.writeNodeContent(r.Context(), p, tenantID, existing.ID, body, ifRev)
		if werr != nil {
			if status == http.StatusPreconditionFailed {
				writeStale(w, tenantID, existing.ID, s)
				return
			}
			httpError(w, status, werr)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(newRev, 10)))
		writeJSON(w, http.StatusOK, map[string]any{"id": existing.ID, "rev": newRev})
	case errors.Is(rerr, store.ErrNotFound):
		n, status, cerr := s.uploadFile(r.Context(), p, tenantID, parent, leaf, "", strings.NewReader(string(body)), false)
		if cerr != nil {
			httpError(w, status, cerr)
			return
		}
		w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(n.Rev, 10)))
		writeJSON(w, http.StatusCreated, nodeView(n))
	default:
		httpError(w, storeErrorStatus(rerr), rerr)
	}
}

// childFolder returns the id of the named folder under parent, creating it
// when create is set and it is absent. Reuses an existing folder.
func (s *Server) childFolder(ctx context.Context, p *Principal, tenantID, parent, name string, create bool) (string, error) {
	kids, err := s.Store.ListChildren(ctx, tenantID, parent)
	if err != nil {
		return "", err
	}
	for _, n := range kids {
		if n.Name == name {
			if n.Kind != store.NodeFolder {
				return "", store.ErrConflict
			}
			return n.ID, nil
		}
	}
	if !create {
		return "", store.ErrNotFound
	}
	n, _, err := s.createFolder(ctx, p, tenantID, parent, name)
	if err != nil {
		return "", err
	}
	return n.ID, nil
}

// ---- D7: grant lookup by binding key ------------------------------------

// handleGrantsMine — D7. GET /v1/grants/mine lets an app that holds only its
// sealed key rediscover every folder it was granted, so it need not persist
// a pointer to each grant. Authenticated by a self-assertion signed with the
// binding key, AND (on the attested data plane) by the enclave-os-verified
// peer app id matching the asserted app id — the same identity the grant
// enforcement already checks. This handler does its own auth, since the
// normal AppGrant path requires a persisted grant row.
func (s *Server) handleGrantsMine(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "AppGrant ") {
		httpError(w, http.StatusUnauthorized, errors.New("expected AppGrant self-assertion"))
		return
	}
	env, err := grants.ParseToken(strings.TrimSpace(strings.TrimPrefix(h, "AppGrant ")))
	if err != nil {
		httpError(w, http.StatusUnauthorized, err)
		return
	}
	if env.Aud != appGrantAudience {
		httpError(w, http.StatusUnauthorized, fmt.Errorf("audience %q != %q", env.Aud, appGrantAudience))
		return
	}
	appID := grants.NormaliseAppSubject(grants.SubjectApp + env.Sub)
	if appID == "" || env.PK == "" {
		httpError(w, http.StatusBadRequest, errors.New("self-assertion must carry an app-id sub and a pk"))
		return
	}
	// On an attested dial the verified peer must be the app it claims to be.
	// Off the attested path (no peer headers) the signed self-assertion
	// stands alone: it proves possession of the binding key, which is the
	// credential, and the returned grants are only those bound to that key.
	if strings.EqualFold(strings.TrimSpace(r.Header.Get(peerVerifiedHeader)), "true") {
		peer := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(r.Header.Get(peerAppIDHeader))), "-", "")
		if peer != appID {
			httpError(w, http.StatusForbidden, errors.New("attested caller is not the app it asserts"))
			return
		}
	}
	gs, err := s.Grants.ListForBindingKey(r.Context(), env.PK)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(gs))
	for _, g := range gs {
		// Only grants for the asserting app id (a key is bound to one app by
		// the creation rule, but check rather than assume).
		if grants.NormaliseAppSubject(g.Subject) != appID {
			continue
		}
		m := map[string]any{
			"id": g.ID, "tenant_id": g.TenantID, "node_id": g.NodeID,
			"scope": g.Scope, "meta": g.Meta,
		}
		if g.ExpiresAt != nil {
			m["expires_unix"] = g.ExpiresAt.Unix()
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"grants": out})
}

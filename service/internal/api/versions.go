package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/store"
)

// File history.
//
// A replacement keeps what it replaced: the previous content stays where it
// was written and gains a row addressing it, while the new content goes to
// an id of its own. Appends are not replacements and record nothing, since
// they extend the same manifest in place (a transcript would otherwise gain
// a revision per turn).
//
// Retention bounds the cost, and eviction deletes both the row and the
// sealed blobs it addressed. Nothing is left unreferenced: that was the
// behaviour of the old overwrite path, where replaced chunks stayed in the
// bucket forever with no way to find or reclaim them.

const (
	// versionsKept is how many superseded revisions of a file survive.
	versionsKept = 10
	// versionsMaxAge is how long a superseded revision survives.
	versionsMaxAge = 30 * 24 * time.Hour
)

// contentObjectID is the id a node's current content is stored under.
// Content written before versioning has no reference recorded and lives
// under the node id itself.
func contentObjectID(n *store.Node) string {
	return manifest.ObjectID(n.ManifestRef, n.ID)
}

// recordContentVersion records a completed replacement: the content prev
// held before it (once, the first time that content is superseded) and the
// content the node holds now. Then it applies retention, deleting evicted
// revisions' blobs.
//
// Best effort throughout: the write it describes has already succeeded and
// been acknowledged, so a failure to keep history must not fail the write.
// A row without its blobs would be worse than no row, hence rows are
// removed before their bytes.
func (s *Server) recordContentVersion(
	ctx context.Context,
	bk objectstore.Backend,
	dek []byte,
	tenantID string,
	prev *store.Node,
	newObjectID, newManifestRef string,
	newMerkleRoot, newWrappedCEK []byte,
	newSize, newRev int64,
	actor string,
) {
	if prev != nil && prev.WrappedCEK != nil && prev.Rev < newRev {
		// The actor of content written before this ran is not recorded
		// anywhere a version row can reach, so it stays empty.
		_ = s.Store.InsertFileVersion(ctx, &store.FileVersion{
			TenantID: tenantID, NodeID: prev.ID, Rev: prev.Rev,
			ObjectID: contentObjectID(prev), ManifestRef: prev.ManifestRef,
			WrappedCEK: prev.WrappedCEK, MerkleRoot: prev.MerkleRoot,
			PlainSize: prev.PlainSize, MimeHint: prev.MimeHint,
		})
	}
	if prev != nil {
		_ = s.Store.InsertFileVersion(ctx, &store.FileVersion{
			TenantID: tenantID, NodeID: prev.ID, Rev: newRev,
			ObjectID: newObjectID, ManifestRef: newManifestRef,
			WrappedCEK: newWrappedCEK, MerkleRoot: newMerkleRoot,
			PlainSize: newSize, MimeHint: prev.MimeHint, Actor: actor,
		})
		s.retainVersions(ctx, bk, dek, tenantID, prev.ID, newRev)
	}
}

// retainVersions applies the retention policy to one file and reclaims the
// bytes of everything it drops.
func (s *Server) retainVersions(ctx context.Context, bk objectstore.Backend, dek []byte, tenantID, nodeID string, liveRev int64) {
	doomed, err := s.Store.EvictFileVersions(ctx, tenantID, nodeID, liveRev,
		versionsKept, time.Now().UTC().Add(-versionsMaxAge))
	if err != nil && len(doomed) == 0 {
		return
	}
	for _, v := range doomed {
		if v.ObjectID == "" || v.ObjectID == nodeID {
			// Content that predates versioning shares the node's own id;
			// deleting it would take the live file with it.
			continue
		}
		_ = manifest.Delete(ctx, bk, dek, tenantID, v.ObjectID, v.WrappedCEK)
	}
}

// deleteVersionBlobs reclaims every retained revision of a file. Called
// when the file itself goes, so history does not outlive its node.
func (s *Server) deleteVersionBlobs(ctx context.Context, bk objectstore.Backend, dek []byte, tenantID, nodeID, liveObjectID string) {
	versions, err := s.Store.ListFileVersions(ctx, tenantID, nodeID, 0)
	if err != nil {
		return
	}
	for _, v := range versions {
		if v.ObjectID == "" || v.ObjectID == liveObjectID {
			continue // the live content, reclaimed by the caller
		}
		_ = manifest.Delete(ctx, bk, dek, tenantID, v.ObjectID, v.WrappedCEK)
	}
}

// --- API ---------------------------------------------------------------

type versionJSON struct {
	Rev       int64  `json:"rev"`
	SizeBytes int64  `json:"size_bytes"`
	MimeHint  string `json:"mime_hint,omitempty"`
	Actor     string `json:"actor,omitempty"`
	CreatedAt string `json:"created_at"`
	// Current marks the revision the file is at now; the rest are history.
	Current bool `json:"current,omitempty"`
}

// handleListVersions returns a file's retained revisions, newest first.
func (s *Server) handleListVersions(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !s.allowNodeRead(r.Context(), p, tenantID, nodeID) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	n, err := s.Store.GetNode(r.Context(), tenantID, nodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	versions, err := s.Store.ListFileVersions(r.Context(), tenantID, nodeID, 0)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]versionJSON, 0, len(versions))
	for _, v := range versions {
		out = append(out, versionJSON{
			Rev: v.Rev, SizeBytes: v.PlainSize, MimeHint: v.MimeHint, Actor: v.Actor,
			CreatedAt: v.CreatedAt.UTC().Format(time.RFC3339), Current: v.Rev == n.Rev,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "rev": n.Rev, "versions": out})
}

// handleReadVersion streams the bytes a file held at one revision.
func (s *Server) handleReadVersion(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	rev, err := strconv.ParseInt(r.PathValue("rev"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.New("bad revision"))
		return
	}
	n, bk, dek, status, err := s.fileReadCtx(r.Context(), p, tenantID, nodeID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	objectID, wrapped, verr := s.revisionSource(r.Context(), tenantID, n, rev)
	if verr != nil {
		writeStoreError(w, verr)
		return
	}
	_, rc, err := manifest.Read(r.Context(), bk, dek, tenantID, objectID, wrapped)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	defer rc.Close()
	if n.MimeHint != "" {
		w.Header().Set("Content-Type", n.MimeHint)
	}
	w.Header().Set("ETag", strconv.FormatInt(rev, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// handleRestoreVersion makes an older revision current by writing it back
// as a new one, so history stays linear and the restore is itself undoable.
func (s *Server) handleRestoreVersion(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	rev, err := strconv.ParseInt(r.PathValue("rev"), 10, 64)
	if err != nil {
		httpError(w, http.StatusBadRequest, errors.New("bad revision"))
		return
	}
	if !s.allowNode(r.Context(), p, tenantID, nodeID, grants.ScopeWrite) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	n, bk, dek, status, err := s.fileReadCtx(r.Context(), p, tenantID, nodeID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	if rev == n.Rev {
		writeJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "rev": n.Rev, "restored": false})
		return
	}
	v, err := s.Store.GetFileVersion(r.Context(), tenantID, nodeID, rev)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if v.PlainSize > maxInlineWrite {
		httpError(w, http.StatusRequestEntityTooLarge,
			errors.New("this revision is too large to restore in one request"))
		return
	}
	_, rc, err := manifest.Read(r.Context(), bk, dek, tenantID, v.ObjectID, v.WrappedCEK)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	content, rerr := io.ReadAll(io.LimitReader(rc, maxInlineWrite+1))
	rc.Close()
	if rerr != nil {
		httpError(w, http.StatusInternalServerError, rerr)
		return
	}
	// Restoring is an ordinary replacement, so it inherits the quota check,
	// the per-node lock, the revision fence, re-indexing and versioning.
	newRev, status, err := s.writeNodeContent(r.Context(), p, tenantID, nodeID, content, -1)
	if err != nil {
		httpError(w, status, err)
		return
	}
	w.Header().Set("ETag", strconv.FormatInt(newRev, 10))
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id": nodeID, "rev": newRev, "restored_from": rev, "restored": true,
	})
}

package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/Privasys/drive/service/internal/diff"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// Comparing two revisions of a file.
//
// Both revisions are decryptable here and nowhere else, so the comparison
// happens inside the enclave and only the result leaves. Text only: a diff
// of two binaries tells a reader nothing, and the pair would have to be
// held in memory to produce it.

// maxDiffBytes caps either side of a comparison. An editor's document is
// orders of magnitude smaller; past this a line diff is not what anyone is
// looking at.
const maxDiffBytes = 2 << 20

// revisionSource resolves where a revision's bytes live. The live revision
// is not history: it is read from the node itself, so a file written
// before versioning still answers for its current content.
func (s *Server) revisionSource(ctx context.Context, tenantID string, n *store.Node, rev int64) (objectID string, wrapped []byte, err error) {
	if rev == n.Rev {
		return contentObjectID(n), n.WrappedCEK, nil
	}
	v, err := s.Store.GetFileVersion(ctx, tenantID, n.ID, rev)
	if err != nil {
		return "", nil, err
	}
	return v.ObjectID, v.WrappedCEK, nil
}

// readRevisionBytes loads one revision in full, refusing anything too big
// to compare.
func (s *Server) readRevisionBytes(ctx context.Context, bk objectstore.Backend, dek []byte, tenantID string, n *store.Node, rev int64) ([]byte, int, error) {
	objectID, wrapped, err := s.revisionSource(ctx, tenantID, n, rev)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	_, rc, err := manifest.Read(ctx, bk, dek, tenantID, objectID, wrapped)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	defer rc.Close()
	body, err := io.ReadAll(io.LimitReader(rc, maxDiffBytes+1))
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if len(body) > maxDiffBytes {
		return nil, http.StatusRequestEntityTooLarge,
			errors.New("this revision is too large to compare")
	}
	return body, http.StatusOK, nil
}

// handleDiffVersions compares two revisions of a text file. Both bounds
// default usefully: `to` to the file as it stands, `from` to the revision
// before that, so asking for a file's diff with no arguments answers "what
// changed in the last save".
func (s *Server) handleDiffVersions(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	n, bk, dek, status, err := s.fileReadCtx(r.Context(), p, tenantID, nodeID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	if search.Classify(n.Name, n.MimeHint) != search.Indexable {
		httpError(w, http.StatusUnsupportedMediaType,
			errors.New("only text files can be compared line by line"))
		return
	}
	q := r.URL.Query()
	toRev := n.Rev
	if raw := q.Get("to"); raw != "" {
		if toRev, err = strconv.ParseInt(raw, 10, 64); err != nil {
			httpError(w, http.StatusBadRequest, errors.New("bad 'to' revision"))
			return
		}
	}
	fromRev := int64(-1)
	if raw := q.Get("from"); raw != "" {
		if fromRev, err = strconv.ParseInt(raw, 10, 64); err != nil {
			httpError(w, http.StatusBadRequest, errors.New("bad 'from' revision"))
			return
		}
	} else {
		// The revision before `to`: what the last save changed.
		versions, lerr := s.Store.ListFileVersions(r.Context(), tenantID, nodeID, 0)
		if lerr != nil {
			httpError(w, http.StatusInternalServerError, lerr)
			return
		}
		for _, v := range versions {
			if v.Rev < toRev {
				fromRev = v.Rev
				break // newest first, so the first one below `to` is it
			}
		}
		if fromRev < 0 {
			httpError(w, http.StatusNotFound, errors.New("this file has no earlier revision to compare"))
			return
		}
	}
	oldBytes, status, err := s.readRevisionBytes(r.Context(), bk, dek, tenantID, n, fromRev)
	if err != nil {
		httpError(w, status, err)
		return
	}
	newBytes, status, err := s.readRevisionBytes(r.Context(), bk, dek, tenantID, n, toRev)
	if err != nil {
		httpError(w, status, err)
		return
	}
	context := diff.DefaultContext
	if raw := q.Get("context"); raw != "" {
		if c, cerr := strconv.Atoi(raw); cerr == nil && c >= 0 && c <= 100 {
			context = c
		}
	}
	res := diff.Unified(string(oldBytes), string(newBytes), context)
	// An empty result is an empty list, never null: a nil slice marshals as
	// null, and a client that iterates the field without guarding would
	// fail on exactly the case where nothing changed.
	hunks := res.Hunks
	if hunks == nil {
		hunks = []diff.Hunk{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":   nodeID,
		"from_rev":  fromRev,
		"to_rev":    toRev,
		"identical": res.Identical,
		"truncated": res.Truncated,
		"hunks":     hunks,
	})
}

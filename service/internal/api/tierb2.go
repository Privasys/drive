package api

// Tier B, second increment: append-only writes (D3) and the subtree change
// feed with long-poll (D5). See plans/drive-as-remote-disk.md.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/store"
)

// appendNodeContent appends bytes to a file node under the same per-node
// critical section as a replace: rev is checked before storage is touched,
// the quota is enforced on the delta, only the appended bytes are sealed as
// new chunks, and the row update re-checks the rev. Returns the new rev and
// size.
func (s *Server) appendNodeContent(ctx context.Context, p *Principal, tenantID, nodeID string, content []byte, ifRev int64) (int64, int64, int, error) {
	if !s.allowNode(ctx, p, tenantID, nodeID, grants.ScopeWrite) {
		return 0, 0, http.StatusForbidden, errors.New("forbidden")
	}
	muAny, _ := s.nodeWriteMu.LoadOrStore(tenantID+"/"+nodeID, &sync.Mutex{})
	mu := muAny.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	n, err := s.Store.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return 0, 0, storeErrorStatus(err), err
	}
	if n.Kind != store.NodeFile {
		return 0, 0, http.StatusBadRequest, errors.New("not a file")
	}
	if ifRev >= 0 && n.Rev != ifRev {
		return 0, 0, http.StatusPreconditionFailed, store.ErrStale
	}
	if limit := s.quotaLimit(); limit > 0 {
		used, uerr := s.Store.TenantUsageBytes(ctx, tenantID)
		if uerr != nil {
			return 0, 0, http.StatusInternalServerError, uerr
		}
		if used+int64(len(content)) > limit {
			return 0, 0, http.StatusRequestEntityTooLarge,
				fmt.Errorf("append would exceed the tenant storage quota (%d bytes)", limit)
		}
	}
	mek, err := s.tenantMEK(ctx, tenantID)
	if err != nil {
		return 0, 0, http.StatusBadGateway, err
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		return 0, 0, http.StatusInternalServerError, err
	}
	bk, err := s.backendFor(ctx, tenantID)
	if err != nil {
		return 0, 0, http.StatusBadGateway, err
	}
	wr, err := manifest.Append(ctx, bk, dek, tenantID, n.ID, n.WrappedCEK, bytes.NewReader(content))
	if err != nil {
		return 0, 0, http.StatusInternalServerError, err
	}
	root, _ := hex.DecodeString(wr.Manifest.MerkleRoot)
	newRev, err := s.Store.UpdateNodeContentCond(ctx, tenantID, n.ID, wr.WrappedCEK, root, wr.ManifestKey, wr.Manifest.PlainSize, p.Sub, ifRev)
	if err != nil {
		if errors.Is(err, store.ErrStale) {
			return 0, 0, http.StatusPreconditionFailed, err
		}
		return 0, 0, storeErrorStatus(err), err
	}
	s.scheduleIndexingChecked(ctx, n)
	return newRev, wr.Manifest.PlainSize, http.StatusOK, nil
}

// handleAppendContent — D3. POST /v1/tenants/{t}/nodes/{id}/append with a
// raw body appends to a file; If-Match as D1. Returns {rev, size}.
func (s *Server) handleAppendContent(w http.ResponseWriter, r *http.Request, p *Principal) {
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
		httpError(w, http.StatusRequestEntityTooLarge, errors.New("body too large"))
		return
	}
	if len(body) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("empty append"))
		return
	}
	newRev, size, status, err := s.appendNodeContent(r.Context(), p, tenantID, nodeID, body, ifRev)
	if err != nil {
		if status == http.StatusPreconditionFailed {
			writeStale(w, tenantID, nodeID, s)
			return
		}
		httpError(w, status, err)
		return
	}
	w.Header().Set("ETag", strconv.Quote(strconv.FormatInt(newRev, 10)))
	writeJSON(w, http.StatusOK, map[string]any{"rev": newRev, "size": size})
}

// ---- D5: subtree change feed with long-poll ------------------------------

type changeJSON struct {
	Seq      int64  `json:"seq"`
	NodeID   string `json:"node_id"`
	Op       string `json:"op"`
	Actor    string `json:"actor"`
	At       string `json:"at"`
	ParentID string `json:"parent_id,omitempty"`
	Name     string `json:"name,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Rev      int64  `json:"rev"`
}

// listChangesFiltered returns changes after since, optionally confined to
// the subtree under root: a live node by ancestry; a deleted node by the
// parent recorded on its change row (the node itself is gone).
func (s *Server) listChangesFiltered(ctx context.Context, p *Principal, tenantID string, since int64, limit int, root string) ([]changeJSON, int, error) {
	if !p.IsUser() && root == "" {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	if root != "" {
		if !s.allowNode(ctx, p, tenantID, root, grants.ScopeRead) {
			return nil, http.StatusForbidden, errors.New("forbidden")
		}
	} else if !s.canRead(ctx, tenantID, p.Sub) {
		return nil, http.StatusForbidden, errors.New("forbidden")
	}
	rows, err := s.Store.ListChanges(ctx, tenantID, since, limit)
	if err != nil {
		return nil, storeErrorStatus(err), err
	}
	out := make([]changeJSON, 0, len(rows))
	for _, c := range rows {
		if root != "" {
			in := false
			if c.Op == "delete" {
				if c.ParentID != "" {
					in, _ = s.Store.IsDescendantOrSelf(ctx, tenantID, root, c.ParentID)
				}
			} else {
				in, _ = s.Store.IsDescendantOrSelf(ctx, tenantID, root, c.NodeID)
			}
			if !in {
				continue
			}
		}
		out = append(out, changeJSON{
			Seq: c.Seq, NodeID: c.NodeID, Op: c.Op, Actor: c.Actor,
			At: c.At.UTC().Format(time.RFC3339), ParentID: c.ParentID,
			Name: c.Name, Kind: c.Kind, Rev: c.Rev,
		})
	}
	return out, http.StatusOK, nil
}

// handleChangesV2 — D5. GET /v1/tenants/{t}/changes?since=&limit=&root=&wait=
// Holds the request up to wait seconds (cap 60) for the first matching
// change so a cache can subscribe to one folder without hammering.
func (s *Server) handleChangesV2(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	q := r.URL.Query()
	since, _ := strconv.ParseInt(q.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	root := strings.TrimSpace(q.Get("root"))
	wait, _ := strconv.Atoi(q.Get("wait"))
	if wait > 60 {
		wait = 60
	}
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		rows, status, err := s.listChangesFiltered(r.Context(), p, tenantID, since, limit, root)
		if err != nil {
			httpError(w, status, err)
			return
		}
		if len(rows) > 0 || wait <= 0 || time.Now().After(deadline) {
			writeJSON(w, http.StatusOK, rows)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(time.Second):
		}
	}
}

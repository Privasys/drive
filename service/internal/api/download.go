package api

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/export"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Downloading a selection: one file streams as itself through
// handleDownloadFile, but a folder, or several items at once, has to
// arrive as an archive. The browser cannot build one (it has no zip of
// its own and would hold every byte in memory), so the enclave does it:
// it already holds the keys, and the plaintext it decrypts on the way
// through is exactly what the caller is authorised to read.

// maxDownloadRoots bounds one request; a whole-drive download is what the
// export tool is for.
const maxDownloadRoots = 500

type downloadZipRequest struct {
	NodeIDs []string `json:"node_ids"`
	// Name is the archive's filename, sanitised; defaults to the single
	// selected item's name, else "drive-download".
	Name string `json:"name,omitempty"`
}

func (s *Server) handleDownloadZip(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	var req downloadZipRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.NodeIDs) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("node_ids required"))
		return
	}
	if len(req.NodeIDs) > maxDownloadRoots {
		httpError(w, http.StatusBadRequest,
			fmt.Errorf("select at most %d items to download at once", maxDownloadRoots))
		return
	}
	// Authorise every root the caller named. A folder's subtree inherits
	// the verdict, the same pre-flight the workspace export makes.
	roots := make([]*store.Node, 0, len(req.NodeIDs))
	for _, id := range req.NodeIDs {
		n, err := s.Store.GetNode(r.Context(), tenantID, id)
		if err != nil {
			writeStoreError(w, err)
			return
		}
		if !s.allowNode(r.Context(), p, tenantID, id, grants.ScopeRead) {
			httpError(w, http.StatusForbidden, errors.New("forbidden"))
			return
		}
		roots = append(roots, n)
	}
	mek, err := s.tenantMEK(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	dek, err := crypto.DeriveDEK(mek, tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	bk, err := s.backendFor(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusBadGateway, err)
		return
	}
	name := req.Name
	if name == "" && len(roots) == 1 {
		name = roots[0].Name
	}
	if name == "" {
		name = "drive-download"
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="%s.zip"`, sanitiseFilename(name)))
	w.WriteHeader(http.StatusOK)
	if err := export.WriteSubtreeZip(r.Context(), s.Store, bk, dek, tenantID, roots, w); err != nil {
		// Headers are already out; the truncated archive is the signal.
		return
	}
}

package api

// The Drive side of the user model in plans/drive-as-remote-disk.md:
//
//   - the storage gauge's by-folder breakdown (GET /v1/tenants/{t}/quota
//     gains `breakdown` and `apps`);
//   - "apps with access": the app grants on a tenant, with the folder each
//     one reaches and what the app is called (GET /v1/tenants/{t}/apps);
//     revocation is the existing DELETE /v1/tenants/{t}/grants/{id};
//   - workspace snapshots: a folder holding `.workspace.json` beside a
//     `.blobs/` folder is one item to the user. Listings flag it, and
//     GET /v1/tenants/{t}/nodes/{id}/workspace.zip rebuilds the working tree
//     from the manifest as a ZIP (Export).
//
// Workspace manifest contract (Drive owns it; the runtime writes it):
//
//	{
//	  "version": 1,
//	  "app": "<app id, 32 hex>",
//	  "saved_at": "<RFC3339>",
//	  "files": [ {"path": "src/main.go", "size": 1234, "mode": "0644",
//	              "blob": "<sha256 hex of the plaintext>"} ]
//	}
//
// Every blob is a file named `<sha256 hex>` inside the folder's `.blobs/`
// child. Paths are relative, forward-slash, no `..` segments. The folder is
// expected to be excluded from indexing (PUT .../indexing {"no_index": true}).

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/store"
)

const (
	workspaceBlobsFolder = ".blobs"
	appDataFolderName    = "AppData"
	maxWorkspaceManifest = 32 << 20 // a manifest larger than this is not a snapshot, it is a mistake
)

// WorkspaceFile is one entry of a workspace manifest.
type WorkspaceFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
	Mode string `json:"mode,omitempty"`
	Blob string `json:"blob"`
}

// WorkspaceManifest is the snapshot description the runtime writes.
type WorkspaceManifest struct {
	Version int             `json:"version"`
	App     string          `json:"app,omitempty"`
	SavedAt string          `json:"saved_at,omitempty"`
	Files   []WorkspaceFile `json:"files"`
}

// usageEntry is one line of the storage breakdown.
type usageEntry struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Bytes  int64  `json:"bytes"`
}

// quotaBreakdown returns the tenant's top-level breakdown and, when an
// AppData folder exists, the per-app breakdown under it. Best effort: a
// failure leaves the gauge without its detail rather than without a total.
func (s *Server) quotaBreakdown(ctx context.Context, tenantID string) (top []usageEntry, apps []usageEntry) {
	roots, err := s.Store.ListRootChildren(ctx, tenantID)
	if err != nil {
		return nil, nil
	}
	byRoot, err := s.Store.UsageByChildren(ctx, tenantID, "")
	if err != nil {
		return nil, nil
	}
	var appData *store.Node
	for _, n := range roots {
		top = append(top, usageEntry{NodeID: n.ID, Name: n.Name, Kind: string(n.Kind), Bytes: byRoot[n.ID]})
		if n.Kind == store.NodeFolder && n.Name == appDataFolderName {
			appData = n
		}
	}
	sort.SliceStable(top, func(i, j int) bool { return top[i].Bytes > top[j].Bytes })
	if appData != nil {
		kids, err := s.Store.ListChildren(ctx, tenantID, appData.ID)
		if err == nil {
			byApp, err := s.Store.UsageByChildren(ctx, tenantID, appData.ID)
			if err == nil {
				for _, n := range kids {
					apps = append(apps, usageEntry{NodeID: n.ID, Name: n.Name, Kind: string(n.Kind), Bytes: byApp[n.ID]})
				}
				sort.SliceStable(apps, func(i, j int) bool { return apps[i].Bytes > apps[j].Bytes })
			}
		}
	}
	return top, apps
}

// appAccessEntry is one row of "apps with access".
type appAccessEntry struct {
	GrantID   string   `json:"grant_id"`
	AppID     string   `json:"app_id"`
	AppName   string   `json:"app_name,omitempty"`
	NodeID    string   `json:"node_id"`
	Folder    string   `json:"folder"`
	Scope     []string `json:"scope"`
	CreatedAt string   `json:"created_at"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Via       string   `json:"via,omitempty"`
}

// handleListApps serves GET /v1/tenants/{tenantID}/apps: every active app
// grant in the tenant, resolved to a folder path and an app name. Owners
// and anyone who may share (the same right revocation needs) can read it.
func (s *Server) handleListApps(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	gs, err := s.Grants.ListAppGrantsForTenant(r.Context(), tenantID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	mgmt := ""
	if cfg := s.CurrentConfig(); cfg != nil {
		mgmt = cfg.MgmtBaseURL
	}
	names := map[string]string{}
	out := make([]appAccessEntry, 0, len(gs))
	for _, g := range gs {
		var meta struct {
			AppID  string `json:"app_id"`
			Folder string `json:"folder"`
			Via    string `json:"via"`
		}
		_ = json.Unmarshal([]byte(g.Meta), &meta)
		appID := meta.AppID
		if appID == "" {
			appID = grants.NormaliseAppSubject(g.Subject)
		}
		folder := meta.Folder
		if folder == "" && g.NodeID != "" {
			folder = s.nodePath(r.Context(), tenantID, g.NodeID)
		}
		name := ""
		if len(appID) == 32 {
			if n, ok := names[appID]; ok {
				name = n
			} else if mgmt != "" {
				name = resolveAppDisplayName(r.Context(), mgmt, appID)
				names[appID] = name
			}
		}
		e := appAccessEntry{
			GrantID:   g.ID,
			AppID:     appID,
			AppName:   name,
			NodeID:    g.NodeID,
			Folder:    folder,
			Scope:     scopeStrings(g.Scope),
			CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339),
			Via:       meta.Via,
		}
		if g.ExpiresAt != nil {
			e.ExpiresAt = g.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": out})
}

// nodePath returns the slash-joined path of a node from the tenant root
// ("" when the node is unknown).
func (s *Server) nodePath(ctx context.Context, tenantID, nodeID string) string {
	var parts []string
	id := nodeID
	for i := 0; i < 64 && id != ""; i++ {
		n, err := s.Store.GetNode(ctx, tenantID, id)
		if err != nil {
			return ""
		}
		parts = append([]string{n.Name}, parts...)
		if !n.ParentID.Valid {
			break
		}
		id = n.ParentID.String
	}
	return strings.Join(parts, "/")
}

// annotateWorkspaces marks the folders in a listing that hold a workspace
// manifest so the front renders them as one item. One query per listing.
func (s *Server) annotateWorkspaces(ctx context.Context, tenantID string, out []nodeJSON) {
	var folders []string
	for i := range out {
		if out[i].Kind == string(store.NodeFolder) {
			folders = append(folders, out[i].ID)
		}
	}
	if len(folders) == 0 {
		return
	}
	marks, err := s.Store.WorkspaceManifestIDs(ctx, tenantID, folders)
	if err != nil {
		return
	}
	for i := range out {
		if id, ok := marks[out[i].ID]; ok {
			out[i].WorkspaceManifestID = id
		}
	}
}

// readWorkspaceManifest opens a folder's manifest and parses it.
func (s *Server) readWorkspaceManifest(ctx context.Context, p *Principal, tenantID, folderID string) (*WorkspaceManifest, *store.Node, int, error) {
	if !s.allowNode(ctx, p, tenantID, folderID, grants.ScopeRead) {
		return nil, nil, http.StatusForbidden, errors.New("forbidden")
	}
	folder, err := s.Store.GetNode(ctx, tenantID, folderID)
	if err != nil {
		return nil, nil, storeErrorStatus(err), err
	}
	if folder.Kind != store.NodeFolder {
		return nil, nil, http.StatusBadRequest, errors.New("not a folder")
	}
	mf, err := s.Store.ChildByName(ctx, tenantID, folderID, store.WorkspaceManifestName)
	if err != nil {
		return nil, nil, http.StatusNotFound, errors.New("folder holds no workspace manifest")
	}
	if mf.PlainSize > maxWorkspaceManifest {
		return nil, nil, http.StatusRequestEntityTooLarge, errors.New("workspace manifest too large")
	}
	_, bk, dek, status, err := s.fileReadCtx(ctx, p, tenantID, mf.ID)
	if err != nil {
		return nil, nil, status, err
	}
	_, rc, err := manifest.Read(ctx, bk, dek, tenantID, mf.ID, mf.WrappedCEK)
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	defer rc.Close()
	raw, err := io.ReadAll(io.LimitReader(rc, maxWorkspaceManifest+1))
	if err != nil {
		return nil, nil, http.StatusInternalServerError, err
	}
	var m WorkspaceManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, http.StatusUnprocessableEntity, fmt.Errorf("workspace manifest: %w", err)
	}
	return &m, folder, http.StatusOK, nil
}

// cleanWorkspacePath rejects absolute paths and parent escapes; the ZIP must
// unpack where the user expects it to.
func cleanWorkspacePath(p string) (string, bool) {
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.TrimPrefix(p, "./")
	if p == "" || strings.HasPrefix(p, "/") {
		return "", false
	}
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || strings.Contains(c, "/../") {
		return "", false
	}
	return c, true
}

// handleWorkspaceZip serves GET /v1/tenants/{tenantID}/nodes/{nodeID}/workspace.zip:
// the working tree rebuilt from the manifest, blob by blob, streamed as a
// ZIP. Blobs are decrypted inside the enclave like any file read; a blob the
// manifest names but the folder lacks is reported and skipped rather than
// failing the whole export half way through.
func (s *Server) handleWorkspaceZip(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	folderID := r.PathValue("nodeID")
	m, folder, status, err := s.readWorkspaceManifest(r.Context(), p, tenantID, folderID)
	if err != nil {
		httpError(w, status, err)
		return
	}
	blobs, err := s.Store.ChildByName(r.Context(), tenantID, folderID, workspaceBlobsFolder)
	if err != nil {
		httpError(w, http.StatusNotFound, errors.New("workspace has no .blobs folder"))
		return
	}
	// Pre-flight the auth once for the blobs folder; every blob inherits it.
	if !s.allowNode(r.Context(), p, tenantID, blobs.ID, grants.ScopeRead) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, sanitiseFilename(folder.Name)))
	w.WriteHeader(http.StatusOK)
	zw := zip.NewWriter(w)
	defer zw.Close()
	files := append([]WorkspaceFile(nil), m.Files...)
	sort.SliceStable(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	seen := map[string]bool{}
	missing := []string{}
	for _, f := range files {
		rel, ok := cleanWorkspacePath(f.Path)
		if !ok || seen[rel] {
			continue
		}
		seen[rel] = true
		blob, err := s.Store.ChildByName(r.Context(), tenantID, blobs.ID, strings.ToLower(f.Blob))
		if err != nil || blob.Kind != store.NodeFile {
			missing = append(missing, rel)
			continue
		}
		n, bk, dek, _, err := s.fileReadCtx(r.Context(), p, tenantID, blob.ID)
		if err != nil {
			missing = append(missing, rel)
			continue
		}
		hdr := &zip.FileHeader{Name: rel, Method: zip.Deflate, Modified: n.UpdatedAt}
		if f.Mode != "" {
			var mode uint32
			if _, perr := fmt.Sscanf(f.Mode, "%o", &mode); perr == nil {
				hdr.SetMode(fsMode(mode))
			}
		}
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return // headers already sent; the stream is what it is
		}
		_, rc, err := manifest.Read(r.Context(), bk, dek, tenantID, blob.ID, n.WrappedCEK)
		if err != nil {
			missing = append(missing, rel)
			continue
		}
		_, cerr := io.Copy(fw, rc)
		rc.Close()
		if cerr != nil {
			return
		}
	}
	if len(missing) > 0 {
		if fw, err := zw.Create("WORKSPACE-MISSING-BLOBS.txt"); err == nil {
			_, _ = io.WriteString(fw, "The snapshot names these files but their blobs were not found:\n"+strings.Join(missing, "\n")+"\n")
		}
	}
}

func sanitiseFilename(name string) string {
	r := strings.NewReplacer(`"`, "", "/", "-", "\\", "-", "\n", "", "\r", "")
	out := strings.TrimSpace(r.Replace(name))
	if out == "" {
		return "workspace"
	}
	return out
}

// fsMode converts a POSIX permission bit pattern (e.g. 0755) into an
// os.FileMode for the ZIP header.
func fsMode(perm uint32) os.FileMode { return os.FileMode(perm & 0o777) }

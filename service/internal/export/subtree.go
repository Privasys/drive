package export

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/store"
)

// WriteSubtreeZip streams a ZIP of the given nodes: a file goes in under
// its own name, a folder under its name with everything beneath it. This
// is what a browser cannot do for itself, since it can save a file but
// not lay out a folder tree, so the enclave assembles the archive from
// plaintext it decrypts in memory and streams out.
//
// Unlike WriteZip this is a plain archive of what the user picked: no
// manifest.json, no "files/" prefix, no ciphertext mode. Roots come from
// one listing, so their names are already unique; a name that repeats
// anyway is suffixed rather than silently overwritten inside the ZIP.
func WriteSubtreeZip(
	ctx context.Context,
	st *store.Store,
	backend objectstore.Backend,
	dek []byte,
	tenantID string,
	roots []*store.Node,
	out io.Writer,
) error {
	zw := zip.NewWriter(out)
	taken := map[string]bool{}
	for _, root := range roots {
		base := uniqueZipName(taken, safeZipName(root.Name))
		switch root.Kind {
		case store.NodeFile:
			if err := writeZipFile(ctx, zw, backend, dek, tenantID, root, base); err != nil {
				return err
			}
		case store.NodeFolder:
			kids, err := walk(ctx, st, tenantID, root.ID, base)
			if err != nil {
				return err
			}
			sort.Slice(kids, func(i, j int) bool { return kids[i].FullPath < kids[j].FullPath })
			// An empty folder still belongs in the archive, so every folder
			// gets its directory entry whether or not it holds files.
			if _, err := zw.Create(base + "/"); err != nil {
				return err
			}
			for _, e := range kids {
				switch e.Node.Kind {
				case store.NodeFolder:
					if _, err := zw.Create(e.FullPath + "/"); err != nil {
						return err
					}
				case store.NodeFile:
					if err := writeZipFile(ctx, zw, backend, dek, tenantID, e.Node, e.FullPath); err != nil {
						return err
					}
				}
			}
		}
	}
	return zw.Close()
}

// writeZipFile decrypts one file into the archive at zipPath.
func writeZipFile(
	ctx context.Context,
	zw *zip.Writer,
	backend objectstore.Backend,
	dek []byte,
	tenantID string,
	n *store.Node,
	zipPath string,
) error {
	_, rc, err := manifest.Read(ctx, backend, dek, tenantID, n.ID, n.WrappedCEK)
	if err != nil {
		return fmt.Errorf("download: read %s: %w", zipPath, err)
	}
	defer rc.Close()
	w, err := zw.Create(zipPath)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, rc)
	return err
}

// safeZipName keeps a node name from escaping its place in the archive.
func safeZipName(name string) string {
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.TrimSpace(path.Base(name))
	if name == "" || name == "." || name == ".." {
		return "unnamed"
	}
	return name
}

// uniqueZipName suffixes a repeated top-level name ("report", "report (2)").
func uniqueZipName(taken map[string]bool, name string) string {
	if !taken[name] {
		taken[name] = true
		return name
	}
	stem, ext := name, ""
	if i := strings.LastIndex(name, "."); i > 0 {
		stem, ext = name[:i], name[i:]
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s (%d)%s", stem, i, ext)
		if !taken[candidate] {
			taken[candidate] = true
			return candidate
		}
	}
}

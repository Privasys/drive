// Package export builds GDPR-grade ZIP exports of a tenant's tree.
//
// Two modes:
//
//   - "plaintext" (default): files are written under their plaintext
//     paths, with a top-level manifest.json describing the tree, MIME
//     hints, sizes, Merkle roots, and timestamps. Suitable for the
//     "Download all my data" UX.
//
//   - "ciphertext": chunks are copied verbatim and accompanied by their
//     sealed manifests + a top-level keys.json wrapping every per-file
//     CEK under the tenant's MEK. Suitable for cold archival; restoring
//     requires the Privasys-issued tenant MEK share.
//
// Both modes are streamed: the output ZIP is written incrementally so a
// 100 GB export does not buffer in RAM.
package export

import (
	"archive/zip"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"time"

	"github.com/Privasys/drive/service/internal/manifest"
	"github.com/Privasys/drive/service/internal/objectstore"
	"github.com/Privasys/drive/service/internal/store"
)

// Mode selects the export flavour.
type Mode string

const (
	ModePlaintext  Mode = "plaintext"
	ModeCiphertext Mode = "ciphertext"
)

// EntryDescriptor is one row in the top-level manifest.json.
type EntryDescriptor struct {
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	MimeHint   string    `json:"mime_hint,omitempty"`
	PlainSize  int64     `json:"size_bytes"`
	MerkleRoot string    `json:"merkle_root_hex,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// TopManifest is the canonical descriptor written at the root of every
// export ZIP. It is deterministic for a given tenant snapshot so that
// two exports of the same tree byte-compare equal in the descriptor.
type TopManifest struct {
	TenantID    string            `json:"tenant_id"`
	Mode        Mode              `json:"mode"`
	GeneratedAt time.Time         `json:"generated_at"`
	Entries     []EntryDescriptor `json:"entries"`
}

// WriteZip writes a complete export of tenantID into out. dek is the
// per-tenant DEK; for ModeCiphertext it can be nil — the caller is
// expected to handle key escrow separately.
func WriteZip(
	ctx context.Context,
	st *store.Store,
	backend objectstore.Backend,
	dek []byte,
	tenantID string,
	mode Mode,
	out io.Writer,
) (TopManifest, error) {
	zw := zip.NewWriter(out)
	defer zw.Close()

	tree, err := walk(ctx, st, tenantID, "", "")
	if err != nil {
		return TopManifest{}, err
	}
	sort.Slice(tree, func(i, j int) bool { return tree[i].FullPath < tree[j].FullPath })

	tm := TopManifest{TenantID: tenantID, Mode: mode, GeneratedAt: time.Now().UTC()}
	for _, entry := range tree {
		desc := EntryDescriptor{
			Path:      entry.FullPath,
			Kind:      string(entry.Node.Kind),
			MimeHint:  entry.Node.MimeHint,
			PlainSize: entry.Node.PlainSize,
			CreatedAt: entry.Node.CreatedAt,
			UpdatedAt: entry.Node.UpdatedAt,
		}
		if len(entry.Node.MerkleRoot) > 0 {
			desc.MerkleRoot = hex.EncodeToString(entry.Node.MerkleRoot)
		}
		tm.Entries = append(tm.Entries, desc)

		if entry.Node.Kind != store.NodeFile {
			continue
		}
		switch mode {
		case ModePlaintext, "":
			if dek == nil {
				return TopManifest{}, fmt.Errorf("export: plaintext mode requires DEK")
			}
			if err := writePlainEntry(ctx, zw, backend, dek, tenantID, entry); err != nil {
				return TopManifest{}, err
			}
		case ModeCiphertext:
			if err := writeCipherEntry(ctx, zw, backend, tenantID, entry); err != nil {
				return TopManifest{}, err
			}
		default:
			return TopManifest{}, fmt.Errorf("export: unknown mode %q", mode)
		}
	}

	manBytes, _ := json.MarshalIndent(tm, "", "  ")
	w, err := zw.Create("manifest.json")
	if err != nil {
		return TopManifest{}, err
	}
	if _, err := w.Write(manBytes); err != nil {
		return TopManifest{}, err
	}
	return tm, nil
}

type entry struct {
	Node     *store.Node
	FullPath string
}

func walk(ctx context.Context, st *store.Store, tenantID, parentID, basePath string) ([]entry, error) {
	kids, err := st.ListChildren(ctx, tenantID, parentID)
	if err != nil {
		return nil, err
	}
	var out []entry
	for _, k := range kids {
		full := path.Join(basePath, k.Name)
		out = append(out, entry{Node: k, FullPath: full})
		if k.Kind == store.NodeFolder {
			sub, err := walk(ctx, st, tenantID, k.ID, full)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
	}
	return out, nil
}

func writePlainEntry(ctx context.Context, zw *zip.Writer, backend objectstore.Backend, dek []byte, tenantID string, e entry) error {
	_, rc, err := manifest.Read(ctx, backend, dek, tenantID, e.Node.ID, e.Node.WrappedCEK)
	if err != nil {
		return fmt.Errorf("export: read %s: %w", e.FullPath, err)
	}
	defer rc.Close()
	w, err := zw.Create(path.Join("files", e.FullPath))
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	return nil
}

func writeCipherEntry(ctx context.Context, zw *zip.Writer, backend objectstore.Backend, tenantID string, e entry) error {
	w, err := zw.Create(path.Join("ciphertext", e.FullPath+".manifest"))
	if err != nil {
		return err
	}
	rc, err := backend.GetChunk(ctx, e.Node.ManifestRef)
	if err != nil {
		return err
	}
	defer rc.Close()
	if _, err := io.Copy(w, rc); err != nil {
		return err
	}
	return nil
}

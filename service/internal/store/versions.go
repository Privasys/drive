package store

import (
	"context"
	"database/sql"
	"time"
)

// File version history.
//
// A version is a retained content pointer: the sealed manifest of what the
// file held at a given rev, plus the key to open it. The node row keeps
// pointing at the current one, so reads are unchanged; history is what the
// older rows address.
//
// Each version addresses its own manifest and its own chunks under a
// distinct object id, because the manifest key and the AEAD associated data
// are both derived from that id. Nothing is shared between versions: chunks
// are content-addressed over ciphertext sealed with a random per-chunk
// nonce, so two versions never collide on a chunk key even where their
// plaintext is identical. That costs storage, and buys the property that
// evicting a version can delete its chunks outright without a reference
// count and without any chance of tearing a version that is still live.

// FileVersion is one retained revision of a file's content.
type FileVersion struct {
	TenantID    string
	NodeID      string
	Rev         int64  // the node rev this content was committed at
	ObjectID    string // manifest + AAD id for this version's blobs
	ManifestRef string
	WrappedCEK  []byte
	MerkleRoot  []byte
	PlainSize   int64
	MimeHint    string
	Actor       string
	CreatedAt   time.Time
}

// InsertFileVersion records a version. Re-recording the same (node, rev) is
// a no-op rather than an error: a retried write must not fail here.
func (s *Store) InsertFileVersion(ctx context.Context, v *FileVersion) error {
	// The caller may date a version (retention is age-sensitive, and a test
	// or a backfill needs to say when content was really written).
	created := v.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO file_versions
		   (tenant_id, node_id, rev, object_id, manifest_ref, wrapped_cek,
		    merkle_root, plain_size, mime_hint, actor, created_at)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT (node_id, rev) DO NOTHING`),
		v.TenantID, v.NodeID, v.Rev, v.ObjectID, v.ManifestRef,
		nullableBytes(v.WrappedCEK), nullableBytes(v.MerkleRoot),
		v.PlainSize, v.MimeHint, v.Actor, created)
	return err
}

// ListFileVersions returns a file's versions, newest first. limit <= 0
// returns all of them.
func (s *Store) ListFileVersions(ctx context.Context, tenantID, nodeID string, limit int) ([]*FileVersion, error) {
	q := `SELECT tenant_id, node_id, rev, object_id, manifest_ref, wrapped_cek,
	             merkle_root, plain_size, mime_hint, actor, created_at
	      FROM file_versions WHERE tenant_id = ? AND node_id = ?
	      ORDER BY rev DESC`
	args := []any{tenantID, nodeID}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.DB.QueryContext(ctx, s.q(q), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanFileVersions(rows)
}

// GetFileVersion returns one version of a file.
func (s *Store) GetFileVersion(ctx context.Context, tenantID, nodeID string, rev int64) (*FileVersion, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT tenant_id, node_id, rev, object_id, manifest_ref, wrapped_cek,
		        merkle_root, plain_size, mime_hint, actor, created_at
		 FROM file_versions WHERE tenant_id = ? AND node_id = ? AND rev = ?`),
		tenantID, nodeID, rev)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanFileVersions(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out[0], nil
}

// EvictFileVersions applies a retention policy to one file and returns the
// rows it removed, so the caller can reclaim their sealed blobs.
//
// Versions at or above keepFromRev are never touched: that is the live
// content. Of the superseded ones, a version survives only while it is
// BOTH among the newest `keep` and no older than `before`. keep < 0 lifts
// the count limit; a zero `before` lifts the age limit.
//
// The rows are deleted here and the blobs reclaimed by the caller: a
// failure between the two leaves unreferenced bytes, which the sweep can
// find again, rather than a version row whose content has gone.
func (s *Store) EvictFileVersions(ctx context.Context, tenantID, nodeID string, keepFromRev int64, keep int, before time.Time) ([]*FileVersion, error) {
	all, err := s.ListFileVersions(ctx, tenantID, nodeID, 0)
	if err != nil {
		return nil, err
	}
	var doomed []*FileVersion
	seen := 0
	for _, v := range all {
		if v.Rev >= keepFromRev {
			continue // live content, never evicted
		}
		seen++
		withinCount := keep < 0 || seen <= keep
		withinAge := before.IsZero() || v.CreatedAt.After(before)
		if withinCount && withinAge {
			continue
		}
		doomed = append(doomed, v)
	}
	for _, v := range doomed {
		if _, err := s.DB.ExecContext(ctx, s.q(
			`DELETE FROM file_versions WHERE tenant_id = ? AND node_id = ? AND rev = ?`),
			tenantID, nodeID, v.Rev); err != nil {
			return doomed, err
		}
	}
	return doomed, nil
}

// DeleteFileVersion drops one version row.
func (s *Store) DeleteFileVersion(ctx context.Context, tenantID, nodeID string, rev int64) error {
	_, err := s.DB.ExecContext(ctx, s.q(
		`DELETE FROM file_versions WHERE tenant_id = ? AND node_id = ? AND rev = ?`),
		tenantID, nodeID, rev)
	return err
}

// FileVersionsBytes totals the plaintext held in a tenant's version
// history, excluding whatever the nodes themselves currently point at.
// Quota counts live bytes; this is what history costs on top.
func (s *Store) FileVersionsBytes(ctx context.Context, tenantID string) (int64, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT COALESCE(SUM(v.plain_size), 0)
		 FROM file_versions v JOIN nodes n ON n.id = v.node_id
		 WHERE v.tenant_id = ? AND v.rev <> n.rev`),
		tenantID)
	var total int64
	err := row.Scan(&total)
	return total, err
}

func scanFileVersions(rows *sql.Rows) ([]*FileVersion, error) {
	var out []*FileVersion
	for rows.Next() {
		var v FileVersion
		var cek, root []byte
		if err := rows.Scan(&v.TenantID, &v.NodeID, &v.Rev, &v.ObjectID, &v.ManifestRef,
			&cek, &root, &v.PlainSize, &v.MimeHint, &v.Actor, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.WrappedCEK, v.MerkleRoot = cek, root
		out = append(out, &v)
	}
	return out, rows.Err()
}

package store

import (
	"context"
	"time"
)

// Node expiry (attachment intent A, §8.7): session-scoped attachments
// auto-expire. Kept in a side table rather than a nodes column so the
// node scan sites stay untouched; the GC sweep deletes expired nodes and
// the cascade removes the expiry row (and the node's sections /
// embeddings / conversions). A node with no row never expires.

func (s *Store) migrateNodeExpiry(ctx context.Context) error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS node_expiry (
			node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
			tenant_id TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS node_expiry_due ON node_expiry(expires_at)`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// SetNodeExpiry marks a node to be GC'd at expiresAt (idempotent; a
// zero time clears any expiry, making the node permanent).
func (s *Store) SetNodeExpiry(ctx context.Context, tenantID, nodeID string, expiresAt time.Time) error {
	if expiresAt.IsZero() {
		_, err := s.DB.ExecContext(ctx, s.q(
			`DELETE FROM node_expiry WHERE tenant_id = ? AND node_id = ?`), tenantID, nodeID)
		return err
	}
	if s.Dialect == DialectPostgres {
		_, err := s.DB.ExecContext(ctx,
			`INSERT INTO node_expiry (node_id, tenant_id, expires_at) VALUES ($1,$2,$3)
			 ON CONFLICT(node_id) DO UPDATE SET expires_at = EXCLUDED.expires_at`,
			nodeID, tenantID, expiresAt.UTC())
		return err
	}
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO node_expiry (node_id, tenant_id, expires_at) VALUES (?,?,?)
		 ON CONFLICT(node_id) DO UPDATE SET expires_at = excluded.expires_at`,
		nodeID, tenantID, expiresAt.UTC())
	return err
}

// NodeExpiry returns the node's expiry time, or a zero time when it does
// not expire.
func (s *Store) NodeExpiry(ctx context.Context, tenantID, nodeID string) (time.Time, error) {
	var t time.Time
	err := s.DB.QueryRowContext(ctx, s.q(
		`SELECT expires_at FROM node_expiry WHERE tenant_id = ? AND node_id = ?`),
		tenantID, nodeID).Scan(&t)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return time.Time{}, nil
		}
		return time.Time{}, err
	}
	return t, nil
}

// SweepExpiredNodes deletes every node whose expiry has passed and
// returns how many were removed. Cascades clear the index rows and the
// expiry row. Files uploaded IN a conversation live under its files/
// folder; only the ones with an expiry (intent A) are swept.
func (s *Store) SweepExpiredNodes(ctx context.Context, now time.Time) (int, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT node_id FROM node_expiry WHERE expires_at <= ?`), now.UTC())
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if _, err := s.DB.ExecContext(ctx, s.q(`DELETE FROM nodes WHERE id = ?`), id); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

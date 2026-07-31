package store

// Assistant settings: per-tenant switches for the AI-scope surface that are
// not representable as grants. Today that is a single flag — whether the
// assistant may read (and be handed) the tenant's Memory/ folder. Memory
// used to be unconditionally always-scoped; the chat UI's Memory toggle
// therefore only gated its own client-side retrieval, and the in-enclave
// path could not honour "off" at all. This table makes "off" enforceable
// where the reads happen.
//
// Absence of a row means the default: memory ON.

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Store) migrateAssistantSettings(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx,
		`CREATE TABLE IF NOT EXISTS assistant_settings (
			tenant_id TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
			memory_on BOOLEAN NOT NULL DEFAULT TRUE,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`)
	return err
}

// AssistantMemoryOn reports whether the assistant may read the tenant's
// Memory/ folder. No row = the default, ON.
func (s *Store) AssistantMemoryOn(ctx context.Context, tenantID string) (bool, error) {
	var on bool
	err := s.DB.QueryRowContext(ctx,
		s.q(`SELECT memory_on FROM assistant_settings WHERE tenant_id = ?`), tenantID).Scan(&on)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return true, nil
		}
		return true, err
	}
	return on, nil
}

// SetAssistantMemoryOn upserts the tenant's memory switch.
func (s *Store) SetAssistantMemoryOn(ctx context.Context, tenantID string, on bool) error {
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO assistant_settings (tenant_id, memory_on, updated_at)
		 VALUES (?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT (tenant_id) DO UPDATE SET memory_on = excluded.memory_on, updated_at = CURRENT_TIMESTAMP`),
		tenantID, on)
	return err
}

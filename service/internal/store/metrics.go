package store

import (
	"context"
	"fmt"
	"time"
)

// Access events: the drive measures, the wallet names. Every content
// read is recorded keyed by the caller's sub — never a name or an
// attribute (the PII boundary of the wallet integration). The metrics
// queries aggregate for the owner's Insights view.

// AccessEvent is one recorded content access.
type AccessEvent struct {
	TenantID   string
	Sub        string
	Event      string // view | download | tool
	NodeID     string
	DurationMS int64
	Bytes      int64
}

// migrateAccessEvents creates the access_events table (idempotent,
// called from migrate). Rowid/implicit-heap on both dialects: events
// are insert-only and queried by the indexes below, no PK needed.
func (s *Store) migrateAccessEvents(ctx context.Context) error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS access_events (
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			sub TEXT NOT NULL,
			event TEXT NOT NULL,
			node_id TEXT,
			at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			duration_ms BIGINT NOT NULL DEFAULT 0,
			bytes BIGINT NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS access_events_tenant_at ON access_events(tenant_id, at)`,
		`CREATE INDEX IF NOT EXISTS access_events_tenant_sub ON access_events(tenant_id, sub)`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// RecordAccessEvent inserts one event (best-effort at call sites: a
// metrics failure never blocks a read).
func (s *Store) RecordAccessEvent(ctx context.Context, e AccessEvent) error {
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO access_events (tenant_id, sub, event, node_id, duration_ms, bytes)
		 VALUES (?, ?, ?, NULLIF(?, ''), ?, ?)`),
		e.TenantID, e.Sub, e.Event, e.NodeID, e.DurationMS, e.Bytes)
	return err
}

// dayExpr / isoExpr format a timestamp column per dialect.
func (s *Store) dayExpr(col string) string {
	if s.Dialect == DialectPostgres {
		return fmt.Sprintf("to_char(%s, 'YYYY-MM-DD')", col)
	}
	return fmt.Sprintf("strftime('%%Y-%%m-%%d', %s)", col)
}

func (s *Store) isoExpr(agg, col string) string {
	if s.Dialect == DialectPostgres {
		return fmt.Sprintf(`to_char(%s(%s), 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`, agg, col)
	}
	return fmt.Sprintf("strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', %s(%s))", agg, col)
}

// MetricsDay is one day of the access series.
type MetricsDay struct {
	Date       string `json:"date"`
	Views      int64  `json:"views"`
	Downloads  int64  `json:"downloads"`
	UniqueSubs int64  `json:"unique_subs"`
}

// MetricsNode is a per-node aggregate (top content).
type MetricsNode struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Views  int64  `json:"views"`
	LastAt string `json:"last_at"`
}

// MetricsSub is a per-subject aggregate. The sub is opaque here; the
// wallet decorates it client-side.
type MetricsSub struct {
	Sub       string `json:"sub"`
	Views     int64  `json:"views"`
	Downloads int64  `json:"downloads"`
	Bytes     int64  `json:"bytes"`
	TotalMS   int64  `json:"total_ms"`
	FirstAt   string `json:"first_at"`
	LastAt    string `json:"last_at"`
}

// MetricsUniqueSubs counts distinct subjects in the window (the
// series' per-day uniques cannot be summed).
func (s *Store) MetricsUniqueSubs(ctx context.Context, tenantID string, days int) (int64, error) {
	var n int64
	err := s.DB.QueryRowContext(ctx, s.q(
		`SELECT count(DISTINCT sub) FROM access_events WHERE tenant_id = ? AND at >= ?`),
		tenantID, time.Now().UTC().AddDate(0, 0, -days)).Scan(&n)
	return n, err
}

// MetricsSeries returns the per-day series for the last `days` days.
func (s *Store) MetricsSeries(ctx context.Context, tenantID string, days int) ([]MetricsDay, error) {
	query := fmt.Sprintf(
		`SELECT %s AS d,
		        count(*) FILTER (WHERE event <> 'download') AS views,
		        count(*) FILTER (WHERE event = 'download') AS downloads,
		        count(DISTINCT sub) AS uniq
		 FROM access_events
		 WHERE tenant_id = ? AND at >= ?
		 GROUP BY d ORDER BY d`, s.dayExpr("at"))
	rows, err := s.DB.QueryContext(ctx, s.q(query),
		tenantID, time.Now().UTC().AddDate(0, 0, -days))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricsDay
	for rows.Next() {
		var m MetricsDay
		if err := rows.Scan(&m.Date, &m.Views, &m.Downloads, &m.UniqueSubs); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MetricsTopNodes returns the most-read nodes in the window.
func (s *Store) MetricsTopNodes(ctx context.Context, tenantID string, days, limit int) ([]MetricsNode, error) {
	query := fmt.Sprintf(
		`SELECT e.node_id, COALESCE(n.name, '(deleted)') AS name,
		        count(*) AS views, %s AS last_at
		 FROM access_events e
		 LEFT JOIN nodes n ON n.id = e.node_id
		 WHERE e.tenant_id = ? AND e.at >= ? AND e.node_id IS NOT NULL
		 GROUP BY e.node_id, n.name
		 ORDER BY views DESC LIMIT ?`, s.isoExpr("max", "e.at"))
	rows, err := s.DB.QueryContext(ctx, s.q(query),
		tenantID, time.Now().UTC().AddDate(0, 0, -days), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricsNode
	for rows.Next() {
		var m MetricsNode
		if err := rows.Scan(&m.NodeID, &m.Name, &m.Views, &m.LastAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MetricsSubs returns per-subject aggregates in the window.
func (s *Store) MetricsSubs(ctx context.Context, tenantID string, days, limit int) ([]MetricsSub, error) {
	query := fmt.Sprintf(
		`SELECT sub,
		        count(*) FILTER (WHERE event <> 'download') AS views,
		        count(*) FILTER (WHERE event = 'download') AS downloads,
		        COALESCE(sum(bytes), 0), COALESCE(sum(duration_ms), 0),
		        %s, %s
		 FROM access_events
		 WHERE tenant_id = ? AND at >= ?
		 GROUP BY sub ORDER BY views DESC LIMIT ?`,
		s.isoExpr("min", "at"), s.isoExpr("max", "at"))
	rows, err := s.DB.QueryContext(ctx, s.q(query),
		tenantID, time.Now().UTC().AddDate(0, 0, -days), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MetricsSub
	for rows.Next() {
		var m MetricsSub
		if err := rows.Scan(&m.Sub, &m.Views, &m.Downloads, &m.Bytes, &m.TotalMS, &m.FirstAt, &m.LastAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

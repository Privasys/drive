package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// LinkRequest is a visitor's pending (or decided) request to access a
// node via a "restricted" share link. The visitor authenticated and
// presented some attributes; the owner approves or denies. Approval
// mints a per-recipient grant, recorded in GrantID.
type LinkRequest struct {
	ID           string
	TenantID     string
	LinkID       string
	NodeID       string
	RequesterSub string
	Attributes   string // JSON object of the attributes the visitor presented
	Scope        string // comma-joined scope the link offers (e.g. "read")
	Status       string // pending | approved | denied
	GrantID      string
	CreatedAt    time.Time
	DecidedAt    *time.Time
	DecidedBy    string
}

// CreateLinkRequest persists a fresh pending request. The partial unique
// index on (link_id, requester_sub) WHERE status='pending' collapses
// repeat redemptions by the same visitor into ErrDuplicateApproval so a
// visitor cannot flood the owner with duplicates.
func (s *Store) CreateLinkRequest(ctx context.Context, r *LinkRequest) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = Now()
	}
	if r.Scope == "" {
		r.Scope = "read"
	}
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO link_requests(id, tenant_id, link_id, node_id, requester_sub,
		                           attributes, scope, status, created_at)
		 VALUES (?,?,?,?,?,?,?, 'pending', ?)`),
		r.ID, r.TenantID, r.LinkID, nullableString(r.NodeID), r.RequesterSub,
		r.Attributes, r.Scope, r.CreatedAt)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") {
			return ErrDuplicateApproval
		}
		return err
	}
	return nil
}

// GetLinkRequest returns a request scoped to its tenant.
func (s *Store) GetLinkRequest(ctx context.Context, tenantID, id string) (*LinkRequest, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT id, tenant_id, link_id, node_id, requester_sub, attributes, scope,
		        status, grant_id, created_at, decided_at, decided_by
		 FROM link_requests WHERE tenant_id = ? AND id = ?`), tenantID, id)
	return scanLinkRequest(row)
}

// PendingLinkRequestFor returns the visitor's active pending request on a
// link, or (nil, ErrNotFound) when none exists. Lets a re-visiting
// recipient see the state of their earlier request.
func (s *Store) PendingLinkRequestFor(ctx context.Context, linkID, requesterSub string) (*LinkRequest, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT id, tenant_id, link_id, node_id, requester_sub, attributes, scope,
		        status, grant_id, created_at, decided_at, decided_by
		 FROM link_requests WHERE link_id = ? AND requester_sub = ? AND status = 'pending'`),
		linkID, requesterSub)
	return scanLinkRequest(row)
}

// ListLinkRequests returns a tenant's requests filtered by status (pass
// "" for all), newest first.
func (s *Store) ListLinkRequests(ctx context.Context, tenantID, status string) ([]*LinkRequest, error) {
	query := `SELECT id, tenant_id, link_id, node_id, requester_sub, attributes, scope,
	                 status, grant_id, created_at, decided_at, decided_by
	          FROM link_requests WHERE tenant_id = ?`
	args := []any{tenantID}
	if status != "" {
		query += ` AND status = ?`
		args = append(args, status)
	}
	query += ` ORDER BY created_at DESC`
	rows, err := s.DB.QueryContext(ctx, s.q(query), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*LinkRequest
	for rows.Next() {
		r, err := scanLinkRequest(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DecideLinkRequest flips a pending request to approved/denied. Guarded
// on status so a concurrent double-decision cannot mint twice.
func (s *Store) DecideLinkRequest(ctx context.Context, tenantID, id, status, grantID, decidedBy string) error {
	res, err := s.DB.ExecContext(ctx, s.q(
		`UPDATE link_requests SET status = ?, grant_id = ?, decided_at = ?, decided_by = ?
		 WHERE tenant_id = ? AND id = ? AND status = 'pending'`),
		status, grantID, Now(), decidedBy, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanLinkRequest(row rowScanner) (*LinkRequest, error) {
	var (
		r        LinkRequest
		nodeID   sql.NullString
		decided  sql.NullTime
	)
	if err := row.Scan(&r.ID, &r.TenantID, &r.LinkID, &nodeID, &r.RequesterSub,
		&r.Attributes, &r.Scope, &r.Status, &r.GrantID, &r.CreatedAt,
		&decided, &r.DecidedBy); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	r.NodeID = nodeID.String
	if decided.Valid {
		t := decided.Time
		r.DecidedAt = &t
	}
	return &r, nil
}

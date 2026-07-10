package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Recovery is a pending or executed escrowed-mode recovery request.
type Recovery struct {
	ID          string
	TenantID    string
	Reason      string
	GranteeSub  string
	TTLSeconds  int64
	Nonce       string
	RequestedBy string
	Status      string // pending | executed | expired
	GrantID     string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// CreateRecovery persists a fresh pending recovery request.
func (s *Store) CreateRecovery(ctx context.Context, r *Recovery) error {
	if r.ID == "" {
		r.ID = NewID()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = Now()
	}
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO recoveries(id, tenant_id, reason, grantee_sub, ttl_seconds,
		                        nonce, requested_by, status, created_at, expires_at)
		 VALUES (?,?,?,?,?,?,?, 'pending', ?, ?)`),
		r.ID, r.TenantID, r.Reason, r.GranteeSub, r.TTLSeconds,
		r.Nonce, r.RequestedBy, r.CreatedAt, r.ExpiresAt)
	return err
}

// GetRecovery returns a recovery scoped to its tenant.
func (s *Store) GetRecovery(ctx context.Context, tenantID, id string) (*Recovery, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT id, tenant_id, reason, grantee_sub, ttl_seconds, nonce,
		        requested_by, status, grant_id, created_at, expires_at
		 FROM recoveries WHERE tenant_id = ? AND id = ?`), tenantID, id)
	var r Recovery
	if err := row.Scan(&r.ID, &r.TenantID, &r.Reason, &r.GranteeSub, &r.TTLSeconds,
		&r.Nonce, &r.RequestedBy, &r.Status, &r.GrantID, &r.CreatedAt, &r.ExpiresAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &r, nil
}

// AddRecoveryApproval records one approver's approval. Duplicate
// approvers and replayed tokens (jti) are rejected by the schema; the
// caller distinguishes them via ErrDuplicateApproval.
func (s *Store) AddRecoveryApproval(ctx context.Context, recoveryID, approverSub, jti string) error {
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO recovery_approvals(recovery_id, approver_sub, jti) VALUES (?, ?, ?)`),
		recoveryID, approverSub, jti)
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate") {
			return ErrDuplicateApproval
		}
		return err
	}
	return nil
}

// ErrDuplicateApproval means this approver (or this exact token) has
// already approved the recovery.
var ErrDuplicateApproval = errors.New("recovery: duplicate approval")

// CountRecoveryApprovals returns the number of distinct approvers
// recorded for a recovery.
func (s *Store) CountRecoveryApprovals(ctx context.Context, recoveryID string) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, s.q(
		`SELECT COUNT(*) FROM recovery_approvals WHERE recovery_id = ?`), recoveryID).Scan(&n)
	return n, err
}

// ListRecoveryApprovers returns the approver subjects for a recovery.
func (s *Store) ListRecoveryApprovers(ctx context.Context, recoveryID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT approver_sub FROM recovery_approvals WHERE recovery_id = ? ORDER BY at`), recoveryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// MarkRecoveryExecuted flips a pending recovery to executed, recording
// the minted grant. Guarded on status so a concurrent double-execute
// cannot mint twice.
func (s *Store) MarkRecoveryExecuted(ctx context.Context, tenantID, id, grantID string) error {
	res, err := s.DB.ExecContext(ctx, s.q(
		`UPDATE recoveries SET status = 'executed', grant_id = ?
		 WHERE tenant_id = ? AND id = ? AND status = 'pending'`), grantID, tenantID, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CreateTenant inserts a new tenant and records ownerSub as its owner.
// User tenants have exactly one member — the owner — which is what the
// API's access checks key on; Enterprise tenants start with the creator
// as owner and grow via AddMember.
func (s *Store) CreateTenant(ctx context.Context, t *Tenant, ownerSub string) error {
	if t.ID == "" {
		t.ID = NewID()
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = Now()
	}
	if t.Kind != TenantUser && t.Kind != TenantEnterprise {
		return fmt.Errorf("%w: tenant kind %q", ErrInvalidInput, t.Kind)
	}
	if ownerSub == "" {
		return fmt.Errorf("%w: tenant owner required", ErrInvalidInput)
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.q(
		`INSERT INTO tenants(id, kind, name, created_at) VALUES (?, ?, ?, ?)`),
		t.ID, string(t.Kind), t.Name, t.CreatedAt); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, s.q(
		`INSERT INTO members(tenant_id, user_sub, role) VALUES (?, ?, ?)`),
		t.ID, ownerSub, string(RoleOwner)); err != nil {
		return err
	}
	return tx.Commit()
}

// GetTenant fetches a tenant by id.
func (s *Store) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	row := s.DB.QueryRowContext(ctx, s.q(`SELECT id, kind, name, created_at FROM tenants WHERE id = ?`), id)
	var t Tenant
	var kind string
	if err := row.Scan(&t.ID, &kind, &t.Name, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.Kind = TenantKind(kind)
	return &t, nil
}

// AddMember adds (or updates) a user as a member of an enterprise tenant.
func (s *Store) AddMember(ctx context.Context, m *Member) error {
	t, err := s.GetTenant(ctx, m.TenantID)
	if err != nil {
		return err
	}
	if t.Kind != TenantEnterprise {
		return fmt.Errorf("%w: members allowed only on enterprise tenants", ErrInvalidInput)
	}
	switch m.Role {
	case RoleOwner, RoleAdmin, RoleContributor, RoleReader:
	default:
		return fmt.Errorf("%w: role %q", ErrInvalidInput, m.Role)
	}
	// Upsert that works on both SQLite and Postgres.
	_, err = s.DB.ExecContext(ctx, s.q(
		`INSERT INTO members(tenant_id, user_sub, role) VALUES (?, ?, ?)
		 ON CONFLICT(tenant_id, user_sub) DO UPDATE SET role = excluded.role`),
		m.TenantID, m.UserSub, string(m.Role))
	return err
}

// SwitchTenantKeys atomically migrates a tenant to a new master key:
// rewrap mutates each node in place (re-wrapped CEK for files, fresh
// name HMAC for every node), and the tenant's mek_ref is committed in
// the same transaction, so a crash leaves the tenant fully on the old
// key or fully on the new one. Returns the number of nodes updated.
func (s *Store) SwitchTenantKeys(ctx context.Context, tenantID, mekRef string, rewrap func(*Node) error) (int, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, s.q(
		`SELECT id, tenant_id, parent_id, kind, name, name_hmac, mime_hint, plain_size,
		        wrapped_cek, manifest_ref, merkle_root, acl_override, created_at, updated_at
		 FROM nodes WHERE tenant_id = ?`), tenantID)
	if err != nil {
		return 0, err
	}
	var nodes []*Node
	for rows.Next() {
		n, serr := scanNode(rows)
		if serr != nil {
			rows.Close()
			return 0, serr
		}
		nodes = append(nodes, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, n := range nodes {
		if err := rewrap(n); err != nil {
			return 0, fmt.Errorf("rewrap node %s: %w", n.ID, err)
		}
		if _, err := tx.ExecContext(ctx, s.q(
			`UPDATE nodes SET wrapped_cek = ?, name_hmac = ? WHERE tenant_id = ? AND id = ?`),
			nullableBytes(n.WrappedCEK), n.NameHMAC, tenantID, n.ID); err != nil {
			return 0, err
		}
	}
	res, err := tx.ExecContext(ctx, s.q(
		`UPDATE tenants SET mek_ref = ? WHERE id = ?`), mekRef, tenantID)
	if err != nil {
		return 0, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrNotFound
	}
	return len(nodes), tx.Commit()
}

// SetTenantMekRef persists the tenant's vault MEK reference (JSON).
func (s *Store) SetTenantMekRef(ctx context.Context, tenantID, ref string) error {
	res, err := s.DB.ExecContext(ctx, s.q(
		`UPDATE tenants SET mek_ref = ? WHERE id = ?`), ref, tenantID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TenantMekRef returns the tenant's persisted vault MEK reference, or
// "" when the tenant still uses the instance MEK.
func (s *Store) TenantMekRef(ctx context.Context, tenantID string) (string, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT COALESCE(mek_ref, '') FROM tenants WHERE id = ?`), tenantID)
	var ref string
	if err := row.Scan(&ref); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return ref, nil
}

// TenantMembership pairs a tenant with the member's role in it.
type TenantMembership struct {
	Tenant Tenant
	Role   MemberRole
}

// TenantsOf returns every tenant sub is a member of, with the role.
func (s *Store) TenantsOf(ctx context.Context, sub string) ([]TenantMembership, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT t.id, t.kind, t.name, t.created_at, m.role
		 FROM members m JOIN tenants t ON t.id = m.tenant_id
		 WHERE m.user_sub = ? ORDER BY t.created_at`), sub)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantMembership
	for rows.Next() {
		var tm TenantMembership
		var kind, role string
		if err := rows.Scan(&tm.Tenant.ID, &kind, &tm.Tenant.Name, &tm.Tenant.CreatedAt, &role); err != nil {
			return nil, err
		}
		tm.Tenant.Kind = TenantKind(kind)
		tm.Role = MemberRole(role)
		out = append(out, tm)
	}
	return out, rows.Err()
}

// PersonalTenantOf returns the User-kind tenant sub owns, or ErrNotFound.
// The API keeps this unique per sub (get-or-create on first login).
func (s *Store) PersonalTenantOf(ctx context.Context, sub string) (*Tenant, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT t.id, t.kind, t.name, t.created_at
		 FROM members m JOIN tenants t ON t.id = m.tenant_id
		 WHERE m.user_sub = ? AND m.role = ? AND t.kind = ?
		 ORDER BY t.created_at LIMIT 1`), sub, string(RoleOwner), string(TenantUser))
	var t Tenant
	var kind string
	if err := row.Scan(&t.ID, &kind, &t.Name, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	t.Kind = TenantKind(kind)
	return &t, nil
}

// MemberRoleOf returns the role of user_sub inside tenant, or ErrNotFound.
func (s *Store) MemberRoleOf(ctx context.Context, tenantID, userSub string) (MemberRole, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT role FROM members WHERE tenant_id = ? AND user_sub = ?`),
		tenantID, userSub)
	var r string
	if err := row.Scan(&r); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return MemberRole(r), nil
}

// CreateNode inserts a new folder or file. The caller is responsible
// for computing NameHMAC; the store enforces uniqueness within (tenant,
// parent). actor is recorded on the change feed for attribution.
func (s *Store) CreateNode(ctx context.Context, n *Node, actor string) error {
	if n.ID == "" {
		n.ID = NewID()
	}
	now := Now()
	if n.CreatedAt.IsZero() {
		n.CreatedAt = now
	}
	n.UpdatedAt = now
	if n.Kind != NodeFolder && n.Kind != NodeFile {
		return fmt.Errorf("%w: node kind %q", ErrInvalidInput, n.Kind)
	}
	if strings.TrimSpace(n.Name) == "" {
		return fmt.Errorf("%w: empty name", ErrInvalidInput)
	}
	if len(n.NameHMAC) == 0 {
		return fmt.Errorf("%w: missing name_hmac", ErrInvalidInput)
	}
	parent := nullable(n.ParentID)
	_, err := s.DB.ExecContext(ctx, s.q(
		`INSERT INTO nodes(
			id, tenant_id, parent_id, kind, name, name_hmac, mime_hint,
			plain_size, wrapped_cek, manifest_ref, merkle_root, acl_override,
			created_at, updated_at
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
		n.ID, n.TenantID, parent, string(n.Kind), n.Name, n.NameHMAC, n.MimeHint,
		n.PlainSize, nullableBytes(n.WrappedCEK), nullableString(n.ManifestRef), nullableBytes(n.MerkleRoot), nullableBytes(n.ACLOverride),
		n.CreatedAt, n.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	_, _ = s.DB.ExecContext(ctx, s.q(
		`INSERT INTO changes(tenant_id, node_id, op, actor) VALUES (?, ?, 'create', ?)`),
		n.TenantID, n.ID, actor,
	)
	return nil
}

// GetNode returns the node with the given id within a tenant.
func (s *Store) GetNode(ctx context.Context, tenantID, id string) (*Node, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT id, tenant_id, parent_id, kind, name, name_hmac, mime_hint, plain_size,
		        wrapped_cek, manifest_ref, merkle_root, acl_override, created_at, updated_at
		 FROM nodes WHERE tenant_id = ? AND id = ?`),
		tenantID, id)
	return scanNode(row)
}

// ListChildren returns the immediate children of parentID (or the root,
// when parentID == "").
func (s *Store) ListChildren(ctx context.Context, tenantID, parentID string) ([]*Node, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if parentID == "" {
		rows, err = s.DB.QueryContext(ctx, s.q(
			`SELECT id, tenant_id, parent_id, kind, name, name_hmac, mime_hint, plain_size,
			        wrapped_cek, manifest_ref, merkle_root, acl_override, created_at, updated_at
			 FROM nodes WHERE tenant_id = ? AND parent_id IS NULL ORDER BY kind, name`),
			tenantID)
	} else {
		rows, err = s.DB.QueryContext(ctx, s.q(
			`SELECT id, tenant_id, parent_id, kind, name, name_hmac, mime_hint, plain_size,
			        wrapped_cek, manifest_ref, merkle_root, acl_override, created_at, updated_at
			 FROM nodes WHERE tenant_id = ? AND parent_id = ? ORDER BY kind, name`),
			tenantID, parentID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Node
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// DeleteNode removes a single node (and its descendants for folders).
// actor is recorded on the change feed for attribution.
func (s *Store) DeleteNode(ctx context.Context, tenantID, id, actor string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Recursive descent.
	queue := []string{id}
	var visited []string
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		visited = append(visited, cur)
		rows, err := tx.QueryContext(ctx, s.q(
			`SELECT id FROM nodes WHERE tenant_id = ? AND parent_id = ?`),
			tenantID, cur)
		if err != nil {
			return err
		}
		for rows.Next() {
			var cid string
			if err := rows.Scan(&cid); err != nil {
				rows.Close()
				return err
			}
			queue = append(queue, cid)
		}
		rows.Close()
	}
	for _, nid := range visited {
		if _, err := tx.ExecContext(ctx, s.q(
			`DELETE FROM nodes WHERE tenant_id = ? AND id = ?`),
			tenantID, nid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, s.q(
			`INSERT INTO changes(tenant_id, node_id, op, actor) VALUES (?, ?, 'delete', ?)`),
			tenantID, nid, actor); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TenantUsageBytes returns the total plaintext bytes stored by a tenant
// (the sum of file sizes; folders are 0). Used for quota enforcement.
func (s *Store) TenantUsageBytes(ctx context.Context, tenantID string) (int64, error) {
	row := s.DB.QueryRowContext(ctx, s.q(
		`SELECT COALESCE(SUM(plain_size), 0) FROM nodes WHERE tenant_id = ? AND kind = ?`),
		tenantID, string(NodeFile))
	var total int64
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// IsDescendantOrSelf reports whether nodeID equals ancestorID or lies in
// its subtree, by walking the parent chain upward. Used to confine
// AppGrant principals to their granted node's subtree.
func (s *Store) IsDescendantOrSelf(ctx context.Context, tenantID, ancestorID, nodeID string) (bool, error) {
	if ancestorID == "" || nodeID == "" {
		return false, nil
	}
	cur := nodeID
	for depth := 0; depth < 4096; depth++ {
		if cur == ancestorID {
			return true, nil
		}
		row := s.DB.QueryRowContext(ctx, s.q(
			`SELECT parent_id FROM nodes WHERE tenant_id = ? AND id = ?`),
			tenantID, cur)
		var parent sql.NullString
		if err := row.Scan(&parent); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
		if !parent.Valid {
			return false, nil
		}
		cur = parent.String
	}
	return false, fmt.Errorf("node tree too deep at %s", nodeID)
}

// ChangeRow is one entry in the change feed.
type ChangeRow struct {
	Seq      int64
	TenantID string
	NodeID   string
	Op       string
	Actor    string
	At       time.Time
}

// ListChanges returns changes for a tenant strictly above sinceSeq (use
// 0 for "from the beginning") up to limit.
func (s *Store) ListChanges(ctx context.Context, tenantID string, sinceSeq int64, limit int) ([]ChangeRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT seq, tenant_id, node_id, op, actor, at FROM changes
		 WHERE tenant_id = ? AND seq > ? ORDER BY seq ASC LIMIT ?`),
		tenantID, sinceSeq, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChangeRow
	for rows.Next() {
		var c ChangeRow
		if err := rows.Scan(&c.Seq, &c.TenantID, &c.NodeID, &c.Op, &c.Actor, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// scanRow is the small interface common to *sql.Row and *sql.Rows.
type scanRow interface {
	Scan(dest ...any) error
}

func scanNode(r scanRow) (*Node, error) {
	var (
		n           Node
		parent      sql.NullString
		mimeHint    string
		wrappedCEK  []byte
		manifestRef sql.NullString
		merkleRoot  []byte
		aclOverride []byte
		kind        string
	)
	if err := r.Scan(&n.ID, &n.TenantID, &parent, &kind, &n.Name, &n.NameHMAC, &mimeHint,
		&n.PlainSize, &wrappedCEK, &manifestRef, &merkleRoot, &aclOverride,
		&n.CreatedAt, &n.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	n.ParentID = parent
	n.Kind = NodeKind(kind)
	n.MimeHint = mimeHint
	n.WrappedCEK = wrappedCEK
	if manifestRef.Valid {
		n.ManifestRef = manifestRef.String
	}
	n.MerkleRoot = merkleRoot
	n.ACLOverride = aclOverride
	return &n, nil
}

func nullable(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}

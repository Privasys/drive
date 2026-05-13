// Package store is the Privasys Drive index: the durable mapping from
// (tenant, parent_folder, name) to a node, plus its manifest reference,
// ACL overrides, change feed, audit, and grants.
//
// Two SQL backends are supported:
//
//   - SQLite (`modernc.org/sqlite`, pure Go) for unit tests and `--dev`.
//   - Postgres for production. The schema sticks to a portable subset
//     so the same DDL works against both with trivial driver swaps.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// TenantKind enumerates the kinds of tenants Drive recognises.
type TenantKind string

const (
	TenantUser       TenantKind = "user"
	TenantEnterprise TenantKind = "enterprise"
)

// MemberRole is the role of a member inside an Enterprise tenant.
type MemberRole string

const (
	RoleOwner       MemberRole = "owner"
	RoleAdmin       MemberRole = "admin"
	RoleContributor MemberRole = "contributor"
	RoleReader      MemberRole = "reader"
)

// NodeKind distinguishes folders from files in the closure tree.
type NodeKind string

const (
	NodeFolder NodeKind = "folder"
	NodeFile   NodeKind = "file"
)

// Tenant is a Drive tenant — User OR Enterprise.
type Tenant struct {
	ID        string
	Kind      TenantKind
	Name      string
	CreatedAt time.Time
}

// Member is a member of an Enterprise tenant.
type Member struct {
	TenantID string
	UserSub  string
	Role     MemberRole
}

// Node is a folder or file in a tenant's tree.
type Node struct {
	ID          string
	TenantID    string
	ParentID    sql.NullString
	Kind        NodeKind
	Name        string // plaintext: DB lives in TDX
	NameHMAC    []byte // fixed-length unique key (parent, name)
	MimeHint    string
	PlainSize   int64
	WrappedCEK  []byte // null for folders
	ManifestRef string // backend key, null for folders
	MerkleRoot  []byte // null for folders
	ACLOverride []byte // optional jsonb blob (raw bytes)
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Errors returned by Store.
var (
	ErrNotFound     = errors.New("store: not found")
	ErrConflict     = errors.New("store: conflict")
	ErrForbidden    = errors.New("store: forbidden")
	ErrInvalidInput = errors.New("store: invalid input")
)

// Store wraps a *sql.DB plus the per-driver dialect.
type Store struct {
	DB      *sql.DB
	Dialect Dialect
}

// Dialect is the small set of per-driver differences we need to express.
type Dialect string

const (
	DialectSQLite   Dialect = "sqlite"
	DialectPostgres Dialect = "postgres"
)

// New wraps an existing *sql.DB. The schema is created on first call
// (if missing). This is intentionally cheap so tests can call it freely.
func New(db *sql.DB, d Dialect) (*Store, error) {
	s := &Store{DB: db, Dialect: d}
	if err := s.migrate(context.Background()); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) placeholder(i int) string {
	if s.Dialect == DialectPostgres {
		return fmt.Sprintf("$%d", i)
	}
	return "?"
}

// q rewrites a `?`-style query to the dialect's placeholder style.
func (s *Store) q(query string) string {
	if s.Dialect != DialectPostgres {
		return query
	}
	var b strings.Builder
	i := 1
	for _, r := range query {
		if r == '?' {
			fmt.Fprintf(&b, "$%d", i)
			i++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (s *Store) migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS tenants (
			id TEXT PRIMARY KEY,
			kind TEXT NOT NULL,
			name TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS members (
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			user_sub TEXT NOT NULL,
			role TEXT NOT NULL,
			PRIMARY KEY (tenant_id, user_sub)
		)`,
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			parent_id TEXT,
			kind TEXT NOT NULL,
			name TEXT NOT NULL,
			name_hmac BLOB NOT NULL,
			mime_hint TEXT NOT NULL DEFAULT '',
			plain_size BIGINT NOT NULL DEFAULT 0,
			wrapped_cek BLOB,
			manifest_ref TEXT,
			merkle_root BLOB,
			acl_override BLOB,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS nodes_unique_name
			ON nodes(tenant_id, COALESCE(parent_id,''), name_hmac)`,
		`CREATE INDEX IF NOT EXISTS nodes_parent ON nodes(tenant_id, parent_id)`,
		`CREATE TABLE IF NOT EXISTS grants (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			subject TEXT NOT NULL,
			scope TEXT NOT NULL,
			created_by TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP,
			revoked_at TIMESTAMP,
			binding_pubkey TEXT,
			meta TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS grants_lookup ON grants(tenant_id, node_id)`,
		`CREATE INDEX IF NOT EXISTS grants_subject ON grants(tenant_id, subject)`,
		`CREATE TABLE IF NOT EXISTS changes (
			seq INTEGER PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			op TEXT NOT NULL,
			actor TEXT NOT NULL,
			at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS changes_tenant ON changes(tenant_id, seq)`,
	}
	for _, stmt := range stmts {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w (stmt: %s)", err, stmt)
		}
	}
	return nil
}

// NewID returns a fresh UUIDv4 string. Exposed so tests can mint ids.
func NewID() string { return uuid.NewString() }

// Now returns the time the store treats as "now" — abstracted for tests.
var Now = func() time.Time { return time.Now().UTC() }

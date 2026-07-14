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
	ID        string     `json:"id"`
	Kind      TenantKind `json:"kind"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
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
	// VectorOK reports whether the pgvector extension is available
	// (Postgres with postgresql-16-pgvector installed). When false,
	// semantic indexing and search are unavailable and files stay
	// index_status='' rather than pending.
	VectorOK bool
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
	// The DDL is shared; only the byte type and the change-feed
	// sequence differ per engine.
	blob := "BLOB"
	seq := "INTEGER PRIMARY KEY" // SQLite rowid autoincrement
	if s.Dialect == DialectPostgres {
		blob = "BYTEA"
		seq = "BIGSERIAL PRIMARY KEY"
	}
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
			name_hmac ` + blob + ` NOT NULL,
			mime_hint TEXT NOT NULL DEFAULT '',
			plain_size BIGINT NOT NULL DEFAULT 0,
			wrapped_cek ` + blob + `,
			manifest_ref TEXT,
			merkle_root ` + blob + `,
			acl_override ` + blob + `,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS nodes_unique_name
			ON nodes(tenant_id, (COALESCE(parent_id,'')), name_hmac)`,
		`CREATE INDEX IF NOT EXISTS nodes_parent ON nodes(tenant_id, parent_id)`,
		// node_id is nullable and foreign-keyed to nodes: a node-scoped
		// share references a real node (FK-enforced, cascades on node
		// delete), and a tenant-wide grant (e.g. an escrowed recovery)
		// stores NULL, which satisfies the FK.
		`CREATE TABLE IF NOT EXISTS grants (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			node_id TEXT REFERENCES nodes(id) ON DELETE CASCADE,
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
			seq ` + seq + `,
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
	// Additive columns on existing deployments (CREATE IF NOT EXISTS
	// leaves them untouched); an already-exists error means the column
	// is there (SQLite says "duplicate column", Postgres "already
	// exists" — PG's ADD COLUMN IF NOT EXISTS is not in SQLite).
	for _, col := range []string{
		`ALTER TABLE tenants ADD COLUMN mek_ref TEXT`,
		`ALTER TABLE tenants ADD COLUMN bucket_cred TEXT`,
		`ALTER TABLE tenants ADD COLUMN escrow_wrap TEXT`,
		// Semantic index bookkeeping: '' (n/a for folders / predates the
		// feature) | pending | processing | indexed | skipped | failed.
		// no_index marks a file excluded at upload, or a folder whose
		// whole subtree is non-searchable (checked up the parent chain).
		`ALTER TABLE nodes ADD COLUMN index_status TEXT DEFAULT ''`,
		`ALTER TABLE nodes ADD COLUMN no_index BOOLEAN DEFAULT FALSE`,
		// Who created the node (the change-feed actor), for the Owner
		// column in listings. '' on nodes that predate the column.
		`ALTER TABLE nodes ADD COLUMN created_by TEXT DEFAULT ''`,
	} {
		if _, err := s.DB.ExecContext(ctx, col); err != nil {
			msg := strings.ToLower(err.Error())
			if !strings.Contains(msg, "duplicate") && !strings.Contains(msg, "exists") {
				return fmt.Errorf("migrate: %q: %w", col, err)
			}
		}
	}
	// Audit log: append-only security events (escrow-wrap, recovery),
	// disclosed to the affected tenant. Separate from the change feed.
	auditSeq := "INTEGER PRIMARY KEY"
	if s.Dialect == DialectPostgres {
		auditSeq = "BIGSERIAL PRIMARY KEY"
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS audit (
			seq ` + auditSeq + `,
			tenant_id TEXT NOT NULL,
			event TEXT NOT NULL,
			actor TEXT NOT NULL,
			detail TEXT NOT NULL DEFAULT '',
			at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS audit_tenant ON audit(tenant_id, seq)`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate audit: %w", err)
		}
	}
	// Reconcile the grants.node_id foreign key on existing Postgres
	// deployments: make it nullable, normalise the legacy tenant-wide
	// sentinel ("") to NULL, and (re-)assert the FK so node-scoped
	// shares stay referentially intact. SQLite never enforced FKs and
	// has no ALTER for constraints, so this is Postgres-only; a fresh
	// SQLite/Postgres DB gets the correct shape from CREATE above.
	if s.Dialect == DialectPostgres {
		stmts := []string{
			`ALTER TABLE grants ALTER COLUMN node_id DROP NOT NULL`,
			`UPDATE grants SET node_id = NULL WHERE node_id = ''`,
			// Idempotent re-add: drop any prior FK, then add the current one.
			`ALTER TABLE grants DROP CONSTRAINT IF EXISTS grants_node_id_fkey`,
			`ALTER TABLE grants ADD CONSTRAINT grants_node_id_fkey
			   FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE`,
		}
		for _, stmt := range stmts {
			if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("migrate grants fk: %w (stmt: %s)", err, stmt)
			}
		}
	}
	// Escrowed-mode recovery requests + their approvals. Approvals are
	// unique per (recovery, approver) and per presented token (jti), so
	// one approver or one captured token can never satisfy the quorum.
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS recoveries (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			reason TEXT NOT NULL,
			grantee_sub TEXT NOT NULL,
			ttl_seconds INTEGER NOT NULL,
			nonce TEXT NOT NULL,
			requested_by TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			grant_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS recoveries_tenant ON recoveries(tenant_id, created_at)`,
		`CREATE TABLE IF NOT EXISTS recovery_approvals (
			recovery_id TEXT NOT NULL,
			approver_sub TEXT NOT NULL,
			jti TEXT NOT NULL DEFAULT '',
			at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (recovery_id, approver_sub)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS recovery_approvals_jti
			ON recovery_approvals(jti) WHERE jti != ''`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate recoveries: %w", err)
		}
	}
	// Restricted-link access requests. A visitor who redeems a
	// "restricted" share link lands here (status 'pending') with the
	// attributes they presented; the owner approves or denies. Approval
	// mints a per-recipient grant. Node-scoped, cascades with the link.
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS link_requests (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			link_id TEXT NOT NULL,
			node_id TEXT REFERENCES nodes(id) ON DELETE CASCADE,
			requester_sub TEXT NOT NULL,
			attributes TEXT NOT NULL DEFAULT '',
			scope TEXT NOT NULL DEFAULT 'read',
			status TEXT NOT NULL DEFAULT 'pending',
			grant_id TEXT NOT NULL DEFAULT '',
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			decided_at TIMESTAMP,
			decided_by TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS link_requests_tenant ON link_requests(tenant_id, status, created_at)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS link_requests_pending
			ON link_requests(link_id, requester_sub) WHERE status = 'pending'`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate link_requests: %w", err)
		}
	}
	// Section tree: deterministic document structure (headings, page
	// provenance) built at index time. Both dialects — sections need no
	// pgvector, and the doc tree exists even where embeddings do not.
	sectionsSeq := "INTEGER PRIMARY KEY"
	if s.Dialect == DialectPostgres {
		sectionsSeq = "BIGSERIAL PRIMARY KEY"
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS sections (
			id ` + sectionsSeq + `,
			tenant_id TEXT NOT NULL,
			node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			parent_id BIGINT,
			ord INT NOT NULL DEFAULT 0,
			title TEXT NOT NULL DEFAULT '',
			depth INT NOT NULL DEFAULT 0,
			char_start BIGINT NOT NULL DEFAULT 0,
			char_end BIGINT NOT NULL DEFAULT 0,
			page_start INT,
			page_end INT,
			summary TEXT NOT NULL DEFAULT '',
			summary_model TEXT NOT NULL DEFAULT ''
		)`,
		`CREATE INDEX IF NOT EXISTS sections_node ON sections(node_id, ord)`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate sections: %w", err)
		}
	}
	// Semantic index (pgvector). Postgres-only, and tolerant of a server
	// without the extension (e.g. the CI service container): semantic
	// search simply reports unavailable there. The real image bundles
	// postgresql-16-pgvector.
	//
	// v2 schema (2026-07-15, per the drive plan §8.3/§8.4): 1024-dim
	// vectors (Qwen3-Embedding full width), an `embed_space` stamp so
	// vector spaces never mix, and section anchors for provenance. The
	// v1 768-dim table held only throwaway lexical-fallback data, so
	// the migration is drop-and-recreate, resetting indexed files to
	// pending for a clean re-index.
	if s.Dialect == DialectPostgres {
		if _, err := s.DB.ExecContext(ctx, `CREATE EXTENSION IF NOT EXISTS vector`); err == nil {
			// Detect + drop the v1 shape (768-dim, no embed_space).
			var hasSpace bool
			_ = s.DB.QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM information_schema.columns
				 WHERE table_name = 'embeddings' AND column_name = 'embed_space')`).Scan(&hasSpace)
			var hasTable bool
			_ = s.DB.QueryRowContext(ctx,
				`SELECT EXISTS (SELECT 1 FROM information_schema.tables
				 WHERE table_name = 'embeddings')`).Scan(&hasTable)
			if hasTable && !hasSpace {
				if _, err := s.DB.ExecContext(ctx, `DROP TABLE embeddings`); err != nil {
					return fmt.Errorf("migrate embeddings v1 drop: %w", err)
				}
				if _, err := s.DB.ExecContext(ctx,
					`UPDATE nodes SET index_status = 'pending' WHERE index_status IN ('indexed','failed')`); err != nil {
					return fmt.Errorf("migrate embeddings v1 reset: %w", err)
				}
			}
			for _, stmt := range []string{
				`CREATE TABLE IF NOT EXISTS embeddings (
					id BIGSERIAL PRIMARY KEY,
					tenant_id TEXT NOT NULL,
					node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
					section_id BIGINT REFERENCES sections(id) ON DELETE CASCADE,
					chunk_index INT NOT NULL,
					content TEXT NOT NULL,
					char_start BIGINT NOT NULL DEFAULT 0,
					char_end BIGINT NOT NULL DEFAULT 0,
					embed_space TEXT NOT NULL,
					embedding vector(1024) NOT NULL,
					created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
				)`,
				`CREATE INDEX IF NOT EXISTS embeddings_node ON embeddings(node_id)`,
				`CREATE INDEX IF NOT EXISTS embeddings_tenant_space ON embeddings(tenant_id, embed_space)`,
			} {
				if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
					return fmt.Errorf("migrate embeddings: %w", err)
				}
			}
			s.VectorOK = true
		}
	}
	return nil
}

// NewID returns a fresh UUIDv4 string. Exposed so tests can mint ids.
func NewID() string { return uuid.NewString() }

// Now returns the time the store treats as "now" — abstracted for tests.
var Now = func() time.Time { return time.Now().UTC() }

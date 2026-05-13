// Package grants implements Privasys Drive's three-audience sharing
// model:
//
//   - subject:<sub>     user-to-user share (wallet re-wraps the CEK)
//   - link              anonymous static link (URL fragment-secret)
//   - app:<mrtd>        third-party platform app via signed AppGrant
//
// Grants are stored in the index (table `grants`) and enforced inside
// the API layer. Revocation is immediate (sets `revoked_at`).
package grants

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Subject prefixes used in the `subject` column.
const (
	SubjectUser = "subject:" // followed by OIDC sub
	SubjectLink = "link"     // sentinel — no further data
	SubjectApp  = "app:"     // followed by hex-encoded MRTD measurement
)

// Scope flags. Stored as a comma-joined string for portability.
type Scope string

const (
	ScopeRead   Scope = "read"
	ScopeWrite  Scope = "write"
	ScopeShare  Scope = "share"
	ScopeDelete Scope = "delete"
)

// Grant is the persisted form of a share / app-grant record.
type Grant struct {
	ID            string
	TenantID      string
	NodeID        string
	Subject       string
	Scope         []Scope
	CreatedBy     string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	RevokedAt     *time.Time
	BindingPubkey string // for SubjectApp — base64 ed25519 public key
	Meta          string // free-form JSON (UI label, etc.)
}

// Repo persists and queries grants. It is parameterised by the same
// `?`-style placeholder rewriter as store.Store.
type Repo struct {
	DB         *sql.DB
	Postgres   bool
	NowFn      func() time.Time
	IDFn       func() string
}

// New returns a Repo bound to db.
func New(db *sql.DB, postgres bool) *Repo {
	return &Repo{DB: db, Postgres: postgres,
		NowFn: func() time.Time { return time.Now().UTC() },
		IDFn:  func() string { return uuid.NewString() },
	}
}

func (r *Repo) q(query string) string {
	if !r.Postgres {
		return query
	}
	var b strings.Builder
	i := 1
	for _, ch := range query {
		if ch == '?' {
			fmt.Fprintf(&b, "$%d", i)
			i++
			continue
		}
		b.WriteRune(ch)
	}
	return b.String()
}

// Create persists a new grant and fills g.ID + g.CreatedAt.
func (r *Repo) Create(ctx context.Context, g *Grant) error {
	if g.ID == "" {
		g.ID = r.IDFn()
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = r.NowFn()
	}
	scope := joinScopes(g.Scope)
	var exp any
	if g.ExpiresAt != nil {
		exp = *g.ExpiresAt
	}
	_, err := r.DB.ExecContext(ctx, r.q(
		`INSERT INTO grants(id, tenant_id, node_id, subject, scope, created_by,
		                    created_at, expires_at, revoked_at, binding_pubkey, meta)
		 VALUES (?,?,?,?,?,?,?,?,NULL,?,?)`),
		g.ID, g.TenantID, g.NodeID, g.Subject, scope, g.CreatedBy,
		g.CreatedAt, exp, nullableString(g.BindingPubkey), nullableString(g.Meta))
	return err
}

// Revoke marks a grant revoked. Idempotent.
func (r *Repo) Revoke(ctx context.Context, tenantID, id string) error {
	_, err := r.DB.ExecContext(ctx, r.q(
		`UPDATE grants SET revoked_at = ? WHERE tenant_id = ? AND id = ? AND revoked_at IS NULL`),
		r.NowFn(), tenantID, id)
	return err
}

// ListForNode returns the active grants for a node.
func (r *Repo) ListForNode(ctx context.Context, tenantID, nodeID string) ([]*Grant, error) {
	rows, err := r.DB.QueryContext(ctx, r.q(
		`SELECT id, tenant_id, node_id, subject, scope, created_by, created_at,
		        expires_at, revoked_at, binding_pubkey, meta
		 FROM grants WHERE tenant_id = ? AND node_id = ?`),
		tenantID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		g, err := scanGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func scanGrant(rows *sql.Rows) (*Grant, error) {
	var (
		g          Grant
		scope      string
		expires    sql.NullTime
		revoked    sql.NullTime
		bindingKey sql.NullString
		meta       sql.NullString
	)
	if err := rows.Scan(&g.ID, &g.TenantID, &g.NodeID, &g.Subject, &scope, &g.CreatedBy,
		&g.CreatedAt, &expires, &revoked, &bindingKey, &meta); err != nil {
		return nil, err
	}
	g.Scope = splitScopes(scope)
	if expires.Valid {
		t := expires.Time
		g.ExpiresAt = &t
	}
	if revoked.Valid {
		t := revoked.Time
		g.RevokedAt = &t
	}
	if bindingKey.Valid {
		g.BindingPubkey = bindingKey.String
	}
	if meta.Valid {
		g.Meta = meta.String
	}
	return &g, nil
}

// IsActive reports whether g is currently in force.
func (g *Grant) IsActive(now time.Time) bool {
	if g.RevokedAt != nil {
		return false
	}
	if g.ExpiresAt != nil && !g.ExpiresAt.After(now) {
		return false
	}
	return true
}

// HasScope reports whether g grants s.
func (g *Grant) HasScope(s Scope) bool {
	for _, x := range g.Scope {
		if x == s {
			return true
		}
	}
	return false
}

func joinScopes(ss []Scope) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return strings.Join(out, ",")
}

func splitScopes(s string) []Scope {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]Scope, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, Scope(p))
		}
	}
	return out
}

func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// --- AppGrant token ---------------------------------------------------
//
// AppGrant tokens are detached, signed JSON envelopes. They are minted
// by the wallet (or by the service on the wallet's behalf) and presented
// by the platform app on every request:
//
//   Authorization: AppGrant <base64url(envelope)>.<base64url(signature)>
//
// The service verifies (1) the embedded signing public key matches the
// grant row's BindingPubkey, (2) the signature, (3) the envelope's exp,
// (4) the grant has not been revoked, and (5) the requested scope.

// Envelope is the JSON payload carried by an AppGrant token.
type Envelope struct {
	Iss   string   `json:"iss"`            // "https://privasys.id"
	Aud   string   `json:"aud"`            // "privasys-drive"
	Sub   string   `json:"sub"`            // tenant id
	Node  string   `json:"node"`           // node id
	Scope []Scope  `json:"scope"`
	MRTD  string   `json:"mrtd"`           // hex-encoded
	JTI   string   `json:"jti"`            // == grant.ID for revocation lookup
	Iat   int64    `json:"iat"`
	Exp   int64    `json:"exp"`
	PK    string   `json:"pk"`             // base64 ed25519 public key
}

// MintToken signs env with priv and returns the wire form.
func MintToken(priv ed25519.PrivateKey, env Envelope) (string, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, body)
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// ParseToken decodes + signature-verifies a token. The caller must
// still verify (a) issuer/audience/expiry, (b) scope, (c) PK matches
// the persisted Grant.BindingPubkey, and (d) the grant is active.
func ParseToken(tok string) (*Envelope, error) {
	dot := strings.IndexByte(tok, '.')
	if dot <= 0 {
		return nil, errors.New("grants: malformed token")
	}
	body, err := base64.RawURLEncoding.DecodeString(tok[:dot])
	if err != nil {
		return nil, fmt.Errorf("grants: bad envelope: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(tok[dot+1:])
	if err != nil {
		return nil, fmt.Errorf("grants: bad signature: %w", err)
	}
	var env Envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("grants: bad envelope json: %w", err)
	}
	pk, err := base64.RawStdEncoding.DecodeString(env.PK)
	if err != nil {
		// Wallets sometimes use std padding.
		pk, err = base64.StdEncoding.DecodeString(env.PK)
		if err != nil {
			return nil, fmt.Errorf("grants: bad pk: %w", err)
		}
	}
	if len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("grants: pk wrong length")
	}
	if !ed25519.Verify(pk, body, sig) {
		return nil, errors.New("grants: signature does not verify")
	}
	return &env, nil
}

// PubkeyThumbprint returns hex(SHA-256(pk)) for use as a stable id.
func PubkeyThumbprint(pk []byte) string { sum := sha256.Sum256(pk); return hex.EncodeToString(sum[:]) }

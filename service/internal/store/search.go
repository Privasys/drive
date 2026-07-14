package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Semantic-index persistence. Embedding rows live in the same database
// as the node index (FK to nodes and sections, cascade on delete), so
// deletion and revocation stay trivially consistent — the drive is its
// own RAG store. Sections carry the deterministic document structure
// (provenance-first: every chunk anchors to its section and char range).

// IndexStatus values for nodes.index_status.
const (
	IndexPending    = "pending"
	IndexProcessing = "processing"
	IndexIndexed    = "indexed"
	IndexSkipped    = "skipped"
	IndexFailed     = "failed"
)

// SetIndexStatus updates a node's semantic-index status.
func (s *Store) SetIndexStatus(ctx context.Context, tenantID, nodeID, status string) error {
	_, err := s.DB.ExecContext(ctx, s.q(
		`UPDATE nodes SET index_status = ? WHERE tenant_id = ? AND id = ?`),
		status, tenantID, nodeID)
	return err
}

// SetNoIndex flags a node (file or folder) as excluded from the
// semantic index. For folders the exclusion covers the whole subtree
// (the indexer walks the parent chain).
func (s *Store) SetNoIndex(ctx context.Context, tenantID, nodeID string, noIndex bool) error {
	res, err := s.DB.ExecContext(ctx, s.q(
		`UPDATE nodes SET no_index = ? WHERE tenant_id = ? AND id = ?`),
		noIndex, tenantID, nodeID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// NodeIndexMeta returns (index_status, no_index) for a node.
func (s *Store) NodeIndexMeta(ctx context.Context, tenantID, nodeID string) (string, bool, error) {
	var (
		status  *string
		noIndex *bool
	)
	err := s.DB.QueryRowContext(ctx, s.q(
		`SELECT index_status, no_index FROM nodes WHERE tenant_id = ? AND id = ?`),
		tenantID, nodeID).Scan(&status, &noIndex)
	if err != nil {
		return "", false, err
	}
	st, ni := "", false
	if status != nil {
		st = *status
	}
	if noIndex != nil {
		ni = *noIndex
	}
	return st, ni, nil
}

// HasNoIndexAncestor reports whether the node or any ancestor folder is
// marked no_index (the "non-searchable directory" rule).
func (s *Store) HasNoIndexAncestor(ctx context.Context, tenantID, nodeID string) (bool, error) {
	cur := nodeID
	for depth := 0; cur != "" && depth < 4096; depth++ {
		var (
			noIndex *bool
			parent  *string
		)
		err := s.DB.QueryRowContext(ctx, s.q(
			`SELECT no_index, parent_id FROM nodes WHERE tenant_id = ? AND id = ?`),
			tenantID, cur).Scan(&noIndex, &parent)
		if err != nil {
			return false, err
		}
		if noIndex != nil && *noIndex {
			return true, nil
		}
		if parent == nil {
			return false, nil
		}
		cur = *parent
	}
	return false, nil
}

// ListPendingIndex returns file node ids awaiting indexing, oldest
// first, for the retry sweep.
func (s *Store) ListPendingIndex(ctx context.Context, limit int) ([][3]string, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT tenant_id, id, name FROM nodes
		 WHERE kind = 'file' AND index_status = ?
		 ORDER BY updated_at LIMIT `+fmt.Sprint(limit)),
		IndexPending)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var t, id, name string
		if err := rows.Scan(&t, &id, &name); err != nil {
			return nil, err
		}
		out = append(out, [3]string{t, id, name})
	}
	return out, rows.Err()
}

// NodeListMeta carries the per-node listing extras fetched in one
// batched query: the semantic-index state and the creator.
type NodeListMeta struct {
	IndexStatus string // '' | pending | processing | indexed | skipped | failed | excluded
	CreatedBy   string
}

// ListNodeMeta returns nodeID -> listing meta for a set of nodes. A
// node explicitly marked no_index reports index status "excluded" —
// how a non-searchable folder surfaces its state to the UI toggle.
func (s *Store) ListNodeMeta(ctx context.Context, tenantID string, nodeIDs []string) (map[string]NodeListMeta, error) {
	out := make(map[string]NodeListMeta, len(nodeIDs))
	if len(nodeIDs) == 0 {
		return out, nil
	}
	ph := make([]string, len(nodeIDs))
	args := make([]any, 0, len(nodeIDs)+1)
	args = append(args, tenantID)
	for i, id := range nodeIDs {
		ph[i] = "?"
		args = append(args, id)
	}
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT id, index_status, no_index, created_by FROM nodes WHERE tenant_id = ? AND id IN (`+strings.Join(ph, ",")+`)`),
		args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var status, createdBy *string
		var noIndex *bool
		if err := rows.Scan(&id, &status, &noIndex, &createdBy); err != nil {
			return nil, err
		}
		var m NodeListMeta
		switch {
		case noIndex != nil && *noIndex:
			m.IndexStatus = "excluded"
		case status != nil && *status != "":
			m.IndexStatus = *status
		}
		if createdBy != nil {
			m.CreatedBy = *createdBy
		}
		out[id] = m
	}
	return out, rows.Err()
}

// --- Sections (deterministic document structure) ------------------------

// Section is one node of a file's structure tree.
type Section struct {
	ID        int64
	TenantID  string
	NodeID    string
	ParentID  *int64
	Ord       int
	Title     string
	Depth     int
	CharStart int64
	CharEnd   int64
	PageStart *int
	PageEnd   *int
	Summary   string
}

// ReplaceSections atomically swaps a file's section tree. Input
// sections reference parents by SLICE INDEX (ParentIdx < own index, -1
// for roots); the store assigns ids and returns them in input order.
func (s *Store) ReplaceSections(ctx context.Context, tenantID, nodeID string, secs []SectionInput) ([]int64, error) {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.q(
		`DELETE FROM sections WHERE node_id = ?`), nodeID); err != nil {
		return nil, err
	}
	ids := make([]int64, len(secs))
	for i, sec := range secs {
		var parent any
		if sec.ParentIdx >= 0 {
			parent = ids[sec.ParentIdx]
		}
		var id int64
		if s.Dialect == DialectPostgres {
			err = tx.QueryRowContext(ctx,
				`INSERT INTO sections(tenant_id, node_id, parent_id, ord, title, depth,
				                      char_start, char_end, page_start, page_end)
				 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id`,
				tenantID, nodeID, parent, i, sec.Title, sec.Depth,
				sec.CharStart, sec.CharEnd, sec.PageStart, sec.PageEnd).Scan(&id)
		} else {
			var res sql.Result
			res, err = tx.ExecContext(ctx, s.q(
				`INSERT INTO sections(tenant_id, node_id, parent_id, ord, title, depth,
				                      char_start, char_end, page_start, page_end)
				 VALUES (?,?,?,?,?,?,?,?,?,?)`),
				tenantID, nodeID, parent, i, sec.Title, sec.Depth,
				sec.CharStart, sec.CharEnd, sec.PageStart, sec.PageEnd)
			if err == nil {
				id, err = res.LastInsertId()
			}
		}
		if err != nil {
			return nil, err
		}
		ids[i] = id
	}
	return ids, tx.Commit()
}

// SectionInput is one section to persist; ParentIdx refers to an
// earlier element of the same slice (-1 = root).
type SectionInput struct {
	ParentIdx int
	Title     string
	Depth     int
	CharStart int64
	CharEnd   int64
	PageStart *int
	PageEnd   *int
}

// ListSections returns a file's sections in document order.
func (s *Store) ListSections(ctx context.Context, tenantID, nodeID string) ([]*Section, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT id, tenant_id, node_id, parent_id, ord, title, depth,
		        char_start, char_end, page_start, page_end, summary
		 FROM sections WHERE tenant_id = ? AND node_id = ? ORDER BY ord`),
		tenantID, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Section
	for rows.Next() {
		var sec Section
		var parent sql.NullInt64
		var ps, pe sql.NullInt64
		if err := rows.Scan(&sec.ID, &sec.TenantID, &sec.NodeID, &parent, &sec.Ord,
			&sec.Title, &sec.Depth, &sec.CharStart, &sec.CharEnd, &ps, &pe, &sec.Summary); err != nil {
			return nil, err
		}
		if parent.Valid {
			p := parent.Int64
			sec.ParentID = &p
		}
		if ps.Valid {
			v := int(ps.Int64)
			sec.PageStart = &v
		}
		if pe.Valid {
			v := int(pe.Int64)
			sec.PageEnd = &v
		}
		out = append(out, &sec)
	}
	return out, rows.Err()
}

// GetSection returns one section, tenant-scoped.
func (s *Store) GetSection(ctx context.Context, tenantID string, id int64) (*Section, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT id, tenant_id, node_id, parent_id, ord, title, depth,
		        char_start, char_end, page_start, page_end, summary
		 FROM sections WHERE tenant_id = ? AND id = ?`), tenantID, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}
	var sec Section
	var parent sql.NullInt64
	var ps, pe sql.NullInt64
	if err := rows.Scan(&sec.ID, &sec.TenantID, &sec.NodeID, &parent, &sec.Ord,
		&sec.Title, &sec.Depth, &sec.CharStart, &sec.CharEnd, &ps, &pe, &sec.Summary); err != nil {
		return nil, err
	}
	if parent.Valid {
		p := parent.Int64
		sec.ParentID = &p
	}
	if ps.Valid {
		v := int(ps.Int64)
		sec.PageStart = &v
	}
	if pe.Valid {
		v := int(pe.Int64)
		sec.PageEnd = &v
	}
	return &sec, nil
}

// --- Embeddings ----------------------------------------------------------

// EmbeddingRow is one chunk of a file's text plus its vector and
// provenance anchors.
type EmbeddingRow struct {
	SectionID  *int64
	ChunkIndex int
	Content    string
	CharStart  int64
	CharEnd    int64
	Vector     []float32
}

// ReplaceEmbeddings atomically swaps a node's embedding rows under a
// vector-space stamp (delete + insert), so re-indexing never leaves a
// mixed state. Postgres+pgvector only.
func (s *Store) ReplaceEmbeddings(ctx context.Context, tenantID, nodeID, space string, rows []EmbeddingRow) error {
	if !s.VectorOK {
		return fmt.Errorf("semantic index unavailable (pgvector missing)")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM embeddings WHERE node_id = $1`, nodeID); err != nil {
		return err
	}
	for _, r := range rows {
		var section any
		if r.SectionID != nil {
			section = *r.SectionID
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO embeddings(tenant_id, node_id, section_id, chunk_index, content,
			                        char_start, char_end, embed_space, embedding)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::vector)`,
			tenantID, nodeID, section, r.ChunkIndex, r.Content,
			r.CharStart, r.CharEnd, space, vectorLiteral(r.Vector)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SearchHit is one semantic-search result with provenance.
type SearchHit struct {
	NodeID     string
	Name       string
	MimeHint   string
	SectionID  *int64
	ChunkIndex int
	Content    string
	CharStart  int64
	CharEnd    int64
	Score      float64 // cosine similarity, higher is better
}

// SearchEmbeddings runs a cosine nearest-neighbour search over a
// tenant's embeddings IN ONE VECTOR SPACE, joined with live node
// metadata. Rows written by another space never mix into results.
func (s *Store) SearchEmbeddings(ctx context.Context, tenantID, space string, query []float32, topK int) ([]SearchHit, error) {
	if !s.VectorOK {
		return nil, fmt.Errorf("semantic index unavailable (pgvector missing)")
	}
	if topK <= 0 || topK > 50 {
		topK = 10
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT e.node_id, n.name, n.mime_hint, e.section_id, e.chunk_index, e.content,
		        e.char_start, e.char_end,
		        1 - (e.embedding <=> $1::vector) AS score
		 FROM embeddings e JOIN nodes n ON n.id = e.node_id
		 WHERE e.tenant_id = $2 AND e.embed_space = $3
		 ORDER BY e.embedding <=> $1::vector
		 LIMIT $4`,
		vectorLiteral(query), tenantID, space, topK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchHit
	for rows.Next() {
		var h SearchHit
		var section sql.NullInt64
		if err := rows.Scan(&h.NodeID, &h.Name, &h.MimeHint, &section, &h.ChunkIndex,
			&h.Content, &h.CharStart, &h.CharEnd, &h.Score); err != nil {
			return nil, err
		}
		if section.Valid {
			v := section.Int64
			h.SectionID = &v
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// vectorLiteral renders a pgvector input literal: [0.1,0.2,...].
func vectorLiteral(v []float32) string {
	var b strings.Builder
	b.WriteByte('[')
	for i, f := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%g", f)
	}
	b.WriteByte(']')
	return b.String()
}

package store

import (
	"context"
	"fmt"
	"strings"
)

// Semantic-index persistence. Embedding rows live in the same database
// as the node index (FK to nodes, cascade on delete), so deletion and
// revocation stay trivially consistent — the drive is its own RAG store.

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

// EmbeddingRow is one chunk of a file's text plus its vector.
type EmbeddingRow struct {
	ChunkIndex int
	Content    string
	Vector     []float32
}

// ReplaceEmbeddings atomically swaps a node's embedding rows (delete +
// insert), so re-indexing never leaves a mixed state. Postgres+pgvector
// only.
func (s *Store) ReplaceEmbeddings(ctx context.Context, tenantID, nodeID string, rows []EmbeddingRow) error {
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
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO embeddings(tenant_id, node_id, chunk_index, content, embedding)
			 VALUES ($1, $2, $3, $4, $5::vector)`,
			tenantID, nodeID, r.ChunkIndex, r.Content, vectorLiteral(r.Vector)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SearchHit is one semantic-search result.
type SearchHit struct {
	NodeID     string
	Name       string
	MimeHint   string
	ChunkIndex int
	Content    string
	Score      float64 // cosine similarity, higher is better
}

// SearchEmbeddings runs a cosine nearest-neighbour search over a
// tenant's embeddings, joined with live node metadata.
func (s *Store) SearchEmbeddings(ctx context.Context, tenantID string, query []float32, topK int) ([]SearchHit, error) {
	if !s.VectorOK {
		return nil, fmt.Errorf("semantic index unavailable (pgvector missing)")
	}
	if topK <= 0 || topK > 50 {
		topK = 10
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT e.node_id, n.name, n.mime_hint, e.chunk_index, e.content,
		        1 - (e.embedding <=> $1::vector) AS score
		 FROM embeddings e JOIN nodes n ON n.id = e.node_id
		 WHERE e.tenant_id = $2
		 ORDER BY e.embedding <=> $1::vector
		 LIMIT $3`,
		vectorLiteral(query), tenantID, topK)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SearchHit
	for rows.Next() {
		var h SearchHit
		if err := rows.Scan(&h.NodeID, &h.Name, &h.MimeHint, &h.ChunkIndex, &h.Content, &h.Score); err != nil {
			return nil, err
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

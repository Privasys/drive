package store

import (
	"context"
	"strings"
)

// UsageByChildren returns, for every direct child of parentID ("" = the
// tenant root), the plaintext bytes stored in that child's subtree (a file
// counts its own size; a folder the sum of everything under it). One
// recursive query, so a storage breakdown costs the same on a Drive with a
// hundred thousand nodes as on an empty one. Feeds the storage gauge's
// by-folder view (plans/drive-as-remote-disk.md, user model).
func (s *Store) UsageByChildren(ctx context.Context, tenantID, parentID string) (map[string]int64, error) {
	var (
		seed string
		args []any
	)
	if parentID == "" {
		seed = `SELECT id, id AS top FROM nodes WHERE tenant_id = ? AND parent_id IS NULL`
		args = []any{tenantID, tenantID}
	} else {
		seed = `SELECT id, id AS top FROM nodes WHERE tenant_id = ? AND parent_id = ?`
		args = []any{tenantID, parentID, tenantID}
	}
	rows, err := s.DB.QueryContext(ctx, s.q(
		`WITH RECURSIVE tree(id, top) AS (
		    `+seed+`
		    UNION ALL
		    SELECT n.id, t.top FROM nodes n JOIN tree t ON n.parent_id = t.id WHERE n.tenant_id = ?
		 )
		 SELECT t.top, COALESCE(SUM(n.plain_size), 0)
		 FROM tree t JOIN nodes n ON n.id = t.id
		 WHERE n.kind = 'file'
		 GROUP BY t.top`), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var bytes int64
		if err := rows.Scan(&id, &bytes); err != nil {
			return nil, err
		}
		out[id] = bytes
	}
	return out, rows.Err()
}

// WorkspaceManifestName is the file that marks a folder as a workspace
// snapshot (plans/drive-as-remote-disk.md, tier C): the manifest the runtime
// writes beside a `.blobs/` folder. Drive stores the interior without
// indexing it and the front renders the folder as one item.
const WorkspaceManifestName = ".workspace.json"

// WorkspaceManifestIDs returns, for each folder in folderIDs that directly
// contains a workspace manifest, the manifest file's node id. Folders
// without one are absent from the map. One query for a whole listing.
func (s *Store) WorkspaceManifestIDs(ctx context.Context, tenantID string, folderIDs []string) (map[string]string, error) {
	out := map[string]string{}
	if len(folderIDs) == 0 {
		return out, nil
	}
	// Chunk the IN list so a very large listing stays within placeholder
	// limits on either database.
	const chunk = 400
	for start := 0; start < len(folderIDs); start += chunk {
		end := start + chunk
		if end > len(folderIDs) {
			end = len(folderIDs)
		}
		ids := folderIDs[start:end]
		args := make([]any, 0, len(ids)+3)
		args = append(args, tenantID, WorkspaceManifestName, string(NodeFile))
		marks := make([]string, len(ids))
		for i, id := range ids {
			marks[i] = "?"
			args = append(args, id)
		}
		rows, err := s.DB.QueryContext(ctx, s.q(
			`SELECT parent_id, id FROM nodes
			 WHERE tenant_id = ? AND name = ? AND kind = ? AND parent_id IN (`+strings.Join(marks, ",")+`)`), args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var parent, id string
			if err := rows.Scan(&parent, &id); err != nil {
				rows.Close()
				return nil, err
			}
			out[parent] = id
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

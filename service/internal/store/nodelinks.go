package store

import "context"

// Typed links between nodes (§8.7). Populated at index time from
// markdown content: digest citations (drive://<node>#<section>) and
// [[wikilinks]] between memory files. Containment (parent/child) is
// derived from the node tree at graph-render time, not stored here.
//
// Backlinks are a query; dead-link and orphan detection fall out. The
// edge's to_node is empty for an unresolved wikilink (a dangling node —
// a memory worth writing).

// LinkKind classifies an edge.
type LinkKind string

const (
	LinkCitation LinkKind = "citation"
	LinkWikilink LinkKind = "wikilink"
)

// NodeLink is one typed edge from a node (optionally a section) to
// another.
type NodeLink struct {
	FromNode    string
	FromSection string // stable anchor, "" for a file-level link
	ToNode      string // "" when unresolved (dangling)
	ToSection   string
	ToName      string // the link's target label (wikilink name / file name)
	Kind        LinkKind
}

func (s *Store) migrateNodeLinks(ctx context.Context) error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS node_links (
			tenant_id TEXT NOT NULL,
			from_node TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			from_section TEXT NOT NULL DEFAULT '',
			to_node TEXT,
			to_section TEXT NOT NULL DEFAULT '',
			to_name TEXT NOT NULL DEFAULT '',
			kind TEXT NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS node_links_from ON node_links(tenant_id, from_node)`,
		`CREATE INDEX IF NOT EXISTS node_links_to ON node_links(tenant_id, to_node)`,
	} {
		if _, err := s.DB.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceNodeLinks atomically swaps a node's outbound links.
func (s *Store) ReplaceNodeLinks(ctx context.Context, tenantID, fromNode string, links []NodeLink) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, s.q(
		`DELETE FROM node_links WHERE tenant_id = ? AND from_node = ?`), tenantID, fromNode); err != nil {
		return err
	}
	for _, l := range links {
		var to any
		if l.ToNode != "" {
			to = l.ToNode
		}
		if _, err := tx.ExecContext(ctx, s.q(
			`INSERT INTO node_links(tenant_id, from_node, from_section, to_node, to_section, to_name, kind)
			 VALUES (?,?,?,?,?,?,?)`),
			tenantID, fromNode, l.FromSection, to, l.ToSection, l.ToName, string(l.Kind)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ResolveMemoryName maps a wikilink target ("coffee-preference" or
// "coffee-preference.md") to a node id within the tenant's Memory/
// folder, or "" when unresolved.
func (s *Store) ResolveMemoryName(ctx context.Context, tenantID, name string) string {
	root, err := s.ChildByName(ctx, tenantID, "", "Memory")
	if err != nil {
		return ""
	}
	want := name
	if !hasMDSuffix(want) {
		want += ".md"
	}
	if n, err := s.ChildByName(ctx, tenantID, root.ID, want); err == nil {
		return n.ID
	}
	return ""
}

func hasMDSuffix(s string) bool {
	return len(s) >= 3 && s[len(s)-3:] == ".md"
}

// Backlinks returns the nodes that link TO the given node.
func (s *Store) Backlinks(ctx context.Context, tenantID, toNode string) ([]NodeLink, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT from_node, from_section, to_section, kind FROM node_links
		 WHERE tenant_id = ? AND to_node = ?`), tenantID, toNode)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeLink
	for rows.Next() {
		var l NodeLink
		l.ToNode = toNode
		if err := rows.Scan(&l.FromNode, &l.FromSection, &l.ToSection, &l.Kind); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// GraphEdge is one edge for the graph view.
type GraphEdge struct {
	FromNode string   `json:"from_node"`
	ToNode   string   `json:"to_node,omitempty"`
	ToName   string   `json:"to_name,omitempty"` // for dangling targets
	Kind     LinkKind `json:"kind"`
}

// GraphNode is one node for the graph view.
type GraphNode struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`  // file | folder
	Class  string `json:"class"` // memory | conversation | document
	Parent string `json:"parent_id,omitempty"`
}

// GraphData returns the tenant's nodes and edges for the graph view:
// stored typed links (citation, wikilink) plus derived containment from
// the node tree. Dangling wikilinks appear as edges to an empty to_node
// with a to_name.
func (s *Store) GraphData(ctx context.Context, tenantID string) ([]GraphNode, []GraphEdge, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT id, parent_id, kind, name FROM nodes WHERE tenant_id = ? ORDER BY name`), tenantID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	nameOf := map[string]string{}
	parentOf := map[string]string{}
	type raw struct{ id, parent, kind, name string }
	var all []raw
	for rows.Next() {
		var id, kind, name string
		var parent *string
		if err := rows.Scan(&id, &parent, &kind, &name); err != nil {
			return nil, nil, err
		}
		p := ""
		if parent != nil {
			p = *parent
		}
		all = append(all, raw{id, p, kind, name})
		nameOf[id] = name
		parentOf[id] = p
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	var nodes []GraphNode
	var edges []GraphEdge
	for _, r := range all {
		nodes = append(nodes, GraphNode{
			NodeID: r.id, Name: r.name, Kind: r.kind,
			Class: classifyByRoot(r.id, parentOf, nameOf), Parent: r.parent,
		})
		if r.parent != "" {
			edges = append(edges, GraphEdge{FromNode: r.parent, ToNode: r.id, Kind: "containment"})
		}
	}
	lrows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT from_node, to_node, to_name, kind FROM node_links WHERE tenant_id = ?`), tenantID)
	if err != nil {
		return nil, nil, err
	}
	defer lrows.Close()
	for lrows.Next() {
		var from, name, kind string
		var to *string
		if err := lrows.Scan(&from, &to, &name, &kind); err != nil {
			return nil, nil, err
		}
		e := GraphEdge{FromNode: from, ToName: name, Kind: LinkKind(kind)}
		if to != nil {
			e.ToNode = *to
		}
		edges = append(edges, e)
	}
	return nodes, edges, lrows.Err()
}

// classifyByRoot returns memory | conversation | document from the
// node's top-level ancestor folder name.
func classifyByRoot(id string, parentOf, nameOf map[string]string) string {
	cur := id
	for parentOf[cur] != "" {
		cur = parentOf[cur]
	}
	switch nameOf[cur] {
	case "Memory":
		return "memory"
	case "Chat conversations":
		return "conversation"
	default:
		return "document"
	}
}

// DeadLinks returns links whose target did not resolve (dangling
// wikilinks) — the wiki-lint signal.
func (s *Store) DeadLinks(ctx context.Context, tenantID string) ([]NodeLink, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT from_node, from_section, to_name, kind FROM node_links
		 WHERE tenant_id = ? AND to_node IS NULL`), tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NodeLink
	for rows.Next() {
		var l NodeLink
		if err := rows.Scan(&l.FromNode, &l.FromSection, &l.ToName, &l.Kind); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// OrphanNodes returns file nodes that nothing links to and that link to
// nothing — the wiki-lint orphan signal. Folders and the top-level
// convention folders are excluded.
func (s *Store) OrphanNodes(ctx context.Context, tenantID string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, s.q(
		`SELECT n.id FROM nodes n
		 WHERE n.tenant_id = ? AND n.kind = 'file'
		   AND NOT EXISTS (SELECT 1 FROM node_links l WHERE l.tenant_id = n.tenant_id AND l.to_node = n.id)
		   AND NOT EXISTS (SELECT 1 FROM node_links l WHERE l.tenant_id = n.tenant_id AND l.from_node = n.id)`),
		tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

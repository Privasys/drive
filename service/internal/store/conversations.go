package store

import "context"

// Conversation storage helpers (§8.7). Conversations are ordinary Drive
// folders under a top-level "Chat conversations/" directory; these
// helpers are the name-based lookups the conversation API composes on
// top of the normal node primitives (no new tables — a conversation is
// a folder convention, GC'd, shared and exported like any other).

// ChildByName returns the child of parentID (or a root child when
// parentID == "") whose plaintext name matches, or ErrNotFound. Names
// are unique within a parent (nodes_unique_name), so at most one.
func (s *Store) ChildByName(ctx context.Context, tenantID, parentID, name string) (*Node, error) {
	var kids []*Node
	var err error
	if parentID == "" {
		kids, err = s.ListRootChildren(ctx, tenantID)
	} else {
		kids, err = s.ListChildren(ctx, tenantID, parentID)
	}
	if err != nil {
		return nil, err
	}
	for _, n := range kids {
		if n.Name == name {
			return n, nil
		}
	}
	return nil, ErrNotFound
}

// ListRootChildren lists a tenant's top-level nodes (parent_id NULL).
func (s *Store) ListRootChildren(ctx context.Context, tenantID string) ([]*Node, error) {
	return s.ListChildren(ctx, tenantID, "")
}

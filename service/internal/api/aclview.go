package api

import (
	"context"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// nodeReader answers "may this principal read node X" for many nodes of
// one tenant, for the routes that list across a tenant (graph, lint,
// backlinks, changes, metrics). For a tenant member it applies the folder
// ACL overrides from a single read of the tree, exactly as aclAllows does
// node by node, and a node the overrides close stays readable through a
// share the member holds. Every other principal falls back to allowNode,
// one node at a time.
type nodeReader struct {
	s        *Server
	ctx      context.Context
	p        *Principal
	tenantID string
	member   bool
	open     bool
	role     store.MemberRole
	tree     map[string]store.NodeACL
	memo     map[string]bool
}

func (s *Server) newNodeReader(ctx context.Context, p *Principal, tenantID string) (*nodeReader, error) {
	v := &nodeReader{s: s, ctx: ctx, p: p, tenantID: tenantID, memo: map[string]bool{}}
	if !p.IsUser() || !s.canRead(ctx, tenantID, p.Sub) {
		return v, nil
	}
	v.member = true
	v.role = s.memberRole(ctx, tenantID, p.Sub)
	if s.tenantKind(ctx, tenantID) != store.TenantEnterprise || v.role == store.RoleOwner {
		v.open = true
		return v, nil
	}
	tree, err := s.Store.NodeACLTree(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	v.tree = tree
	return v, nil
}

// readable reports whether the principal may read nodeID ("" is the root).
func (v *nodeReader) readable(nodeID string) bool {
	if !v.member {
		return v.s.allowNode(v.ctx, v.p, v.tenantID, nodeID, grants.ScopeRead)
	}
	if v.open || nodeID == "" || v.passes(nodeID) {
		return true
	}
	return v.s.hasReadShare(v.ctx, v.tenantID, nodeID, v.p.Sub)
}

// readableLive is readable for a node that must still exist: under the
// overrides, a node gone from the tree cannot be placed, so it fails.
func (v *nodeReader) readableLive(nodeID string) bool {
	if v.member && !v.open {
		if _, ok := v.tree[nodeID]; !ok {
			return false
		}
	}
	return v.readable(nodeID)
}

// changeVisible reports whether the caller may see a change row. Under
// the overrides the row is judged where it was recorded: its parent must
// be the root or a folder that still exists and is readable, so nothing
// recorded inside a since-deleted folder passes. A node that still exists
// must be readable too, except a folder with an override of its own,
// whose name shows wherever its parent does.
func (v *nodeReader) changeVisible(c store.ChangeRow) bool {
	if !v.member || v.open {
		if c.Op == "delete" {
			return v.readable(c.ParentID)
		}
		return v.readable(c.NodeID)
	}
	if c.ParentID != "" && !v.readableLive(c.ParentID) {
		return false
	}
	e, ok := v.tree[c.NodeID]
	if !ok || c.Op == "delete" {
		return true
	}
	return e.Has || v.readable(c.NodeID)
}

// passes applies the nearest ACL override at or above nodeID, as
// EffectiveACL and aclAllows do. A node not in the tree passes, as it does
// there.
func (v *nodeReader) passes(nodeID string) bool {
	if ok, seen := v.memo[nodeID]; seen {
		return ok
	}
	v.memo[nodeID] = false // a cycle in the tree fails closed
	ok := true
	if e, found := v.tree[nodeID]; found {
		switch {
		case e.Has && e.Roles != nil:
			ok = false
			for _, r := range e.Roles {
				if store.MemberRole(r) == v.role {
					ok = true
					break
				}
			}
		case !e.Has && e.Parent != "":
			ok = v.passes(e.Parent)
		}
	}
	v.memo[nodeID] = ok
	return ok
}

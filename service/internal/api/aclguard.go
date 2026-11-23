// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import (
	"context"
	"strings"

	"github.com/Privasys/drive/service/internal/grants"
)

// Folder ACL overrides (aclAllows) narrow who may reach a folder and its
// subtree. Every way of reaching content has to respect them: a direct
// read, a grant or link someone minted, and a read of a whole subtree.

// grantHonoured reports whether g may open nodeID under the folder ACL
// overrides. A grant carries no more than its creator could reach: one
// minted by a member an override excludes does not open that folder, even
// when it was minted on an ancestor or before the override was set.
func (s *Server) grantHonoured(ctx context.Context, g *grants.Grant, nodeID string) bool {
	creator, trusted := s.grantCreator(ctx, g)
	if trusted {
		return true
	}
	return s.aclAllows(ctx, g.TenantID, nodeID, creator)
}

// grantCreator resolves the member a grant acts for. A grant minted by a
// link redemption acts for the link's creator. A recovery grant was
// approved through the recovery gate and is trusted as such.
func (s *Server) grantCreator(ctx context.Context, g *grants.Grant) (sub string, trusted bool) {
	c := g.CreatedBy
	if strings.HasPrefix(c, "recovery:") {
		return "", true
	}
	if id, ok := strings.CutPrefix(c, "link:"); ok {
		lg, err := s.Grants.Get(ctx, id)
		if err != nil || lg.TenantID != g.TenantID {
			return "", false
		}
		c = lg.CreatedBy
	}
	return strings.TrimPrefix(c, grants.SubjectUser), false
}

// subtreeHidesFrom reports whether the subtree at root ("" for the whole
// tenant) holds a folder whose ACL override p may not pass, so a request
// that would return the subtree in one piece must be refused.
func (s *Server) subtreeHidesFrom(ctx context.Context, p *Principal, tenantID, root string) bool {
	ids, err := s.Store.OverriddenFolders(ctx, tenantID)
	if err != nil {
		return true
	}
	for _, id := range ids {
		inside := root == ""
		if !inside {
			ok, err := s.Store.IsDescendantOrSelf(ctx, tenantID, root, id)
			if err != nil {
				return true
			}
			inside = ok
		}
		if inside && !s.allowNode(ctx, p, tenantID, id, grants.ScopeRead) {
			return true
		}
	}
	return false
}

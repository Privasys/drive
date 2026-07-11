package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/grants"
)

// grantView is the display form of a grant for the permissions dialog
// (no binding pubkey / wrapped material — just who has what).
type grantView struct {
	ID        string   `json:"id"`
	Subject   string   `json:"subject"`
	Scope     []string `json:"scope"`
	CreatedBy string   `json:"created_by"`
	ExpiresAt *string  `json:"expires_at,omitempty"`
	Revoked   bool     `json:"revoked"`
}

// handleNodePermissions returns everything the Share/Permissions dialog
// needs for a node: the people it is shared with (grants), the node's
// own folder ACL override (if any), and the effective (inherited) ACL.
// Any tenant reader may inspect; changes stay owner/admin-gated.
func (s *Server) handleNodePermissions(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canRead(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	n, err := s.Store.GetNode(r.Context(), tenantID, nodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	gs, err := s.Grants.ListForNode(r.Context(), tenantID, nodeID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	views := make([]grantView, 0, len(gs))
	for _, g := range gs {
		gv := grantView{
			ID: g.ID, Subject: g.Subject, CreatedBy: g.CreatedBy,
			Revoked: g.RevokedAt != nil,
		}
		for _, sc := range g.Scope {
			gv.Scope = append(gv.Scope, string(sc))
		}
		if g.ExpiresAt != nil {
			iso := g.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
			gv.ExpiresAt = &iso
		}
		views = append(views, gv)
	}

	// This node's OWN ACL override (what an admin edits), plus the
	// effective (nearest-ancestor) override for display.
	var ownRoles []string
	if len(n.ACLOverride) > 0 {
		var doc struct {
			Roles []string `json:"roles"`
		}
		if json.Unmarshal(n.ACLOverride, &doc) == nil {
			ownRoles = doc.Roles
		}
	}
	effective, _ := s.Store.EffectiveACL(r.Context(), tenantID, nodeID)

	var parentID string
	if n.ParentID.Valid {
		parentID = n.ParentID.String
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node": map[string]any{
			"id": n.ID, "name": n.Name, "kind": string(n.Kind),
			"parent_id": parentID,
		},
		"grants":        views,
		"acl_override":  ownRoles, // nil when no own override (inherits)
		"effective_acl": effective,
	})
}

var _ = grants.ScopeRead

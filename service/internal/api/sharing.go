package api

import (
	"context"
	"errors"
	"net/http"

	"github.com/Privasys/drive/service/internal/grants"
)

// hasReadShare reports whether sub holds an active read (or write, which
// implies read) user-to-user share on nodeID or any ancestor folder in
// tenantID. A share is an explicit grant by the owner, so it authorises
// the recipient independently of the tenant's membership ACL.
func (s *Server) hasReadShare(ctx context.Context, tenantID, nodeID, sub string) bool {
	if nodeID == "" {
		return false
	}
	cur := nodeID
	for depth := 0; cur != "" && depth < 4096; depth++ {
		g, err := s.Grants.ActiveForSubjectOnNode(ctx, tenantID, cur, sub)
		if err == nil && g != nil && (g.HasScope(grants.ScopeRead) || g.HasScope(grants.ScopeWrite)) {
			return true
		}
		n, err := s.Store.GetNode(ctx, tenantID, cur)
		if err != nil || !n.ParentID.Valid {
			return false
		}
		cur = n.ParentID.String
	}
	return false
}

// sharedItem is one entry in a recipient's inbound-share inbox.
type sharedItem struct {
	GrantID   string `json:"grant_id"`
	TenantID  string `json:"tenant_id"`
	NodeID    string `json:"node_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Scope     string `json:"scope"`
	SharedBy  string `json:"shared_by"`
	SizeBytes int64  `json:"size_bytes"`
	// WrappedCEK is the recipient-wrapped CEK the sharing owner stored
	// on the grant (for a client-side-decrypt recipient); empty for the
	// server-side-decrypt path.
	WrappedCEK string `json:"wrapped_cek,omitempty"`
}

// handleSharedWithMe lists the shares addressed to the caller across all
// tenants — the recipient's inbox. Each entry gives the owning tenant +
// node so the recipient can read it via the normal file endpoints.
func (s *Server) handleSharedWithMe(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("user principals only"))
		return
	}
	gs, err := s.Grants.ListForSubject(r.Context(), p.Sub)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]sharedItem, 0, len(gs))
	for _, g := range gs {
		it := sharedItem{
			GrantID: g.ID, TenantID: g.TenantID, NodeID: g.NodeID,
			SharedBy: g.CreatedBy, WrappedCEK: g.Meta,
		}
		if len(g.Scope) > 0 {
			it.Scope = string(g.Scope[0])
		}
		if n, nerr := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID); nerr == nil {
			it.Name = n.Name
			it.Kind = string(n.Kind)
			it.SizeBytes = n.PlainSize
		}
		out = append(out, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{"shared": out})
}

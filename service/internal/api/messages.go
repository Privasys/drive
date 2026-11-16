package api

import (
	"context"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Wallet notifications use the platform's generic app message once the
// instance turns it on (config app_messages). Its banner text is fixed by
// kind, so nothing Drive writes reaches Apple or Google in the clear; the
// wallet opens the path on Drive's own host, which the platform supplies,
// never Drive. Nothing else rides in the payload: the wallet shows no file
// names, only who is asking, with its own labels.
//
// Until then Drive sends its own share-request and share-decision types,
// which older wallets need: they learn the requester's name only from those.
const appMessage = "app-message"

// requestMessage tells a sharer that someone asks to open their link. The
// path lands on the Requests view of the drive the link belongs to.
// presented carries what the requester presented, keyed by attribute name;
// the wallet keeps only the names it knows and labels them itself.
func requestMessage(tenantID string, presented map[string]string) map[string]any {
	m := map[string]any{"kind": "request", "path": "/#requests/" + tenantID}
	if len(presented) > 0 {
		m["presented"] = presented
	}
	return m
}

// responseMessage tells a requester that the sharer decided. Whatever the
// decision, the place to look is Shared with me.
func responseMessage() map[string]any {
	return map[string]any{"kind": "response", "path": "/#shared"}
}

func (s *Server) appMessages() bool {
	cfg := s.CurrentConfig()
	return cfg != nil && cfg.AppMessages
}

// notifyShareRequest tells the sharer that requesterSub asks to open link g.
func (s *Server) notifyShareRequest(g *grants.Grant, lr *store.LinkRequest, n *store.Node, requesterSub string, presented map[string]string) {
	if s.appMessages() {
		s.Notifier().Fire(g.CreatedBy, appMessage, requestMessage(g.TenantID, presented))
		return
	}
	s.Notifier().Fire(g.CreatedBy, "share-request", map[string]any{
		"tenant_id":     g.TenantID,
		"request_id":    lr.ID,
		"node_id":       g.NodeID,
		"node_name":     n.Name,
		"requester_sub": requesterSub,
		"attributes":    presented,
		"scope":         scopeStrings(g.Scope),
	})
}

// notifyShareDecision tells the requester that the sharer decided.
func (s *Server) notifyShareDecision(ctx context.Context, lr *store.LinkRequest, status string) {
	if s.appMessages() {
		s.Notifier().Fire(lr.RequesterSub, appMessage, responseMessage())
		return
	}
	nodeName := ""
	if n, err := s.Store.GetNode(ctx, lr.TenantID, lr.NodeID); err == nil {
		nodeName = n.Name
	}
	s.Notifier().Fire(lr.RequesterSub, "share-decision", map[string]any{
		"tenant_id": lr.TenantID, "request_id": lr.ID,
		"node_id": lr.NodeID, "node_name": nodeName, "status": status,
	})
}

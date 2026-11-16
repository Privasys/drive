package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Wallet notifications use the platform's generic types once the instance
// turns them on (config app_messages):
//   - a share request is an app form, which the sharer answers inside the
//     wallet (formanswer.go receives the answer);
//   - a decision is an app message of kind response, a link back in.
//
// Banner text is fixed by the IdP, and a form is built only from
// components the wallet draws itself, so nothing Drive writes reaches Apple
// or Google in the clear or speaks in the wallet's voice. Paths are on
// Drive's own host, which the platform supplies, never Drive.
//
// Until then Drive sends its own share-request and share-decision types,
// which older wallets need: they learn the requester's name only from those.
const (
	appMessage = "app-message"
	appForm    = "app-form"

	// formAnswerPath is where the wallet posts the holder's answer.
	formAnswerPath = "/v1/link-requests/answer"
)

// requestForm is the form a sharer answers: who asks, for which file, what
// access, and approve or deny. Its id is the request's id.
func requestForm(lr *store.LinkRequest, fileName string, presented map[string]string) string {
	blocks := []map[string]any{}
	if vals := formAttributes(presented); len(vals) > 0 {
		blocks = append(blocks, map[string]any{"type": "attributes", "values": vals})
	}
	access := "Read"
	for _, sc := range splitScopeStrings(lr.Scope) {
		if sc == grants.ScopeWrite {
			access = "Read and edit"
		}
	}
	items := []map[string]string{}
	if name := formText(fileName, 200); name != "" {
		items = append(items, map[string]string{"label": "File", "value": name})
	}
	items = append(items, map[string]string{"label": "Access", "value": access})
	blocks = append(blocks, map[string]any{"type": "fields", "items": items})
	form := map[string]any{
		"v":        1,
		"id":       lr.ID,
		"title":    "Access to a shared file",
		"blocks":   blocks,
		"actions":  []map[string]string{{"id": "approve", "kind": "approve"}, {"id": "deny", "kind": "deny"}},
		"callback": formAnswerPath,
		"link":     "/#requests/" + lr.TenantID,
	}
	b, _ := json.Marshal(form)
	return string(b)
}

// formAttributes keeps the presented values the form may carry: at most
// 200 characters, nothing the IdP would refuse. A value that does not fit
// is left out rather than cut, so the sharer never sees half an address.
func formAttributes(presented map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range presented {
		if c := formText(v, 200); c != "" && c == strings.TrimSpace(v) {
			out[k] = c
		}
	}
	return out
}

// formText strips what a form may not hold (control, bidirectional and
// zero-width characters) and shortens to max characters.
func formText(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || isBidiOrZeroWidth(r) {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		r := []rune(s)
		s = string(r[:max-1]) + "…"
	}
	return s
}

func isBidiOrZeroWidth(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F, // zero-width space/joiners, LRM, RLM
		r >= 0x202A && r <= 0x202E, // embeddings and overrides
		r >= 0x2060 && r <= 0x2064, // word joiner, invisible operators
		r >= 0x2066 && r <= 0x2069, // isolates
		r == 0x061C, r == 0xFEFF:
		return true
	}
	return false
}

func formDigest(form string) string {
	sum := sha256.Sum256([]byte(form))
	return hex.EncodeToString(sum[:])
}

// responseMessage tells a requester that the sharer decided. An approval
// leads to the item itself, "/#shared/<tenant id>/<node id>", the ids
// Shared with me lists it under; a refusal has nothing to open and leads to
// Shared with me. Ids only: the payload carries no name.
func responseMessage(lr *store.LinkRequest, status string) map[string]any {
	path := "/#shared"
	if status == "approved" {
		path += "/" + lr.TenantID + "/" + lr.NodeID
	}
	return map[string]any{"kind": "response", "path": path}
}

func (s *Server) appMessages() bool {
	cfg := s.CurrentConfig()
	return cfg != nil && cfg.AppMessages
}

// notifyShareRequest asks the sharer to decide on requesterSub's request.
func (s *Server) notifyShareRequest(ctx context.Context, g *grants.Grant, lr *store.LinkRequest, n *store.Node, requesterSub string, presented map[string]string) {
	if s.appMessages() {
		// Only the digest and the addressee are kept: the answer must
		// commit to both, and the form itself carries the requester's
		// attributes.
		form := requestForm(lr, n.Name, presented)
		if err := s.Store.SetLinkRequestForm(ctx, lr.TenantID, lr.ID, formDigest(form), g.CreatedBy); err != nil {
			log.Printf("link request %s: record form: %v", lr.ID, err)
			return
		}
		s.Notifier().Fire(g.CreatedBy, appForm, map[string]any{"kind": "request", "form": form})
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
		s.Notifier().Fire(lr.RequesterSub, appMessage, responseMessage(lr, status))
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

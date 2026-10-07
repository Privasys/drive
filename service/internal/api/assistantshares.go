package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/search"
	"github.com/Privasys/drive/service/internal/store"
)

// Shares a user opened through their assistant.
//
// A share link is addressed to a person, and the person's assistant opens it
// for them with open_link: the user gets exactly the share a click would
// give them (redeemLinkFor), and the shared node is marked readable by their
// assistant with a SubjectAssistantFor grant in the sharer's tenant. The mark
// grants nothing on its own: every read also requires the user's own live
// share on the node, so revoking the share, or the link it came from, cuts
// the assistant off too. The assistant's reach is otherwise the user's
// personal tenant and its AI scope (aiscope.go); these are the one way it
// reads another tenant, and only what the user received.

// assistantShare is one shared node the user's assistant may read.
type assistantShare struct {
	TenantID string
	NodeID   string
}

// assistantShares lists the shares marked for sub's assistant that sub can
// still read.
func (s *Server) assistantShares(ctx context.Context, sub string) ([]assistantShare, error) {
	if sub == "" {
		return nil, nil
	}
	gs, err := s.Grants.ListForRawSubject(ctx, grants.SubjectAssistantFor+sub)
	if err != nil {
		return nil, err
	}
	out := make([]assistantShare, 0, len(gs))
	for _, g := range gs {
		if g.NodeID == "" || !s.hasReadShare(ctx, g.TenantID, g.NodeID, sub) {
			continue
		}
		out = append(out, assistantShare{TenantID: g.TenantID, NodeID: g.NodeID})
	}
	return out, nil
}

// markAssistantShare makes a node sub received readable by sub's assistant.
// Idempotent. Marking before an owner has approved a restricted request is
// deliberate: the mark lies dormant until the share exists.
func (s *Server) markAssistantShare(ctx context.Context, tenantID, nodeID, sub string) error {
	subject := grants.SubjectAssistantFor + sub
	if g, err := s.Grants.ActiveRawSubjectOnNode(ctx, tenantID, nodeID, subject); err == nil && g != nil {
		return nil
	}
	return s.Grants.Create(ctx, &grants.Grant{
		TenantID:  tenantID,
		NodeID:    nodeID,
		Subject:   subject,
		Scope:     []grants.Scope{grants.ScopeRead},
		CreatedBy: grants.SubjectUser + sub,
	})
}

// shareCovering returns the marked share whose subtree holds nodeID in
// tenantID, if any.
func (s *Server) shareCovering(ctx context.Context, shares []assistantShare, tenantID, nodeID string) (assistantShare, bool) {
	cur := nodeID
	for depth := 0; cur != "" && depth < 4096; depth++ {
		for _, sh := range shares {
			if sh.TenantID == tenantID && sh.NodeID == cur {
				return sh, true
			}
		}
		n, err := s.Store.GetNode(ctx, tenantID, cur)
		if err != nil || !n.ParentID.Valid {
			return assistantShare{}, false
		}
		cur = n.ParentID.String
	}
	return assistantShare{}, false
}

// assistantMayReadShared reports whether the assistant acting for sub may
// read nodeID in tenantID because sub received it and opened it through the
// assistant.
func (s *Server) assistantMayReadShared(ctx context.Context, sub, tenantID, nodeID string) bool {
	if nodeID == "" {
		return false
	}
	shares, err := s.assistantShares(ctx, sub)
	if err != nil || len(shares) == 0 {
		return false
	}
	_, ok := s.shareCovering(ctx, shares, tenantID, nodeID)
	return ok
}

// sharedTenantOf finds which tenant a node the assistant names lives in,
// among the shares marked for sub. The model knows node ids, never tenants.
func (s *Server) sharedTenantOf(ctx context.Context, sub, nodeID string) (string, bool) {
	shares, err := s.assistantShares(ctx, sub)
	if err != nil {
		return "", false
	}
	seen := map[string]bool{}
	for _, sh := range shares {
		if seen[sh.TenantID] {
			continue
		}
		seen[sh.TenantID] = true
		if _, err := s.Store.GetNode(ctx, sh.TenantID, nodeID); err != nil {
			continue
		}
		if _, ok := s.shareCovering(ctx, shares, sh.TenantID, nodeID); ok {
			return sh.TenantID, true
		}
	}
	return "", false
}

// parseShareLink takes a Drive share link as a user would paste it
// (https://drive.privasys.org/l?id=<id>&a=…#<secret>) and returns its id
// and secret. Any host is accepted: the secret is what proves the link,
// and a link minted by another Drive simply does not resolve here.
func parseShareLink(raw string) (id, secret string, err error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", "", errors.New("that is not a link")
	}
	id = strings.TrimSpace(u.Query().Get("id"))
	secret = strings.TrimSpace(u.Fragment)
	if id == "" || secret == "" {
		return "", "", errors.New("the link is incomplete: it needs its id and the part after #")
	}
	return id, secret, nil
}

// toolOpenLink is the assistant's open_link: redeem a share link for the
// acting user and make what it shares readable here.
func (s *Server) toolOpenLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	var req struct {
		URL string `json:"url"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if !p.IsAssistant() || p.Sub == "" {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	id, secret, err := parseShareLink(req.URL)
	if err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	g, meta, err := s.loadLink(r.Context(), id, secret)
	if err != nil {
		writeLinkError(w, err)
		return
	}
	n, err := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	out, err := s.redeemLinkFor(r.Context(), p, g, meta, n, nil)
	var me *linkMarketError
	if errors.As(err, &me) {
		writeMarketError(w, me.err)
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	ownerName := ""
	if t, terr := s.Store.GetTenant(r.Context(), g.TenantID); terr == nil {
		ownerName = t.Name
	}
	res := map[string]any{
		"status":     out.Status,
		"node_id":    n.ID,
		"name":       n.Name,
		"kind":       string(n.Kind),
		"owner_name": ownerName,
	}
	switch out.Status {
	case "granted", "pending":
		if err := s.markAssistantShare(r.Context(), g.TenantID, g.NodeID, p.Sub); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		if out.Status == "granted" {
			if n.Kind == store.NodeFolder {
				res["next"] = "The folder is open. Call get_folder_tree with its node_id, or search_semantic, to read it."
			} else {
				res["next"] = "The file is open. Call read_file with its node_id."
			}
		} else {
			res["next"] = "The owner approves each person for this link. Tell the user their request is with " +
				orDefault(ownerName, "the owner") + "; once approved, the files are readable here without opening the link again."
		}
	case linkMissingAttrs:
		res["missing_attributes"] = out.Missing
		res["next"] = "This link asks the user to share " + strings.Join(out.Missing, ", ") +
			" with " + orDefault(ownerName, "its owner") + ". Ask them to open the link in a browser and approve that in their wallet; afterwards, call open_link again."
	}
	writeJSON(w, http.StatusOK, res)
}

// toolListShares is the assistant's list_shares: what other people shared
// with the user that the assistant may read.
func (s *Server) toolListShares(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.IsAssistant() || p.Sub == "" {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	shares, err := s.assistantShares(r.Context(), p.Sub)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]map[string]any, 0, len(shares))
	for _, sh := range shares {
		n, err := s.Store.GetNode(r.Context(), sh.TenantID, sh.NodeID)
		if err != nil {
			continue
		}
		owner := ""
		if t, terr := s.Store.GetTenant(r.Context(), sh.TenantID); terr == nil {
			owner = t.Name
		}
		out = append(out, map[string]any{
			"node_id": n.ID, "name": n.Name, "kind": string(n.Kind), "owner_name": owner,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": out})
}

func orDefault(s, d string) string {
	if strings.TrimSpace(s) == "" {
		return d
	}
	return s
}

// assistantSearch is search_semantic for the assistant: the user's own
// AI-scoped set plus every share they opened through the assistant, ranked
// together. The query is embedded once. A harness folder filter
// (knowledge.go) narrows the shares too: a share joins only when its root
// is one of the folders named.
func (s *Server) assistantSearch(ctx context.Context, sub, personalTenant, q string, topK int) (searchResult, int, error) {
	shares, err := s.assistantShares(ctx, sub)
	if err != nil {
		return searchResult{}, http.StatusInternalServerError, err
	}
	if filter := folderFilterFrom(ctx); filter != nil {
		keep := map[string]bool{}
		for _, id := range filter {
			keep[id] = true
		}
		kept := shares[:0]
		for _, sh := range shares {
			if keep[sh.NodeID] {
				kept = append(kept, sh)
			}
		}
		shares = kept
	}
	if len(shares) == 0 {
		return s.semanticSearchScoped(ctx, personalTenant, q, topK)
	}

	emb := s.activeEmbedder()
	vecs, err := emb.Embed(ctx, []string{q}, search.Query)
	if err != nil {
		return searchResult{}, http.StatusBadGateway, err
	}
	rr := s.activeReranker()
	limit := recallLimit(topK, rr != nil)

	scopes := map[string][]string{} // tenant → allowed node ids
	own, err := s.aiScopeNodeSet(ctx, personalTenant)
	if err != nil {
		return searchResult{}, http.StatusInternalServerError, err
	}
	scopes[personalTenant] = own
	roots := map[string][]string{}
	for _, sh := range shares {
		roots[sh.TenantID] = append(roots[sh.TenantID], sh.NodeID)
	}
	for tenantID, ids := range roots {
		under, err := s.Store.DescendantNodeIDs(ctx, tenantID, ids)
		if err != nil {
			return searchResult{}, http.StatusInternalServerError, err
		}
		scopes[tenantID] = append(scopes[tenantID], under...)
	}

	var hits []store.SearchHit
	tenantOf := map[string]string{} // node id → tenant
	for tenantID, allow := range scopes {
		if len(allow) == 0 {
			continue
		}
		hs, err := s.Store.SearchEmbeddingsScoped(ctx, tenantID, emb.Space(), vecs[0], limit, allow)
		if err != nil {
			return searchResult{}, http.StatusInternalServerError, err
		}
		for _, h := range hs {
			tenantOf[h.NodeID] = tenantID
		}
		hits = append(hits, hs...)
	}
	sort.SliceStable(hits, func(i, j int) bool { return hits[i].Score > hits[j].Score })
	if len(hits) > limit {
		hits = hits[:limit]
	}
	hits, reranked := applyRerank(ctx, rr, q, hits, topK)
	out := make([]searchHitJSON, 0, len(hits))
	for _, h := range hits {
		out = append(out, s.hitsToJSON(ctx, tenantOf[h.NodeID], []store.SearchHit{h})...)
	}
	return searchResult{Hits: out, Reranked: reranked}, http.StatusOK, nil
}

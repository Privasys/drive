package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// An open link that asks for nothing opens without a sign-in. Its secret is
// already the whole authority: whoever holds the link may read, and anyone
// it is forwarded to may too, so a sign-in would name a visitor without
// deciding anything. The page presents the link itself as the credential,
// `Authorization: DriveLink <link id>.<secret>`, and gets read access to the
// shared node and what is beneath it, nothing more.
//
// Everything else keeps the sign-in:
//   - a restricted link, whose visitor proves who they are or what they
//     hold, which only a sign-in can carry;
//   - a one-off link, which closes on the first person it lets in, so it
//     needs that person to be someone;
//   - a link that grants more than reading, whose writes need an author.
//
// Only on a direct name: there TLS ends in the enclave, so the gateway sees
// neither the secret nor the content. The platform hostname's terminated
// leg never carries it, and the runtime stamps which leg a request came by.
const linkAuthScheme = "DriveLink "

var (
	errLinkNeedsSignIn = errors.New("sign in to open this link")
	errLinkNotDirect   = errors.New("open this link on the drive's own address")
)

// opensWithoutSignIn reports whether a link may be read by whoever holds it.
func opensWithoutSignIn(g *grants.Grant, meta *linkMeta) bool {
	return meta.Mode == linkModeOpen && len(meta.Attrs) == 0 && !meta.OneOff &&
		len(g.Scope) == 1 && g.Scope[0] == grants.ScopeRead
}

// linkReader authenticates a route that a link alone may also read: a link
// credential when the request carries one, the usual sign-in otherwise.
func (s *Server) linkReader(next func(http.ResponseWriter, *http.Request, *Principal)) http.Handler {
	signedIn := s.auth(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred, ok := strings.CutPrefix(r.Header.Get("Authorization"), linkAuthScheme)
		if !ok {
			signedIn.ServeHTTP(w, r)
			return
		}
		p, status, err := s.linkPrincipal(r, cred)
		if err != nil {
			httpError(w, status, err)
			return
		}
		next(w, r, p)
	})
}

// linkPrincipal turns a link credential into a principal confined to the
// link's subtree, for reading. Every refusal of the link itself answers the
// same 404, as the public preview does.
func (s *Server) linkPrincipal(r *http.Request, cred string) (*Principal, int, error) {
	if r.Header.Get(transportHeader) != "direct" {
		return nil, http.StatusForbidden, errLinkNotDirect
	}
	id, secret, ok := strings.Cut(strings.TrimSpace(cred), ".")
	if !ok || id == "" || secret == "" {
		return nil, http.StatusNotFound, errLinkSecret
	}
	g, meta, err := s.loadLink(r.Context(), id, secret)
	if err != nil {
		return nil, http.StatusNotFound, errLinkSecret
	}
	if !opensWithoutSignIn(g, meta) {
		return nil, http.StatusForbidden, errLinkNeedsSignIn
	}
	return &Principal{Sub: grants.SubjectLink + ":" + g.ID, Via: viaLink, Grant: g, Link: true}, http.StatusOK, nil
}

// handleViewLink is what the link page shows before anything is opened: the
// shared node and who it comes from. The link-credential counterpart of
// resolve, which needs a sign-in.
func (s *Server) handleViewLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	if !p.Link || p.Grant == nil || p.Grant.ID != r.PathValue("linkID") || !p.Grant.IsActive(time.Now().UTC()) {
		httpError(w, http.StatusNotFound, errLinkSecret)
		return
	}
	g := p.Grant
	n, err := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if n.Kind == store.NodeFile {
		s.recordAccess(p, g.TenantID, n.ID, "", 0, 0)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"link_id":    g.ID,
		"mode":       linkModeOpen,
		"scope":      scopeStrings(g.Scope),
		"tenant_id":  g.TenantID,
		"owner_name": s.linkSharerName(r.Context(), g, nil),
		"node": map[string]any{
			"id": n.ID, "name": n.Name, "kind": string(n.Kind), "size_bytes": n.PlainSize,
		},
	})
}

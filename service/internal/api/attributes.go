package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/attrbilling"
	"github.com/Privasys/drive/service/internal/oidc"
)

// The attribute marketplace, seen from the sharer's side.
//
// A sharer who requires the recipient of a document to PROVE something
// (a valid identity document, a family name) is buying a disclosure, and
// under "the inviter pays" they buy it themselves rather than leaving
// the bill with whoever registered the OAuth client. These two endpoints
// are what their client needs to make that an informed choice: what may
// be required, and what a chosen set costs. Both are pass-throughs
// carrying the sharer's own token, because the control plane resolves
// the payer from it (see package attrbilling).

// marketClient returns the marketplace client for the configured control
// plane, or nil when attribute billing cannot work here: off-platform,
// before configure, or with no OAuth client id to bind a grant to. Nil
// is a degradation, never an error: required attributes then stay
// self-asserted, which is what they were before billing existed.
func (s *Server) marketClient() *attrbilling.Client {
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.MgmtBaseURL == "" || cfg.OIDCClientID == "" {
		return nil
	}
	s.marketMu.Lock()
	defer s.marketMu.Unlock()
	if s.market == nil || s.market.BaseURL != strings.TrimRight(cfg.MgmtBaseURL, "/") {
		s.market = attrbilling.New(cfg.MgmtBaseURL)
	}
	return s.market
}

var errNoMarket = errors.New("attribute billing is not configured on this instance (needs mgmt_base_url and oidc_client_id)")

// errNoPayer explains the one thing a sealed-session sharer cannot do.
// The payer is resolved from a platform bearer token; a session-relay
// identity carries no token, so there is no account to charge.
var errNoPayer = errors.New("requiring paid attributes needs a platform bearer token: the marketplace charges the token's own account")

// handleAttributeCatalogue lists what a sharer may require, priced. Read
// live from the platform rather than mirrored here, so an attribute
// published by a new provider is offerable without a Drive release.
func (s *Server) handleAttributeCatalogue(w http.ResponseWriter, r *http.Request, p *Principal) {
	m, err := s.marketFor(p)
	if err != nil {
		writeMarketError(w, err)
		return
	}
	attrs, err := m.Catalogue(r.Context(), p.Bearer)
	if err != nil {
		writeMarketError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"attributes": attrs})
}

// handleAttributeQuote prices the set the sharer has actually chosen,
// before the share exists. The figure comes from the same resolution the
// reservation will use, so what the sharer is shown is what they pay.
func (s *Server) handleAttributeQuote(w http.ResponseWriter, r *http.Request, p *Principal) {
	m, err := s.marketFor(p)
	if err != nil {
		writeMarketError(w, err)
		return
	}
	var req struct {
		Attributes []string `json:"attributes"`
	}
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	q, err := m.Quote(r.Context(), p.Bearer, req.Attributes)
	if err != nil {
		writeMarketError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, q)
}

// marketFor returns the marketplace client for a caller who can pay,
// naming the missing half when they cannot.
func (s *Server) marketFor(p *Principal) (*attrbilling.Client, error) {
	m := s.marketClient()
	if m == nil {
		return nil, errNoMarket
	}
	if p.Bearer == "" {
		return nil, errNoPayer
	}
	return m, nil
}

// writeMarketError passes a control-plane refusal through with its own
// status and message. Its refusals are addressed to the person choosing
// the attributes ("unknown or unavailable attribute: x"), so flattening
// them to 502 would hide the only actionable part.
func writeMarketError(w http.ResponseWriter, err error) {
	var se *attrbilling.StatusError
	if errors.As(err, &se) {
		http.Error(w, se.Body, se.Status)
		return
	}
	if errors.Is(err, errNoMarket) || errors.Is(err, errNoPayer) {
		httpError(w, http.StatusPreconditionFailed, err)
		return
	}
	httpError(w, http.StatusBadGateway, err)
}

// canonicaliseAttributes rewrites the sharer's chosen attributes into
// the catalogue's own spelling and picks out the billable ones.
//
// The marketplace addresses an attribute by namespace and refuses a bare
// name at reservation time, so a share must store the namespaced key
// even when the sharer picked it by name. Attributes the catalogue does
// not know are kept verbatim: a self-asserted profile field is a
// legitimate thing to require and has no namespace to gain.
//
// A bare name is only resolved when it is unambiguous across the
// catalogue. Two providers may publish the same name, and guessing which
// one the sharer meant would charge them for the wrong attribute.
func canonicaliseAttributes(catalogue []attrbilling.Attribute, chosen []string) (attrs, paid []string) {
	byKey := make(map[string]attrbilling.Attribute, len(catalogue))
	byName := make(map[string]attrbilling.Attribute, len(catalogue))
	ambiguous := map[string]bool{}
	for _, a := range catalogue {
		byKey[a.Key] = a
		if _, dup := byName[a.Name]; dup {
			ambiguous[a.Name] = true
			continue
		}
		byName[a.Name] = a
	}
	seen := map[string]bool{}
	for _, c := range chosen {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		a, known := byKey[c]
		if !known && !ambiguous[c] {
			a, known = byName[c]
		}
		key := c
		if known {
			key = a.Key
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		attrs = append(attrs, key)
		if known && a.Paid() {
			paid = append(paid, key)
		}
	}
	return attrs, paid
}

// attributeClaim reads a disclosed attribute off a verified token.
//
// The marketplace addresses attributes by namespace
// ("privasys:nationality") while the IdP mints the bare canonical claim,
// so the namespace is dropped for the lookup. A false boolean returns
// empty on purpose: "age_over_18: false" is an answer, not evidence.
func attributeClaim(id *oidc.Identity, key string) string {
	if id == nil || len(id.Claims) == 0 {
		return ""
	}
	name := key
	if _, after, found := strings.Cut(key, ":"); found {
		name = after
	}
	switch v := id.Claims[name].(type) {
	case string:
		return strings.TrimSpace(v)
	case bool:
		if v {
			return "true"
		}
		return ""
	default:
		return ""
	}
}

// mintLinkBillingGrant issues a grant covering the paid attributes,
// charged to the sharer making the request. One grant funds one
// recipient's sign-in.
func (s *Server) mintLinkBillingGrant(ctx context.Context, p *Principal, paid []string) (*attrbilling.Grant, error) {
	m, err := s.marketFor(p)
	if err != nil {
		return nil, err
	}
	return m.Mint(ctx, p.Bearer, s.CurrentConfig().OIDCClientID, paid, linkBillingTTL)
}

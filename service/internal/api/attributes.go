package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Privasys/drive/service/internal/attrbilling"
	"github.com/Privasys/drive/service/internal/attrref"
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

// choiceError is a refusal aimed at the person choosing the attributes
// rather than at the platform, so it answers 400: the share they asked
// for cannot exist, and the fix is to choose differently.
type choiceError struct{ msg string }

func (e *choiceError) Error() string { return e.msg }

func badChoice(format string, a ...any) error {
	return &choiceError{msg: fmt.Sprintf(format, a...)}
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
	var ce *choiceError
	if errors.As(err, &ce) {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	if errors.Is(err, errNoMarket) || errors.Is(err, errNoPayer) || errors.Is(err, errNoReferential) {
		httpError(w, http.StatusPreconditionFailed, err)
		return
	}
	httpError(w, http.StatusBadGateway, err)
}

// canonicaliseAttributes rewrites the sharer's chosen attributes into
// the catalogue's own spelling, picks out the billable ones, and records
// which claim proves each requirement.
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
//
// Namespacing and price come from the CATALOGUE, which is the authority
// and covers third-party providers. The referential is consulted for one
// thing only: the assurance the sharer picked. A registry row is named
// for the field the enclave meters, so "privasys:given_name" is the row
// behind the passport key "given_name_id" and carries the same name as
// the self-asserted "given_name" the holder types. Resolving by name
// alone therefore sells the passport row to a sharer who asked for the
// free one, and leaves the sharer who asked for the passport one with a
// requirement any typed value satisfies. The referential is what tells
// the two apart.
//
// proven maps a stored key to the claim that proves it, and is empty for
// requirements a visitor may simply assert.
func canonicaliseAttributes(ref *attrref.Referential, catalogue []attrbilling.Attribute, chosen []string) (attrs, paid []string, proven map[string]string, err error) {
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
	row := func(c string) (attrbilling.Attribute, bool) {
		if a, ok := byKey[c]; ok {
			return a, true
		}
		if ambiguous[c] {
			return attrbilling.Attribute{}, false
		}
		a, ok := byName[c]
		return a, ok
	}
	proven = map[string]string{}
	seen := map[string]bool{}
	for _, c := range chosen {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		key, claim, price, err := resolveAttribute(ref, row, c)
		if err != nil {
			return nil, nil, nil, err
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		attrs = append(attrs, key)
		if price {
			paid = append(paid, key)
		}
		if claim != "" {
			proven[key] = claim
		}
	}
	if len(proven) == 0 {
		proven = nil
	}
	return attrs, paid, proven, nil
}

// resolveAttribute settles one chosen attribute: the key to store, the
// claim that proves it ("" when a typed value is what was asked for), and
// whether the marketplace charges for it.
func resolveAttribute(ref *attrref.Referential, row func(string) (attrbilling.Attribute, bool), chosen string) (key, claim string, paid bool, err error) {
	ca, canonical := ref.Lookup(chosen)
	switch {
	case canonical && ca.GovBacked():
		// A government-backed key names its own registry row and is never
		// resolved by name: the row is named for the metered field, which
		// is also the self-asserted twin's name.
		mk := ca.MarketplaceKey()
		if mk == "" {
			// A passport field the registry sells no disclosure for
			// (document_number, sex). Free, but still proven: it comes off
			// the token or it does not arrive.
			return ca.Key, ca.Key, false, nil
		}
		a, ok := row(mk)
		if !ok || a.Key != mk {
			return "", "", false, badChoice("cannot require %q: the attribute marketplace does not offer %q", chosen, mk)
		}
		return a.Key, ca.Key, a.Paid(), nil
	case canonical:
		// A self-asserted key. It may still be namespaced, because a
		// provider can sell the cheap reading, but never onto a
		// government-backed row: that row belongs to this key's twin, and
		// landing there bills the sharer for a ceremony they did not ask
		// for and did not need.
		a, ok := row(chosen)
		if !ok || govRow(ref, a) {
			return chosen, "", false, nil
		}
		if a.Paid() {
			return a.Key, ca.Key, true, nil
		}
		return a.Key, "", false, nil
	default:
		// Unknown to the referential: a third-party namespace, or a
		// spelling stored before this build. Namespacing still comes from
		// the catalogue, and a priced disclosure is still proven.
		a, ok := row(chosen)
		if !ok {
			return chosen, "", false, nil
		}
		if !a.Paid() {
			return a.Key, "", false, nil
		}
		return a.Key, claimForRow(ref, a), true, nil
	}
}

// govRow reports whether a catalogue row sells a government-backed
// disclosure. The referential is asked first and is exact; a row it does
// not cover (a third-party provider) is taken at the registry's own
// declaration.
func govRow(ref *attrref.Referential, a attrbilling.Attribute) bool {
	if ca, ok := ref.ForMarketplaceKey(a.Key); ok {
		return ca.GovBacked()
	}
	return a.Assurance == attrref.GovVerified
}

// claimForRow is the claim the IdP mints a paid disclosure under. The IdP
// mints under the canonical key it was asked for, which for a registry row
// is the key the referential maps back to ("privasys:birthdate" is
// disclosed as "birthdate_id"). A row outside the referential has only its
// own name to go on.
func claimForRow(ref *attrref.Referential, a attrbilling.Attribute) string {
	if ca, ok := ref.ForMarketplaceKey(a.Key); ok {
		return ca.Key
	}
	if a.Name != "" {
		return a.Name
	}
	if _, after, found := strings.Cut(a.Key, ":"); found {
		return after
	}
	return a.Key
}

// attributeClaim reads one named claim off a verified token.
//
// The claim is the one the link recorded when it was created, so there is
// no guessing here and deliberately no fallback: a link that requires the
// passport reading of a birth date names "birthdate_id", and a visitor who
// asked their own wallet for the bare "birthdate" instead has proven
// nothing. A false boolean returns empty on purpose: "age_over_18: false"
// is an answer, not evidence.
func attributeClaim(id *oidc.Identity, claim string) string {
	if id == nil || claim == "" || len(id.Claims) == 0 {
		return ""
	}
	switch v := id.Claims[claim].(type) {
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

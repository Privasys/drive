package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Privasys/drive/service/internal/crypto"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/store"
)

// Share links let an owner hand out access to a node without knowing who
// the recipient is (Privasys holds no names or email addresses). A link
// carries a random secret in its URL fragment; the service stores only
// the secret's hash. Two modes:
//
//   - open        the recipient authenticates (wallet, or passkey once the
//                 sealed transport supports it) and redeems the link, which
//                 mints them a per-recipient read grant.
//   - restricted  redeeming files an access request; the owner approves each
//                 one (or, later, a saved wallet contact auto-matches). Only
//                 on approval is a grant minted. Required attributes are
//                 OPTIONAL: with none, the link is pure owner-approval ("I
//                 approve each person"); with some, the recipient must present
//                 them before a request is filed.
//
// Required attributes come in two grades, and which grade an attribute
// has is decided by the marketplace, not by Drive. A self-asserted one
// (a name typed into a form) is what restricted links have always used.
// A PAID one is proven: the IdP discloses it against a verified
// credential during the recipient's sign-in, and someone is charged for
// that disclosure. That someone is the SHARER (see armLinkBilling).
//
// The link itself is a `link`-subject grant whose Meta holds this JSON.
// Because decryption happens inside the enclave from the tenant MEK, a
// redeemed link needs nothing more than an ordinary subject grant for the
// existing download path to serve the file.

type linkMeta struct {
	SecretHash string `json:"secret_hash"` // hex(SHA-256(secret bytes)), constant-time verified
	// Secret keeps the raw-url-b64 fragment secret so the OWNER can re-copy
	// the full link later ("Active links"). The index already lives in
	// plaintext inside the enclave on the sealed volume, so this adds no
	// exposure beyond what node names have; it is only ever returned on the
	// owner-gated list endpoint. Absent on links minted before it existed.
	Secret string   `json:"secret,omitempty"`
	Mode   string   `json:"mode"`            // open | restricted
	Attrs  []string `json:"attrs,omitempty"` // restricted: required attributes
	Label  string   `json:"label,omitempty"` // owner's note

	// PaidAttrs are the required attributes the marketplace charges for,
	// spelled as the reservation expects them (namespaced). They are
	// proven from the recipient's token rather than typed in, and
	// BillingGrant is the sharer's promise to pay for exactly them.
	//
	// A grant is single-use and bound to one OAuth client, so it funds ONE
	// recipient: a link handed to a second person needs re-arming (see
	// handleRearmLinkBilling). BillingExpires is the platform's own
	// expiry, restated here so the pre-sign-in preview can withhold a
	// grant that would only be refused.
	PaidAttrs      []string `json:"paid_attrs,omitempty"`
	BillingGrant   string   `json:"billing_grant,omitempty"`
	BillingExpires string   `json:"billing_expires,omitempty"` // RFC3339
	BillingCredits int64    `json:"billing_credits,omitempty"`

	// ProvenAttrs maps a required attribute, in the Attrs spelling, to the
	// claim that proves it. Its presence is what makes a requirement
	// PROVEN: everything else is a value the visitor may simply assert.
	//
	// It is resolved once, when the link is created, and never re-derived.
	// A link outlives a deploy and outlives the catalogue it was priced
	// against, so a link that meant "a birth date certified against a
	// passport" must go on meaning that after the registry reprices, adds
	// a self-asserted twin or renames a row. Recording it also means the
	// redeem path reads one exact claim rather than guessing a spelling.
	//
	// Absent on links created before it existed; see provenClaims, which
	// reads their meaning back off the referential rather than assuming
	// the cheaper one.
	ProvenAttrs map[string]string `json:"proven_attrs,omitempty"`
}

const (
	linkModeOpen       = "open"
	linkModeRestricted = "restricted"
)

// Billing states a sharer's client can act on: funded means a grant is
// armed for the next recipient, free means the chosen attributes cost
// nothing to disclose, expired means the promise lapsed before anyone
// opened the link, and unavailable means no one could be billed here (no
// marketplace configured, or a sharer with no payer authority) so the
// attributes stay self-asserted.
const (
	billingFunded      = "funded"
	billingFree        = "free"
	billingExpired     = "expired"
	billingUnavailable = "unavailable"
)

// linkBillingTTL is how long a funding promise stays open. A share link
// is opened when the recipient gets round to it, not when it is created,
// so the grant takes the longest window the platform allows (its own
// ceiling is 24h); past that the sharer re-arms.
const linkBillingTTL = 24 * time.Hour

// --- Owner: create / list -------------------------------------------------

type createLinkRequest struct {
	Mode               string   `json:"mode"`                // open | restricted
	Scope              []string `json:"scope"`               // default ["read"]
	RequiredAttributes []string `json:"required_attributes"` // restricted
	ExpiresUnix        int64    `json:"expires_unix,omitempty"`
	Label              string   `json:"label,omitempty"`
}

type createLinkResponse struct {
	ID                 string   `json:"id"`
	Secret             string   `json:"secret"` // returned exactly once
	Mode               string   `json:"mode"`
	Scope              []string `json:"scope"`
	NodeID             string   `json:"node_id"`
	RequiredAttributes []string `json:"required_attributes,omitempty"`
	ExpiresAt          *string  `json:"expires_at,omitempty"`
	// What this share costs its creator, and for which attributes. The
	// sharer is told after the fact as well as before (the quote
	// endpoint) because the price is only fixed once the grant exists.
	PaidAttributes []string `json:"paid_attributes,omitempty"`
	BillingState   string   `json:"billing_state,omitempty"`
	BillingCredits int64    `json:"billing_credits,omitempty"`
	BillingExpires string   `json:"billing_grant_expires_at,omitempty"`
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if _, err := s.Store.GetNode(r.Context(), tenantID, nodeID); err != nil {
		writeStoreError(w, err)
		return
	}
	var req createLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode == "" {
		mode = linkModeOpen
	}
	if mode != linkModeOpen && mode != linkModeRestricted {
		httpError(w, http.StatusBadRequest, errors.New("mode must be open or restricted"))
		return
	}
	scope := normaliseLinkScope(req.Scope)

	secretBytes, err := crypto.RandomKey()
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	sum := sha256.Sum256(secretBytes)
	meta := linkMeta{SecretHash: hex.EncodeToString(sum[:]), Secret: secret, Mode: mode, Label: req.Label}
	if mode == linkModeRestricted {
		meta.Attrs = req.RequiredAttributes
	}
	// Fund the disclosure before the link exists: a link whose attributes
	// look required but cannot be proven is worse than no link at all.
	state, err := s.armLinkBilling(r.Context(), p, &meta)
	if err != nil {
		writeMarketError(w, err)
		return
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}

	g := &grants.Grant{
		TenantID:  tenantID,
		NodeID:    nodeID,
		Subject:   grants.SubjectLink,
		Scope:     scope,
		CreatedBy: p.Sub,
		Meta:      string(metaJSON),
	}
	var expIso *string
	if req.ExpiresUnix > 0 {
		t := time.Unix(req.ExpiresUnix, 0).UTC()
		g.ExpiresAt = &t
		iso := t.Format(time.RFC3339)
		expIso = &iso
	}
	if err := s.Grants.Create(r.Context(), g); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusCreated, createLinkResponse{
		ID:                 g.ID,
		Secret:             secret,
		Mode:               mode,
		Scope:              scopeStrings(scope),
		NodeID:             nodeID,
		RequiredAttributes: meta.Attrs,
		ExpiresAt:          expIso,
		PaidAttributes:     meta.PaidAttrs,
		BillingState:       state,
		BillingCredits:     meta.BillingCredits,
		BillingExpires:     meta.BillingExpires,
	})
}

// armLinkBilling prices the attributes the sharer chose and, when any of
// them is billable, mints a billing grant against the SHARER's own
// account, "the inviter pays". It reports the resulting billing state
// and writes the grant into meta.
//
// The two ways it declines both leave nobody billed rather than moving
// the charge somewhere nobody agreed to:
//
//   - No marketplace configured, or a sharer holding no platform token
//     (the payer is resolved from the token, so a sealed-session sharer
//     has no account to charge): the attributes stay self-asserted,
//     exactly as restricted links worked before billing existed.
//   - An attribute the catalogue does not price, such as the profile
//     fields a sharer has always been able to ask for, is not billable
//     and is left self-asserted rather than failing the share.
//
// A marketplace that refuses to mint is different: that is a share the
// sharer asked to pay for and could not, so it fails. So is a sharer who
// asked for a government-backed attribute on an instance that cannot buy
// one: storing it would leave a requirement any typed value satisfies,
// which is the opposite of what they asked for.
func (s *Server) armLinkBilling(ctx context.Context, p *Principal, meta *linkMeta) (string, error) {
	meta.PaidAttrs, meta.ProvenAttrs = nil, nil
	meta.BillingGrant, meta.BillingExpires, meta.BillingCredits = "", "", 0
	if len(meta.Attrs) == 0 {
		return "", nil
	}
	m := s.marketClient()
	if m == nil || p.Bearer == "" {
		if err := s.refuseUnbuyableAssurance(ctx, meta.Attrs, m != nil); err != nil {
			return "", err
		}
		return billingUnavailable, nil
	}
	ref, err := s.AttrRef.Load(ctx)
	if err != nil {
		return "", err
	}
	catalogue, err := m.Catalogue(ctx, p.Bearer)
	if err != nil {
		return "", err
	}
	// Store the catalogue's spelling from here on: the reservation the
	// recipient's sign-in triggers resolves attributes by namespace, so a
	// share funded under a bare name would be refused at the till.
	attrs, paid, proven, err := canonicaliseAttributes(ref, catalogue, meta.Attrs)
	if err != nil {
		return "", err
	}
	meta.Attrs, meta.ProvenAttrs = attrs, proven
	if len(paid) == 0 {
		return billingFree, nil
	}
	g, err := s.mintLinkBillingGrant(ctx, p, paid)
	if err != nil {
		return "", err
	}
	meta.PaidAttrs = paid
	meta.BillingGrant = g.ID
	meta.BillingExpires = g.ExpiresAt.UTC().Format(time.RFC3339)
	meta.BillingCredits = g.QuotedCredits
	return billingFunded, nil
}

// errNoReferential is the fail-closed answer to an instance that can bill
// for attributes but cannot read what assurance each key carries.
var errNoReferential = errors.New("the attribute referential is unreachable, so the assurance of the required attributes cannot be established")

// refuseUnbuyableAssurance rejects a share whose sharer asked for a
// government-backed attribute that this instance cannot buy: a
// marketplace is configured but the caller holds no platform token to be
// charged (a sealed-session sharer), or there is no marketplace at all.
//
// The attribute would otherwise be stored bare and unpaid, and a bare
// requirement is one the visitor types in, so the sharer would get the
// self-asserted answer they explicitly declined. Refusing names the
// problem while they can still pick the free key instead.
//
// Where neither a marketplace nor an issuer is reachable, an off-platform
// instance keeps what restricted links did before billing existed: a
// self-asserted form, with nobody billed and nothing claimed to be proven.
func (s *Server) refuseUnbuyableAssurance(ctx context.Context, chosen []string, haveMarket bool) error {
	if s.AttrRef == nil {
		if haveMarket {
			return errNoReferential
		}
		return nil
	}
	ref, err := s.AttrRef.Load(ctx)
	if err != nil {
		if haveMarket {
			return err
		}
		return nil
	}
	for _, c := range chosen {
		if a, ok := ref.Lookup(strings.TrimSpace(c)); ok && a.GovBacked() {
			return badChoice("cannot require %q here: a government-backed attribute is a paid disclosure, and %s", a.Key, whyNoPayer(haveMarket))
		}
	}
	return nil
}

func whyNoPayer(haveMarket bool) string {
	if haveMarket {
		return "this share carries no platform token to charge"
	}
	return "this instance has no attribute marketplace"
}

// provenClaims is what each required attribute must be proven by, keyed
// by the spelling the link stores.
//
// New links carry the answer (linkMeta.ProvenAttrs), frozen at creation.
// A link created before that field existed carries only its paid set, and
// a paid attribute is always proven, so the claim is read back off the
// referential: "privasys:birthdate" is disclosed as "birthdate_id", while
// "privasys:document_valid" has no self-asserted reading and stays bare.
// That is a lookup, not a guess, and it preserves what those links have
// always meant.
//
// A referential Drive cannot reach leaves a stored link's meaning
// undecidable, so the redeem fails rather than falling back on the
// cheaper reading.
func (s *Server) provenClaims(ctx context.Context, meta *linkMeta) (map[string]string, error) {
	if meta.ProvenAttrs != nil {
		return meta.ProvenAttrs, nil
	}
	if len(meta.PaidAttrs) == 0 {
		return nil, nil
	}
	ref, err := s.AttrRef.Load(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(meta.PaidAttrs))
	for _, k := range meta.PaidAttrs {
		if ca, ok := ref.ForMarketplaceKey(k); ok {
			out[k] = ca.Key
			continue
		}
		// Outside the referential's namespace there is no twin to be told
		// apart from, so the row's own name is the claim.
		if _, after, found := strings.Cut(k, ":"); found {
			out[k] = after
			continue
		}
		out[k] = k
	}
	return out, nil
}

// billingStateOf reports where a stored link's funding stands now. A
// lapsed promise is called out rather than served, because a recipient
// who carried an expired grant into their sign-in would be refused with
// no way to know why.
func (m *linkMeta) billingStateOf(now time.Time) string {
	if len(m.PaidAttrs) == 0 {
		return ""
	}
	if m.BillingGrant == "" {
		return billingUnavailable
	}
	if exp, err := time.Parse(time.RFC3339, m.BillingExpires); err == nil && !exp.After(now) {
		return billingExpired
	}
	return billingFunded
}

type linkView struct {
	ID                 string   `json:"id"`
	Mode               string   `json:"mode"`
	Scope              []string `json:"scope"`
	Label              string   `json:"label,omitempty"`
	RequiredAttributes []string `json:"required_attributes,omitempty"`
	CreatedAt          string   `json:"created_at"`
	ExpiresAt          *string  `json:"expires_at,omitempty"`
	Revoked            bool     `json:"revoked"`
	// Secret lets the owner re-copy the full link; empty for links minted
	// before secrets were kept. This endpoint is canShare-gated.
	Secret string `json:"secret,omitempty"`
	// What the link is costing its creator, and whether the next
	// recipient is still funded ("Active links" is where a sharer
	// notices a lapsed grant and re-arms).
	PaidAttributes []string `json:"paid_attributes,omitempty"`
	BillingState   string   `json:"billing_state,omitempty"`
	BillingCredits int64    `json:"billing_credits,omitempty"`
	BillingExpires string   `json:"billing_grant_expires_at,omitempty"`
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	nodeID := r.PathValue("nodeID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	gs, err := s.Grants.ListForNode(r.Context(), tenantID, nodeID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]linkView, 0)
	for _, g := range gs {
		if g.Subject != grants.SubjectLink {
			continue
		}
		var meta linkMeta
		_ = json.Unmarshal([]byte(g.Meta), &meta)
		lv := linkView{
			ID: g.ID, Mode: meta.Mode, Scope: scopeStrings(g.Scope),
			Label: meta.Label, RequiredAttributes: meta.Attrs,
			CreatedAt: g.CreatedAt.UTC().Format(time.RFC3339),
			Revoked:   g.RevokedAt != nil,
			Secret:    meta.Secret,

			PaidAttributes: meta.PaidAttrs,
			BillingState:   meta.billingStateOf(time.Now().UTC()),
			BillingCredits: meta.BillingCredits,
			BillingExpires: meta.BillingExpires,
		}
		if g.ExpiresAt != nil {
			iso := g.ExpiresAt.UTC().Format(time.RFC3339)
			lv.ExpiresAt = &iso
		}
		out = append(out, lv)
	}
	writeJSON(w, http.StatusOK, map[string]any{"links": out})
}

// --- Recipient: resolve / redeem -----------------------------------------

type redeemLinkRequest struct {
	Secret     string            `json:"secret"`
	Attributes map[string]string `json:"attributes,omitempty"` // restricted: presented profile
}

// loadLink fetches an active `link` grant and constant-time-verifies the
// presented secret against the stored hash.
func (s *Server) loadLink(ctx context.Context, linkID, secret string) (*grants.Grant, *linkMeta, error) {
	g, err := s.Grants.Get(ctx, linkID)
	if err != nil {
		return nil, nil, err
	}
	if g.Subject != grants.SubjectLink || !g.IsActive(time.Now().UTC()) {
		return nil, nil, store.ErrNotFound
	}
	var meta linkMeta
	if err := json.Unmarshal([]byte(g.Meta), &meta); err != nil {
		return nil, nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(secret))
	if err != nil {
		return nil, nil, errLinkSecret
	}
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(meta.SecretHash)) != 1 {
		return nil, nil, errLinkSecret
	}
	return g, &meta, nil
}

var errLinkSecret = errors.New("invalid or expired link")

// previewLinkResponse is the pre-sign-in view of a link: what the
// visitor must prove, and who is paying for it.
type previewLinkResponse struct {
	LinkID             string   `json:"link_id"`
	Mode               string   `json:"mode"`
	RequiredAttributes []string `json:"required_attributes,omitempty"`
	PaidAttributes     []string `json:"paid_attributes,omitempty"`
	// AttributeClaims names, per required attribute, the canonical claim
	// the visitor's sign-in has to disclose. The link stores the registry
	// spelling ("privasys:birthdate"), which the IdP does not accept and
	// which is not the key it mints the disclosure under ("birthdate_id"),
	// so a client that asked with the stored spelling would request
	// nothing and one that stripped the namespace would request the
	// self-asserted twin. Absent on links created before it was recorded.
	AttributeClaims map[string]string `json:"attribute_claims,omitempty"`
	BillingGrant    string            `json:"billing_grant,omitempty"`
	BillingState    string            `json:"billing_state,omitempty"`
	BillingExpires  string            `json:"billing_grant_expires_at,omitempty"`
}

// handlePreviewLink serves the one thing a visitor needs BEFORE they
// have signed in: which attributes the link requires, and the billing
// grant that funds the paid ones. The grant id has to reach the IdP as
// the `billing_grant` parameter on the visitor's /authorize request,
// which is what makes the sharer, rather than the OAuth client's owner,
// pay for the disclosure, and by then it is far too late to ask an
// endpoint that needs a session.
//
// Unauthenticated for exactly that reason, and sound because the link
// secret IS the authority: this is the same POST body that opens the
// link for a signed-in caller, checked the same way. It answers with
// strictly less than resolve does (no node, no owner, no tenant), so
// holding the secret buys nothing extra by skipping the sign-in.
//
// Drive's responsibility ends here. Putting the id on the authorize URL
// belongs to whoever runs the sign-in, and the @privasys/auth SDK has no
// way to add a parameter to that request today: it builds the query from
// a fixed list. Until it can, a funded share still charges the OAuth
// client's owner, because the IdP never learns the grant exists.
func (s *Server) handlePreviewLink(w http.ResponseWriter, r *http.Request) {
	var req redeemLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	g, meta, err := s.loadLink(r.Context(), r.PathValue("linkID"), req.Secret)
	if err != nil {
		writeLinkError(w, err)
		return
	}
	out := previewLinkResponse{
		LinkID:             g.ID,
		Mode:               meta.Mode,
		RequiredAttributes: meta.Attrs,
		PaidAttributes:     meta.PaidAttrs,
		AttributeClaims:    meta.ProvenAttrs,
		BillingState:       meta.billingStateOf(time.Now().UTC()),
		BillingExpires:     meta.BillingExpires,
	}
	// A lapsed grant is withheld, not passed on: spending it would fail
	// the sign-in with a billing error the visitor cannot act on, whereas
	// the state tells their client to ask the sharer to re-arm.
	if out.BillingState == billingFunded {
		out.BillingGrant = meta.BillingGrant
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRearmLinkBilling mints a fresh billing grant on an existing
// link, charged to the sharer calling it.
//
// A grant funds ONE sign-in, so this is how a link reaches a second
// recipient: cost scales per person, which is the honest shape of "the
// inviter pays" and the reason it is an explicit act rather than
// something Drive does on the sharer's behalf. It is also the repair for
// a grant that expired before anyone opened the link.
func (s *Server) handleRearmLinkBilling(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	g, err := s.Grants.Get(r.Context(), r.PathValue("linkID"))
	if err != nil || g.TenantID != tenantID || g.Subject != grants.SubjectLink || !g.IsActive(time.Now().UTC()) {
		httpError(w, http.StatusNotFound, errLinkSecret)
		return
	}
	var meta linkMeta
	if err := json.Unmarshal([]byte(g.Meta), &meta); err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if len(meta.PaidAttrs) == 0 {
		httpError(w, http.StatusBadRequest, errors.New("this link requires no paid attributes"))
		return
	}
	// Re-price against the attributes the link already commits to, not
	// against anything the caller sends: re-arming funds the share that
	// exists, it does not redefine it.
	grant, err := s.mintLinkBillingGrant(r.Context(), p, meta.PaidAttrs)
	if err != nil {
		writeMarketError(w, err)
		return
	}
	meta.BillingGrant = grant.ID
	meta.BillingExpires = grant.ExpiresAt.UTC().Format(time.RFC3339)
	meta.BillingCredits = grant.QuotedCredits
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	err = s.Grants.UpdateMeta(r.Context(), tenantID, g.ID, string(metaJSON))
	if errors.Is(err, sql.ErrNoRows) {
		// Revoked between the read and the write. The grant just minted is
		// the sharer's to lose; the link it was for no longer exists.
		httpError(w, http.StatusNotFound, errLinkSecret)
		return
	}
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"link_id":                  g.ID,
		"billing_state":            billingFunded,
		"billing_credits":          meta.BillingCredits,
		"billing_grant_expires_at": meta.BillingExpires,
		"paid_attributes":          meta.PaidAttrs,
	})
}

func (s *Server) handleResolveLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	linkID := r.PathValue("linkID")
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("sign in to open this link"))
		return
	}
	var req redeemLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	g, meta, err := s.loadLink(r.Context(), linkID, req.Secret)
	if err != nil {
		writeLinkError(w, err)
		return
	}
	n, err := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	// Whether this caller already has access (previously redeemed).
	granted := false
	if ag, aerr := s.Grants.ActiveForSubjectOnNode(r.Context(), g.TenantID, g.NodeID, p.Sub); aerr == nil && ag != nil {
		granted = true
	}
	// Restricted: surface any pending request state for this caller.
	requestStatus := ""
	if meta.Mode == linkModeRestricted {
		if lr, lerr := s.Store.PendingLinkRequestFor(r.Context(), g.ID, p.Sub); lerr == nil && lr != nil {
			requestStatus = lr.Status
		}
	}
	ownerName := ""
	if t, terr := s.Store.GetTenant(r.Context(), g.TenantID); terr == nil {
		ownerName = t.Name
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"link_id":             g.ID,
		"mode":                meta.Mode,
		"scope":               scopeStrings(g.Scope),
		"required_attributes": meta.Attrs,
		// Which of them the visitor must have PROVEN (they come off the
		// token, so a visitor who signed in without them has to sign in
		// again rather than fill a form in), and the claim each one is
		// proven by, which is what a step-up asks the wallet for.
		"paid_attributes":  meta.PaidAttrs,
		"attribute_claims": meta.ProvenAttrs,
		"billing_state":    meta.billingStateOf(time.Now().UTC()),
		"tenant_id":        g.TenantID,
		"owner_name":       ownerName,
		"already_granted":  granted,
		"request_status":   requestStatus,
		"node": map[string]any{
			"id": n.ID, "name": n.Name, "kind": string(n.Kind), "size_bytes": n.PlainSize,
		},
	})
}

func (s *Server) handleRedeemLink(w http.ResponseWriter, r *http.Request, p *Principal) {
	linkID := r.PathValue("linkID")
	if !p.IsUser() {
		httpError(w, http.StatusForbidden, errors.New("sign in to open this link"))
		return
	}
	var req redeemLinkRequest
	if err := readJSON(r, &req); err != nil {
		httpError(w, http.StatusBadRequest, err)
		return
	}
	g, meta, err := s.loadLink(r.Context(), linkID, req.Secret)
	if err != nil {
		writeLinkError(w, err)
		return
	}
	n, err := s.Store.GetNode(r.Context(), g.TenantID, g.NodeID)
	if err != nil {
		writeStoreError(w, err)
		return
	}

	// Idempotent: an existing grant means access is already in place.
	if ag, aerr := s.Grants.ActiveForSubjectOnNode(r.Context(), g.TenantID, g.NodeID, p.Sub); aerr == nil && ag != nil {
		writeJSON(w, http.StatusOK, redeemResult("granted", g, n, ""))
		return
	}

	switch meta.Mode {
	case linkModeOpen:
		if _, err := s.mintSubjectGrant(r.Context(), g.TenantID, g.NodeID, p.Sub, g.Scope, g.ID); err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, redeemResult("granted", g, n, ""))
	case linkModeRestricted:
		// Every required attribute must be presented, else no request is
		// filed: a half-empty request would push an undecidable card at
		// the owner. The front tells the visitor what is missing.
		proven, err := s.provenClaims(r.Context(), meta)
		if err != nil {
			writeMarketError(w, err)
			return
		}
		presented, missing := linkAttributeEvidence(p, meta, proven, req.Attributes)
		if len(missing) > 0 {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":              "missing required attributes: " + strings.Join(missing, ", "),
				"missing_attributes": missing,
			})
			return
		}
		// PII boundary (§7.6): the presented attributes ride out to the
		// sharer's wallet in the notification and are NOT persisted —
		// the drive keeps only the sub, scope and timestamps.
		lr := &store.LinkRequest{
			TenantID: g.TenantID, LinkID: g.ID, NodeID: g.NodeID,
			RequesterSub: p.Sub,
			Scope:        joinScopeStrings(g.Scope),
		}
		err = s.Store.CreateLinkRequest(r.Context(), lr)
		if errors.Is(err, store.ErrDuplicateApproval) {
			// Already requested; report the current pending state.
			writeJSON(w, http.StatusOK, redeemResult("pending", g, n, ""))
			return
		}
		if err != nil {
			httpError(w, http.StatusInternalServerError, err)
			return
		}
		s.Notifier().Fire(g.CreatedBy, "share-request", map[string]any{
			"tenant_id":     g.TenantID,
			"request_id":    lr.ID,
			"node_id":       g.NodeID,
			"node_name":     n.Name,
			"requester_sub": p.Sub,
			"attributes":    presented,
			"scope":         scopeStrings(g.Scope),
		})
		writeJSON(w, http.StatusOK, redeemResult("pending", g, n, lr.ID))
	default:
		httpError(w, http.StatusInternalServerError, errors.New("unknown link mode"))
	}
}

func redeemResult(status string, g *grants.Grant, n *store.Node, requestID string) map[string]any {
	out := map[string]any{
		"status":    status,
		"tenant_id": g.TenantID,
		"node_id":   g.NodeID,
		"name":      n.Name,
		"kind":      string(n.Kind),
	}
	if requestID != "" {
		out["request_id"] = requestID
	}
	return out
}

// --- Owner: restricted-request review ------------------------------------

type linkRequestView struct {
	ID         string            `json:"id"`
	NodeID     string            `json:"node_id"`
	NodeName   string            `json:"node_name"`
	Requester  string            `json:"requester_sub"`
	Attributes map[string]string `json:"attributes"`
	Scope      []string          `json:"scope"`
	Status     string            `json:"status"`
	CreatedAt  string            `json:"created_at"`
}

func (s *Server) handleListLinkRequests(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	status := r.URL.Query().Get("status")
	rs, err := s.Store.ListLinkRequests(r.Context(), tenantID, status)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]linkRequestView, 0, len(rs))
	for _, lr := range rs {
		var attrs map[string]string
		_ = json.Unmarshal([]byte(lr.Attributes), &attrs)
		name := ""
		if n, nerr := s.Store.GetNode(r.Context(), tenantID, lr.NodeID); nerr == nil {
			name = n.Name
		}
		out = append(out, linkRequestView{
			ID: lr.ID, NodeID: lr.NodeID, NodeName: name, Requester: lr.RequesterSub,
			Attributes: attrs, Scope: scopeStrings(splitScopeStrings(lr.Scope)), Status: lr.Status,
			CreatedAt: lr.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"requests": out})
}

func (s *Server) handleDecideLinkRequest(w http.ResponseWriter, r *http.Request, p *Principal) {
	tenantID := r.PathValue("tenantID")
	reqID := r.PathValue("reqID")
	decision := r.PathValue("decision")
	if !p.IsUser() || !s.canShare(r.Context(), tenantID, p.Sub) {
		httpError(w, http.StatusForbidden, errors.New("forbidden"))
		return
	}
	if decision != "approve" && decision != "deny" {
		httpError(w, http.StatusBadRequest, errors.New("decision must be approve or deny"))
		return
	}
	lr, err := s.Store.GetLinkRequest(r.Context(), tenantID, reqID)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	if lr.Status != "pending" {
		httpError(w, http.StatusConflict, errors.New("request already decided"))
		return
	}
	nodeName := ""
	if n, nerr := s.Store.GetNode(r.Context(), tenantID, lr.NodeID); nerr == nil {
		nodeName = n.Name
	}
	if decision == "deny" {
		if err := s.Store.DecideLinkRequest(r.Context(), tenantID, reqID, "denied", "", p.Sub); err != nil {
			writeStoreError(w, err)
			return
		}
		s.Notifier().Fire(lr.RequesterSub, "share-decision", map[string]any{
			"tenant_id": tenantID, "request_id": reqID,
			"node_id": lr.NodeID, "node_name": nodeName, "status": "denied",
		})
		writeJSON(w, http.StatusOK, map[string]any{"status": "denied"})
		return
	}
	// Approve: mint the recipient's grant, then record the decision.
	g, err := s.mintSubjectGrant(r.Context(), tenantID, lr.NodeID, lr.RequesterSub, splitScopeStrings(lr.Scope), lr.LinkID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	if err := s.Store.DecideLinkRequest(r.Context(), tenantID, reqID, "approved", g.ID, p.Sub); err != nil {
		writeStoreError(w, err)
		return
	}
	s.Notifier().Fire(lr.RequesterSub, "share-decision", map[string]any{
		"tenant_id": tenantID, "request_id": reqID,
		"node_id": lr.NodeID, "node_name": nodeName, "status": "approved",
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "grant_id": g.ID})
}

// --- helpers --------------------------------------------------------------

// linkAttributeEvidence collects what the visitor actually has for each
// required attribute, and names the ones they do not.
//
// A PROVEN attribute is read from the visitor's verified token, from the
// exact claim the link recorded when it was created, and a typed-in value
// for it is ignored: honouring one would make the sharer's payment buy
// nothing, and would let a visitor who asked their own wallet for the
// self-asserted twin open a link that requires the passport reading.
// Everything else stays self-asserted, which is what a restricted link
// has always asked for.
//
// The returned map is the evidence that rides out to the sharer's wallet
// in the notification (§7.6) and is never persisted here.
func linkAttributeEvidence(p *Principal, meta *linkMeta, proven map[string]string, claimed map[string]string) (map[string]string, []string) {
	evidence := make(map[string]string, len(meta.Attrs))
	var missing []string
	for _, k := range meta.Attrs {
		var v string
		if claim, mustProve := proven[k]; mustProve {
			v = attributeClaim(p.ID, claim)
		} else {
			v = strings.TrimSpace(claimed[k])
		}
		if v == "" {
			missing = append(missing, k)
			continue
		}
		evidence[k] = v
	}
	return evidence, missing
}

// mintSubjectGrant creates a per-recipient read/write grant on a node,
// noting the originating link in Meta for audit.
func (s *Server) mintSubjectGrant(ctx context.Context, tenantID, nodeID, sub string, scope []grants.Scope, linkID string) (*grants.Grant, error) {
	meta, _ := json.Marshal(map[string]string{"via_link": linkID})
	g := &grants.Grant{
		TenantID:  tenantID,
		NodeID:    nodeID,
		Subject:   grants.SubjectUser + sub,
		Scope:     scope,
		CreatedBy: "link:" + linkID,
		Meta:      string(meta),
	}
	if err := s.Grants.Create(ctx, g); err != nil {
		return nil, err
	}
	return g, nil
}

func normaliseLinkScope(in []string) []grants.Scope {
	want := map[string]bool{}
	for _, s := range in {
		want[strings.ToLower(strings.TrimSpace(s))] = true
	}
	out := []grants.Scope{grants.ScopeRead}
	if want["write"] {
		out = append(out, grants.ScopeWrite)
	}
	return out
}

func scopeStrings(ss []grants.Scope) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, string(s))
	}
	return out
}

func joinScopeStrings(ss []grants.Scope) string {
	return strings.Join(scopeStrings(ss), ",")
}

func splitScopeStrings(s string) []grants.Scope {
	var out []grants.Scope
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, grants.Scope(p))
		}
	}
	if len(out) == 0 {
		out = []grants.Scope{grants.ScopeRead}
	}
	return out
}

func writeLinkError(w http.ResponseWriter, err error) {
	if errors.Is(err, errLinkSecret) || errors.Is(err, store.ErrNotFound) {
		httpError(w, http.StatusNotFound, errLinkSecret)
		return
	}
	httpError(w, http.StatusInternalServerError, err)
}

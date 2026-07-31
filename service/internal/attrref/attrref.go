// Package attrref reads the canonical attribute referential the IdP
// serves at /referential/canonical-attributes.json.
//
// It answers the one question the marketplace catalogue cannot: which
// keys are government-backed, and which of those name a field that also
// has a self-asserted reading. The catalogue rows for
// "privasys:given_name" (a passport first name) and "privasys:age_over_18"
// (a derived boolean nobody can type) are the same shape, because a row is
// named for the field the ENCLAVE meters; only the referential knows that
// the first has a twin the holder types and the second does not. Without
// that, a bare "given_name" resolves onto the priced passport row and a
// chosen "given_name_id" resolves onto nothing at all.
//
// The referential is NOT a pricing source and must never be used as one.
// Namespacing and price come from the live catalogue, which covers the
// third-party providers this document does not (see canonicaliseAttributes).
//
// It is fetched rather than vendored on purpose. A compiled-in copy is a
// fourth transcription of a document the auth SDK, the wallet and the IdP
// already share, and a stale one fails in the dangerous direction: a pair
// added after this build would read as an unpaired government key, which
// is exactly the mistake this package exists to prevent.
package attrref

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// The registry's assurance vocabulary, as the referential spells it. Not
// the none/provider/gov ladder the IdP puts on a token.
const (
	SelfAsserted = "self_asserted"
	GovVerified  = "gov_verified"
)

// Marketplace is the registry-facing half of an attribute: the
// "<namespace>:<name>" spelling a reservation and a billing grant must
// agree on. It is not "privasys:" + Key, because the registry names the
// metered field: "given_name_id" is sold as "privasys:given_name".
type Marketplace struct {
	Key      string `json:"key"`
	Billable bool   `json:"billable"`
}

// Attribute is one canonical attribute, reduced to the fields Drive
// reasons about.
type Attribute struct {
	Key string `json:"key"`
	// Scope carries the assurance fallback for a document older than this
	// build: an identity-scope key with no stated assurance is
	// government-backed, and reading it as self-asserted would let a typed
	// value satisfy a passport requirement.
	Scope       string       `json:"scope"`
	Assurance   string       `json:"assurance"`
	GovKey      string       `json:"govKey"`
	Marketplace *Marketplace `json:"marketplace"`
}

// AssuranceLevel is this key's own assurance, with the fallback the
// schema defines.
func (a Attribute) AssuranceLevel() string {
	if a.Assurance != "" {
		return a.Assurance
	}
	if a.Scope == "identity" {
		return GovVerified
	}
	return SelfAsserted
}

// GovBacked reports whether disclosing this key discloses something a
// government document evidenced. This, not the "_id" suffix, is the
// distinction: document_valid and age_over_18 carry no suffix and are
// government-backed all the same.
func (a Attribute) GovBacked() bool { return a.AssuranceLevel() == GovVerified }

// MarketplaceKey is the spelling the registry sells this attribute under,
// or "" when it sells no such disclosure.
func (a Attribute) MarketplaceKey() string {
	if a.Marketplace == nil {
		return ""
	}
	return a.Marketplace.Key
}

// Referential is a parsed document, indexed both ways: by canonical key
// (what a picker chooses and what the IdP mints a claim under) and by
// marketplace key (what a link stores and a reservation is priced
// against).
type Referential struct {
	byKey    map[string]Attribute
	byMarket map[string]Attribute
}

// Parse reads the document the IdP serves.
func Parse(raw []byte) (*Referential, error) {
	var doc struct {
		Attributes []Attribute `json:"attributes"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("attribute referential: %w", err)
	}
	if len(doc.Attributes) == 0 {
		return nil, fmt.Errorf("attribute referential: no attributes")
	}
	r := &Referential{
		byKey:    make(map[string]Attribute, len(doc.Attributes)),
		byMarket: make(map[string]Attribute, len(doc.Attributes)),
	}
	for _, a := range doc.Attributes {
		if a.Key == "" {
			continue
		}
		r.byKey[a.Key] = a
		if mk := a.MarketplaceKey(); mk != "" {
			r.byMarket[mk] = a
		}
	}
	return r, nil
}

// Lookup finds an attribute by canonical key.
func (r *Referential) Lookup(key string) (Attribute, bool) {
	if r == nil {
		return Attribute{}, false
	}
	a, ok := r.byKey[key]
	return a, ok
}

// ForMarketplaceKey finds the canonical attribute a registry row sells.
// It is how a stored link key ("privasys:birthdate") reaches the claim
// that proves it ("birthdate_id").
func (r *Referential) ForMarketplaceKey(key string) (Attribute, bool) {
	if r == nil {
		return Attribute{}, false
	}
	a, ok := r.byMarket[key]
	return a, ok
}

// Client fetches the referential from an issuer and holds it for a while.
// The document changes when an attribute is added, which is a release
// event, so a short cache costs nothing and keeps a share dialog from
// making a round trip per keystroke.
type Client struct {
	BaseURL string
	HC      *http.Client
	TTL     time.Duration

	mu      sync.Mutex
	cached  *Referential
	fetched time.Time
}

// DefaultTTL is how long a fetched referential is reused.
const DefaultTTL = 10 * time.Minute

// New returns a client for an issuer, or nil when there is none to ask.
func New(issuerURL string) *Client {
	if issuerURL == "" {
		return nil
	}
	return &Client{
		BaseURL: strings.TrimRight(issuerURL, "/"),
		HC:      &http.Client{Timeout: 10 * time.Second},
		TTL:     DefaultTTL,
	}
}

// Load returns the referential, fetching it when the cached copy has
// aged out. A failure is returned rather than papered over with the stale
// copy: the caller refuses the share, which is the fail-closed answer to
// not knowing what assurance the sharer asked for.
func (c *Client) Load(ctx context.Context) (*Referential, error) {
	if c == nil {
		return nil, fmt.Errorf("attribute referential: no issuer configured")
	}
	ttl := c.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	c.mu.Lock()
	if c.cached != nil && time.Since(c.fetched) < ttl {
		defer c.mu.Unlock()
		return c.cached, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.BaseURL+"/referential/canonical-attributes.json", nil)
	if err != nil {
		return nil, err
	}
	hc := c.HC
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("attribute referential: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("attribute referential: %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	ref, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.cached, c.fetched = ref, time.Now()
	c.mu.Unlock()
	return ref, nil
}

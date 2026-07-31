// Package attrbilling reaches the platform's attribute marketplace on
// behalf of the user doing the asking: the catalogue of disclosable
// attributes, what a chosen set costs, and the billing grant that funds
// one recipient's disclosure.
//
// Every call carries that user's own bearer token, and that is the
// security model rather than a convenience. The control plane resolves
// the payer from the bearer and ignores any payer named in a body, so
// Drive cannot charge an account that did not authorise the charge. It
// can only spend a grant the payer minted themselves.
package attrbilling

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Attribute is one catalogue entry. Key is the namespaced form
// ("privasys:document_valid"): the reservation resolves attributes by
// namespace, so a bare name is refused there and must never be sent.
type Attribute struct {
	Key          string `json:"key"`
	Namespace    string `json:"namespace"`
	Name         string `json:"name"`
	Assurance    string `json:"assurance"` // gov | self
	PriceCredits int64  `json:"price_credits"`
	Description  string `json:"description,omitempty"`
}

// Paid reports whether disclosing a carries a marketplace charge. Only
// paid attributes need funding; a self-asserted one discloses free.
func (a Attribute) Paid() bool { return a.PriceCredits > 0 }

// Line is one chosen attribute priced for display, as returned by both
// the quote and the mint.
type Line struct {
	Key          string `json:"key"`
	Namespace    string `json:"namespace"`
	Assurance    string `json:"assurance"`
	PriceCredits int64  `json:"price_credits"`
}

// Quote is the priced breakdown of a chosen set, shown to the payer
// before they commit to it.
type Quote struct {
	Attributes   []Line `json:"attributes"`
	TotalCredits int64  `json:"total_credits"`
}

// Grant is a minted funding promise. It is single-use and bound to one
// OAuth client, so it funds exactly one sign-in: the id travels to the
// recipient and is spent when their authorization request reserves the
// disclosure.
type Grant struct {
	ID            string    `json:"id"`
	ExpiresAt     time.Time `json:"expires_at"`
	QuotedCredits int64     `json:"quoted_credits"`
	MaxCredits    int64     `json:"max_credits"`
	Attributes    []Line    `json:"attributes"`
}

// Client calls the control plane's marketplace endpoints.
type Client struct {
	BaseURL string
	HC      *http.Client
}

// New returns a client, or nil when no control-plane base URL is
// configured (off-platform: there is no marketplace to ask, and
// required attributes stay self-asserted).
func New(baseURL string) *Client {
	if baseURL == "" {
		return nil
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HC:      &http.Client{Timeout: 20 * time.Second},
	}
}

// StatusError is a non-2xx answer, kept whole. The control plane's
// refusals are actionable to the person choosing the attributes ("unknown
// attribute", "max_credits is below the current price"), so they are
// carried back rather than flattened into "billing failed".
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("attribute marketplace: %d: %s", e.Status, e.Body)
}

// Catalogue lists the attributes a sharer may require, with their prices
// and assurance. Read straight from the platform so a newly published
// attribute appears without a Drive release.
func (c *Client) Catalogue(ctx context.Context, bearer string) ([]Attribute, error) {
	var out struct {
		Attributes []Attribute `json:"attributes"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/attributes", bearer, nil, &out); err != nil {
		return nil, err
	}
	return out.Attributes, nil
}

// Quote prices a chosen set without committing to it.
func (c *Client) Quote(ctx context.Context, bearer string, keys []string) (*Quote, error) {
	var out Quote
	body := map[string]any{"attributes": keys}
	if err := c.do(ctx, http.MethodPost, "/api/v1/attribute-billing-grants/quote", bearer, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Mint issues a billing grant against the bearer's own account for one
// recipient's disclosure at clientID.
//
// max_credits is deliberately omitted: it means "whatever this costs
// when it is spent", which is what a sharer intends. Naming today's
// figure would turn a price change between minting and the recipient
// arriving into a failed sign-in.
func (c *Client) Mint(ctx context.Context, bearer, clientID string, keys []string, ttl time.Duration) (*Grant, error) {
	var out Grant
	body := map[string]any{
		"client_id":   clientID,
		"attributes":  keys,
		"ttl_seconds": int64(ttl / time.Second),
	}
	if err := c.do(ctx, http.MethodPost, "/api/v1/attribute-billing-grants", bearer, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) do(ctx context.Context, method, path, bearer string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HC.Do(req)
	if err != nil {
		return fmt.Errorf("attribute marketplace: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return &StatusError{Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}
	return json.Unmarshal(raw, out)
}

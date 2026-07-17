// Package notify delivers wallet push notifications through the
// platform: the drive authenticates to the control plane with its
// manager-minted attested app identity and asks it to notify one of
// its own users (by the relay-asserted sub). The control plane
// forwards to the IdP, which seals the payload to the user's wallet
// key and sends the push — attributes and node names never persist
// here and never transit third-party push infrastructure in the clear.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// IdentityHeaders supplies fresh attested app-identity headers
// (base64 leaf DER + base64 challenge) for one control-plane call.
type IdentityHeaders func(ctx context.Context) (identityB64, challengeB64 string, err error)

// Client posts notifications to the control plane.
type Client struct {
	BaseURL string // e.g. https://api-test.developer.privasys.org
	Headers IdentityHeaders
	HC      *http.Client
}

// New returns a client, or nil when the base URL or identity source is
// missing (off-platform: notifications are silently unavailable).
func New(baseURL string, headers IdentityHeaders) *Client {
	if baseURL == "" || headers == nil {
		return nil
	}
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Headers: headers,
		HC:      &http.Client{Timeout: 20 * time.Second},
	}
}

// Notify asks the platform to push `typ` with `payload` to the user
// behind sub. Payload values must be JSON-serialisable; the IdP seals
// the whole object to the wallet's registered key.
func (c *Client) Notify(ctx context.Context, sub, typ string, payload map[string]any) error {
	idB64, chB64, err := c.Headers(ctx)
	if err != nil {
		return fmt.Errorf("notify: identity: %w", err)
	}
	body, err := json.Marshal(map[string]any{"sub": sub, "type": typ, "payload": payload})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/api/v1/notify", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Privasys-App-Identity", idB64)
	req.Header.Set("X-Privasys-App-Challenge", chB64)
	resp, err := c.HC.Do(req)
	if err != nil {
		return fmt.Errorf("notify: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("notify: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Fire delivers in the background with a bounded timeout, logging
// failures: a push must never block or fail the user-facing request
// that triggered it.
func (c *Client) Fire(sub, typ string, payload map[string]any) {
	if c == nil || sub == "" {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()
		if err := c.Notify(ctx, sub, typ, payload); err != nil {
			log.Printf("notify: %s to %s…: %v", typ, safePrefix(sub), err)
		}
	}()
}

// safePrefix truncates a sub for logs.
func safePrefix(sub string) string {
	if len(sub) > 8 {
		return sub[:8]
	}
	return sub
}

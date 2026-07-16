package vaultmek

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// identityMinter is the slice of ManagerMinter the token refresher
// needs (an interface so tests can inject a fake).
type identityMinter interface {
	mint(ctx context.Context, challenge []byte) (*tls.Certificate, error)
}

// MgmtTokenRefresher returns a TokenRefresher that fetches a fresh
// aud=attestation-server token from the control plane using the app's
// manager-minted identity: a challenge-bound TDX identity leaf (app id
// at OID 3.6) presented on GET /api/v1/keyvaults/operated behind the
// control plane's app-identity gate. No human secret is involved, so a
// restarted or long-idle instance heals stale vault tokens by itself.
// Returns nil when the client has no manager identity (off-platform).
func (c *Client) MgmtTokenRefresher(mgmtBaseURL string) TokenRefresher {
	if c.minter == nil || mgmtBaseURL == "" {
		return nil
	}
	// The operated response also names the attestation server the token
	// is for; remember it so AttestationCredentials can hand out the
	// full (endpoint, token) pair for other RA-TLS verifications.
	return newMgmtRefresher(mgmtBaseURL, c.minter, nil, func(attServer string) {
		c.tokMu.Lock()
		c.attServer = attServer
		c.tokMu.Unlock()
	})
}

// AttestationCredentials returns the attestation-server endpoint plus a
// currently-valid verification token, refreshing via the control plane
// when the cached token is stale. It reuses the same manager-minted app
// identity as vault operations, so any attested-dependency dial (the
// confidential-AI fleet) verifies peer quotes with no configured
// secret. Errors when no refresher is configured (off-platform).
func (c *Client) AttestationCredentials(ctx context.Context) (server, token string, err error) {
	token = c.cachedFreshToken(time.Now().Unix())
	c.tokMu.Lock()
	server = c.attServer
	c.tokMu.Unlock()
	if token == "" || server == "" {
		if token, err = c.refreshToken(ctx); err != nil {
			return "", "", err
		}
		if token == "" {
			return "", "", fmt.Errorf("vaultmek: no attestation-token refresher configured")
		}
		c.tokMu.Lock()
		server = c.attServer
		c.tokMu.Unlock()
	}
	if server == "" {
		return "", "", fmt.Errorf("vaultmek: control plane did not report an attestation server")
	}
	return server, token, nil
}

// newMgmtRefresher builds the refresher against base (scheme://host)
// with the given minter; hc defaults to a 30s-timeout client. onMeta,
// when non-nil, receives the constellation's attestation-server
// endpoint from each successful refresh.
func newMgmtRefresher(base string, m identityMinter, hc *http.Client, onMeta func(attServer string)) TokenRefresher {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	url := strings.TrimRight(base, "/") + "/api/v1/keyvaults/operated"
	return func(ctx context.Context) (string, int64, error) {
		// The control plane's freshness contract: the first 8 bytes of
		// the challenge are big-endian unix seconds (trustworthy once the
		// quote binds the challenge), the rest anti-replay randomness.
		challenge := make([]byte, 16)
		binary.BigEndian.PutUint64(challenge[:8], uint64(time.Now().Unix()))
		if _, err := rand.Read(challenge[8:]); err != nil {
			return "", 0, err
		}
		cert, err := m.mint(ctx, challenge)
		if err != nil {
			return "", 0, fmt.Errorf("vaultmek: mint identity for token refresh: %w", err)
		}
		if len(cert.Certificate) == 0 {
			return "", 0, fmt.Errorf("vaultmek: minted identity has no leaf")
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("X-Privasys-App-Identity", base64.StdEncoding.EncodeToString(cert.Certificate[0]))
		req.Header.Set("X-Privasys-App-Challenge", base64.StdEncoding.EncodeToString(challenge))
		resp, err := hc.Do(req)
		if err != nil {
			return "", 0, fmt.Errorf("vaultmek: token refresh: %w", err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode/100 != 2 {
			return "", 0, fmt.Errorf("vaultmek: token refresh %s: %s", resp.Status, strings.TrimSpace(string(data)))
		}
		var out struct {
			AttestationToken          string `json:"attestation_token"`
			AttestationTokenExpiresAt int64  `json:"attestation_token_expires_at"`
			Constellation             struct {
				AttestationServer string `json:"attestation_server"`
			} `json:"constellation"`
		}
		if err := json.Unmarshal(data, &out); err != nil {
			return "", 0, fmt.Errorf("vaultmek: decode token refresh response: %w", err)
		}
		if out.AttestationToken == "" {
			return "", 0, fmt.Errorf("vaultmek: control plane returned no attestation token")
		}
		if onMeta != nil && out.Constellation.AttestationServer != "" {
			onMeta(out.Constellation.AttestationServer)
		}
		return out.AttestationToken, out.AttestationTokenExpiresAt, nil
	}
}

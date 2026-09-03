package vaultmek

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"enclave-os-mini/clients/go/ratls"
)

// identityMinter is the slice of ManagerMinter the token refresher needs
// (an interface so tests can inject a fake): the identity leaf plus a quote
// committing to it and the given challenge (header flow, RA-TLS v2).
type identityMinter interface {
	headerIdentity(ctx context.Context, challenge []byte) (der, quote []byte, err error)
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

// AppIdentityHeaders returns the header triple (base64 identity DER, base64
// challenge, base64 quote) that authenticates one control-plane call behind
// the app-identity gate. The 32-byte challenge follows the freshness
// contract: first 8 bytes are big-endian unix seconds, the rest anti-replay
// randomness; the quote commits to the leaf key and the challenge. Errors
// off-platform (no manager identity).
func (c *Client) AppIdentityHeaders(ctx context.Context) (identityB64, challengeB64, evidenceB64 string, err error) {
	if c.minter == nil {
		return "", "", "", fmt.Errorf("vaultmek: no manager identity available (not running on the platform)")
	}
	challenge, err := freshChallenge()
	if err != nil {
		return "", "", "", err
	}
	der, quote, err := c.minter.headerIdentity(ctx, challenge)
	if err != nil {
		return "", "", "", fmt.Errorf("vaultmek: mint identity: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der),
		base64.StdEncoding.EncodeToString(challenge),
		base64.StdEncoding.EncodeToString(quote), nil
}

// freshChallenge builds a 32-byte app-identity challenge: 8 bytes big-endian
// unix seconds (trustworthy once the quote commits to the challenge) followed
// by 24 random bytes.
func freshChallenge() ([]byte, error) {
	challenge := make([]byte, ratls.ContextLen)
	binary.BigEndian.PutUint64(challenge[:8], uint64(time.Now().Unix()))
	if _, err := rand.Read(challenge[8:]); err != nil {
		return nil, err
	}
	return challenge, nil
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
		challenge, err := freshChallenge()
		if err != nil {
			return "", 0, err
		}
		der, quote, err := m.headerIdentity(ctx, challenge)
		if err != nil {
			return "", 0, fmt.Errorf("vaultmek: mint identity for token refresh: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", 0, err
		}
		req.Header.Set("X-Privasys-App-Identity", base64.StdEncoding.EncodeToString(der))
		req.Header.Set("X-Privasys-App-Challenge", base64.StdEncoding.EncodeToString(challenge))
		req.Header.Set("X-Privasys-App-Evidence", base64.StdEncoding.EncodeToString(quote))
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

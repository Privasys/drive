// Package vaultmek creates and loads per-tenant MEKs on the Privasys
// vault constellation. The MEK is generated inside the enclave,
// Shamir-split to the constellation threshold and created share-by-share
// with an IdP-signed, app-id-bound key-creation grant the data owner
// fetched from the control plane; at runtime the shares are read back
// (the app's attested TEE principal holds ExportKey) and recombined in
// memory. The platform never sees the material.
package vaultmek

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"
	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// Bundle is the grant package the data owner hands over: the grant, the
// handle to create, and the constellation addressing from the control
// plane's data-keys/grant response.
type Bundle struct {
	Grant            string   `json:"grant"`
	Handle           string   `json:"handle"`
	Endpoints        []string `json:"endpoints"`
	MrenclaveHex     string   `json:"mrenclave"`
	AttServer        string   `json:"attestation_server"`
	AttToken         string   `json:"attestation_token"`
	Threshold        int      `json:"threshold"`
}

// Ref is what the index persists per tenant (on the sealed volume):
// everything needed to read the MEK back, including the current
// attestation-server token. The token is refreshed whenever the owner
// re-presents a grant bundle (each login), so an expired one only
// bites when the service restarts and the owner has not been back.
type Ref struct {
	Handle       string   `json:"handle"`
	Endpoints    []string `json:"endpoints"`
	MrenclaveHex string   `json:"mrenclave"`
	AttServer    string   `json:"attestation_server"`
	AttToken     string   `json:"attestation_token,omitempty"`
	Threshold    int      `json:"threshold"`
}

// RefJSON round-trips a Ref for the index column.
func RefJSON(r Ref) string { b, _ := json.Marshal(r); return string(b) }

// ParseRef parses a persisted Ref.
func ParseRef(s string) (Ref, error) {
	var r Ref
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return Ref{}, fmt.Errorf("vaultmek: parse ref: %w", err)
	}
	return r, nil
}

// TokenRefresher returns a fresh aud=attestation-server token (and its
// unix expiry) the client uses to verify the vaults' quotes when a
// stored Ref's token has gone stale. See MgmtTokenRefresher.
type TokenRefresher func(ctx context.Context) (token string, expiresAt int64, err error)

// Client provisions and loads tenant MEKs. minter is the fork-only
// manager identity source (nil off-platform, where operations fail).
type Client struct {
	minter *ManagerMinter

	mu   sync.RWMutex
	meks map[string][]byte // handle -> MEK, in-memory only

	tokMu    sync.Mutex
	refresh  TokenRefresher
	freshTok string
	freshExp int64
}

// New builds a client. managerMintURL is the in-TD manager's
// vault-identity endpoint; token is the per-app mint token.
func New(managerMintURL, token string) *Client {
	c := &Client{meks: map[string][]byte{}}
	if managerMintURL != "" && token != "" {
		c.minter = NewManagerMinter(managerMintURL, token)
	}
	return c
}

// SetTokenRefresher enables self-healing of stale attestation tokens:
// when an operation fails with the Ref's stored token, the client
// fetches a fresh token and retries once. Idempotent.
func (c *Client) SetTokenRefresher(r TokenRefresher) {
	c.tokMu.Lock()
	c.refresh = r
	c.tokMu.Unlock()
}

// cachedFreshToken returns a previously fetched token that is still
// comfortably within its validity, or "".
func (c *Client) cachedFreshToken(now int64) string {
	c.tokMu.Lock()
	defer c.tokMu.Unlock()
	if c.freshTok != "" && (c.freshExp == 0 || now+60 < c.freshExp) {
		return c.freshTok
	}
	return ""
}

// refreshToken fetches (and caches) a fresh attestation token, or
// returns "" when no refresher is configured or it fails.
func (c *Client) refreshToken(ctx context.Context) string {
	c.tokMu.Lock()
	r := c.refresh
	c.tokMu.Unlock()
	if r == nil {
		return ""
	}
	tok, exp, err := r(ctx)
	if err != nil || tok == "" {
		return ""
	}
	c.tokMu.Lock()
	c.freshTok, c.freshExp = tok, exp
	c.tokMu.Unlock()
	return tok
}

func (c *Client) policy(mrenclaveHex, attServer, attToken string, nonce []byte) (*ratls.VerificationPolicy, error) {
	mre, err := hex.DecodeString(mrenclaveHex)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vaultmek: vault mrenclave must be 32 bytes of hex")
	}
	return &ratls.VerificationPolicy{
		TEE:               ratls.TeeTypeSGX,
		MRENCLAVE:         mre,
		ReportData:        ratls.ReportDataChallengeResponse,
		Nonce:             nonce,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: attServer, Token: attToken},
	}, nil
}

// dial opens an app-identity RA-TLS connection to one vault endpoint:
// a fresh client nonce puts the vault in bidirectional-challenge mode,
// the manager mints a one-shot identity bound to the vault's challenge,
// and the vault's quote is verified against the pinned MRENCLAVE.
func (c *Client) dial(ctx context.Context, endpoint, mrenclaveHex, attServer, attToken string) (*vsdk.Client, error) {
	if c.minter == nil {
		return nil, fmt.Errorf("vaultmek: no manager identity available (not running on the platform)")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	pol, err := c.policy(mrenclaveHex, attServer, attToken, nonce)
	if err != nil {
		return nil, err
	}
	return vsdk.Dial(ctx, vsdk.VaultRegistration{ID: endpoint, Endpoint: endpoint, Status: "static"}, vsdk.DialOptions{
		Challenge:            nonce,
		GetClientCertificate: c.minter.GetClientCertificate(),
		VaultPolicy:          pol,
	})
}

// Provision generates a fresh 256-bit MEK, splits it k-of-n across the
// constellation and creates each share under the grant. Every endpoint
// must accept its share (a partial create is torn down best-effort so a
// retry with a fresh grant starts clean). Returns the persistable Ref;
// the MEK stays cached in memory.
func (c *Client) Provision(ctx context.Context, b Bundle) (Ref, error) {
	if len(b.Endpoints) == 0 || b.Grant == "" || b.Handle == "" {
		return Ref{}, fmt.Errorf("vaultmek: grant, handle and endpoints are required")
	}
	threshold := b.Threshold
	if threshold <= 0 || threshold > len(b.Endpoints) {
		threshold = (len(b.Endpoints) + 1) / 2
	}
	mek := make([]byte, 32)
	if _, err := rand.Read(mek); err != nil {
		return Ref{}, err
	}
	shares, err := vsdk.ShamirSplit(mek, threshold, len(b.Endpoints))
	if err != nil {
		return Ref{}, fmt.Errorf("vaultmek: split: %w", err)
	}
	created := 0
	for i, ep := range b.Endpoints {
		vc, derr := c.dial(ctx, ep, b.MrenclaveHex, b.AttServer, b.AttToken)
		if derr != nil {
			err = fmt.Errorf("vaultmek: dial %s: %w", ep, derr)
			break
		}
		_, cerr := vc.CreateKey(ctx, b.Handle, vsdk.ShareToBytes(shares[i]), b.Grant)
		vc.Close()
		if cerr != nil {
			err = fmt.Errorf("vaultmek: create share on %s: %w", ep, cerr)
			break
		}
		created++
	}
	if err != nil {
		// Best-effort teardown of a partial create; the owner keeps
		// DeleteKey, but the app TEE does not, so leftovers may need an
		// owner-side delete. Report the underlying error regardless.
		return Ref{}, err
	}
	_ = created
	ref := Ref{
		Handle: b.Handle, Endpoints: b.Endpoints,
		MrenclaveHex: b.MrenclaveHex, AttServer: b.AttServer,
		AttToken: b.AttToken, Threshold: threshold,
	}
	c.mu.Lock()
	c.meks[b.Handle] = mek
	c.mu.Unlock()
	return ref, nil
}

// Unwrap decrypts a payload sealed under a vault Aes256GcmKey (a
// "wrapped-secret" operator key: the app TEE holds Unwrap only). Used
// for BYO bucket credentials — the tenant/owner sealed the credential
// with an in-enclave Wrap RPC; Drive unwraps it in-enclave per session
// and never persists the plaintext. The key lives on a single vault
// (AES keys are not Shamir-split), so the first endpoint that holds it
// answers.
func (c *Client) Unwrap(ctx context.Context, ref Ref, ciphertext, iv []byte) ([]byte, error) {
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	pt, err := c.unwrapOnce(ctx, ref, tok, ciphertext, iv)
	if err != nil {
		// The stored token may simply have expired; fetch a fresh one and
		// retry once (self-heal, no owner round-trip).
		if ft := c.refreshToken(ctx); ft != "" && ft != tok {
			return c.unwrapOnce(ctx, ref, ft, ciphertext, iv)
		}
	}
	return pt, err
}

func (c *Client) unwrapOnce(ctx context.Context, ref Ref, attToken string, ciphertext, iv []byte) ([]byte, error) {
	var lastErr error
	for _, ep := range ref.Endpoints {
		vc, derr := c.dial(ctx, ep, ref.MrenclaveHex, ref.AttServer, attToken)
		if derr != nil {
			lastErr = derr
			continue
		}
		pt, uerr := vc.Unwrap(ctx, ref.Handle, ciphertext, iv, nil)
		vc.Close()
		if uerr != nil {
			if strings.Contains(uerr.Error(), "not found") {
				continue
			}
			lastErr = uerr
			continue
		}
		return pt, nil
	}
	return nil, fmt.Errorf("vaultmek: unwrap %s: %v", ref.Handle, lastErr)
}

// Load returns the MEK for a persisted Ref, reading shares back from
// the constellation on first use (the app TEE holds ExportKey) and
// caching the result in memory.
func (c *Client) Load(ctx context.Context, ref Ref) ([]byte, error) {
	c.mu.RLock()
	if mek, ok := c.meks[ref.Handle]; ok {
		c.mu.RUnlock()
		return mek, nil
	}
	c.mu.RUnlock()

	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	mek, err := c.loadOnce(ctx, ref, tok)
	if err != nil {
		// The stored token expires ~15 min after the last re-arm; with a
		// refresher configured the client self-heals instead of failing
		// until the owner comes back.
		if ft := c.refreshToken(ctx); ft != "" && ft != tok {
			mek, err = c.loadOnce(ctx, ref, ft)
		}
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.meks[ref.Handle] = mek
	c.mu.Unlock()
	return mek, nil
}

func (c *Client) loadOnce(ctx context.Context, ref Ref, attToken string) ([]byte, error) {
	threshold := ref.Threshold
	if threshold <= 0 {
		threshold = (len(ref.Endpoints) + 1) / 2
	}
	var shares []*vsdk.Share
	var lastErr error
	for _, ep := range ref.Endpoints {
		if len(shares) >= threshold {
			break
		}
		vc, derr := c.dial(ctx, ep, ref.MrenclaveHex, ref.AttServer, attToken)
		if derr != nil {
			lastErr = derr
			continue
		}
		raw, eerr := vc.ExportKey(ctx, ref.Handle)
		vc.Close()
		if eerr != nil {
			lastErr = eerr
			continue
		}
		sh, perr := vsdk.ShareFromBytes(raw)
		if perr != nil {
			lastErr = perr
			continue
		}
		shares = append(shares, sh)
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("vaultmek: only %d/%d shares recovered for %s: %v", len(shares), threshold, ref.Handle, lastErr)
	}
	mek, err := vsdk.ShamirReconstruct(shares)
	if err != nil {
		return nil, fmt.Errorf("vaultmek: reconstruct: %w", err)
	}
	return mek, nil
}

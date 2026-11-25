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
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"strconv"
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
	Grant        string   `json:"grant"`
	Handle       string   `json:"handle"`
	Endpoints    []string `json:"endpoints"`
	MrenclaveHex string   `json:"mrenclave"`
	AttServer    string   `json:"attestation_server"`
	AttToken     string   `json:"attestation_token"`
	Threshold    int      `json:"threshold"`
	// Audience is the constellation's OIDC audience: the "aud" an owner
	// token must carry for these vaults (each environment has its own).
	// Empty on a bundle from a control plane that does not send it.
	Audience string `json:"oidc_audience,omitempty"`
	// Issuer is the constellation's OIDC issuer, kept with the ref so a later
	// carried renewal can name the source's implicit billing id.
	Issuer string `json:"oidc_issuer,omitempty"`
	// CarryFrom, when set, makes the new key carry the policy of the key
	// at that ref (read from its vaults) instead of the grant's: a
	// renewal with a carried policy. The grant then only admits the
	// create. Needs vaults that take a carried policy (vault-v0.40.0+).
	CarryFrom *Ref `json:"-"`
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
	// Audience is the constellation's OIDC audience (see Bundle.Audience).
	Audience string `json:"oidc_audience,omitempty"`
	// Issuer is the constellation's OIDC issuer (see Bundle.Issuer).
	Issuer string `json:"oidc_issuer,omitempty"`
	// RotatedAt is when this handle generation was created (unix seconds).
	// Vault key records expire at a FIXED expires_at (90-day cap, 30-day
	// default; nothing extends it), so the only renewal is re-creating the
	// same material at the next handle generation (Regenerate). Zero marks
	// a legacy ref from before rotation existed: due immediately.
	RotatedAt int64 `json:"rotated_at,omitempty"`
	// Policy and PolicyVersion are the key's stored policy as its vaults
	// last confirmed it (read back from every member after a create, an
	// update or a load, never what Drive meant to send). They carry no
	// trust: a measurement approval binds PD(Policy) and PolicyVersion, and
	// the vault refuses one that does not match what it holds. They let
	// Drive build that approval without reading the policy as the owner.
	Policy        json.RawMessage `json:"policy,omitempty"`
	PolicyVersion uint32          `json:"policy_version,omitempty"`
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

	// fails paces retries of a failing key (by handle) and of a failing
	// token refresh (key ""), see backoff.go; refreshMu lets one refresh
	// run at a time.
	fails     backoffs
	refreshMu sync.Mutex

	tokMu    sync.Mutex
	refresh  TokenRefresher
	freshTok string
	freshExp int64
	// attServer is the constellation's attestation-server endpoint as
	// reported by the last successful control-plane token refresh.
	attServer string
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

// Seed installs an already-recovered MEK in the in-memory cache (e.g.
// an escrowed recovery unwrapped it from the escrow wrap), so content
// reads work even when the key's own vault path is unavailable — the
// escrow is the disaster-recovery path. In-memory only.
func (c *Client) Seed(handle string, mek []byte) {
	c.mu.Lock()
	c.meks[handle] = mek
	c.mu.Unlock()
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

// refreshToken fetches (and caches) a fresh attestation token. Returns
// ("", nil) when no refresher is configured.
func (c *Client) refreshToken(ctx context.Context) (string, error) {
	c.tokMu.Lock()
	r := c.refresh
	c.tokMu.Unlock()
	if r == nil {
		return "", nil
	}
	// One refresh at a time: callers that queued behind it take its token.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		return ft, nil
	}
	if err := c.fails.wait("", time.Now()); err != nil {
		return "", err
	}
	tok, exp, err := r(ctx)
	if err == nil && tok == "" {
		err = fmt.Errorf("vaultmek: refresher returned an empty token")
	}
	if err != nil {
		// The control plane's answer (its reason for a refusal) is in err.
		log.Printf("vaultmek: attestation-token refresh failed: %v", err)
		c.fails.fail("", err, time.Now())
		return "", err
	}
	c.fails.reset("")
	c.tokMu.Lock()
	c.freshTok, c.freshExp = tok, exp
	c.tokMu.Unlock()
	return tok, nil
}

func (c *Client) policy(mrenclaveHex, attServer, attToken string) (*ratls.VerificationPolicy, error) {
	mre, err := hex.DecodeString(mrenclaveHex)
	if err != nil || len(mre) != 32 {
		return nil, fmt.Errorf("vaultmek: vault mrenclave must be 32 bytes of hex")
	}
	return &ratls.VerificationPolicy{
		TEE:               ratls.TeeTypeSGX,
		MRENCLAVE:         mre,
		QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: attServer, Token: attToken},
	}, nil
}

// dial opens an app-identity RA-TLS v2 connection to one vault endpoint:
// the vault's evidence is requested after the handshake in challenge mode
// and verified against the pinned MRENCLAVE, and the manager-minted
// identity is presented with a quote bound to this connection.
func (c *Client) dial(ctx context.Context, endpoint, mrenclaveHex, attServer, attToken string) (*vsdk.Client, error) {
	return c.dialAs(ctx, endpoint, mrenclaveHex, attServer, attToken, "")
}

// dialAs is dial with an optional OIDC bearer attached to every request
// on the connection — the owner-authenticated path (UpdatePolicy for a
// measurement approval), where the vault authorises by the caller's
// OIDC principal on top of the app's attested transport identity.
func (c *Client) dialAs(ctx context.Context, endpoint, mrenclaveHex, attServer, attToken, bearer string) (*vsdk.Client, error) {
	return c.dialWith(ctx, endpoint, mrenclaveHex, attServer, attToken, bearer, nil)
}

// dialWith is dialAs with the member set of a binding-v2 approval, which
// every approval-gated request then carries.
func (c *Client) dialWith(ctx context.Context, endpoint, mrenclaveHex, attServer, attToken, bearer string, members []string) (*vsdk.Client, error) {
	if c.minter == nil {
		return nil, fmt.Errorf("vaultmek: no manager identity available (not running on the platform)")
	}
	pol, err := c.policy(mrenclaveHex, attServer, attToken)
	if err != nil {
		return nil, err
	}
	opts := vsdk.DialOptions{
		GetClientCertificate: c.minter.GetClientCertificate(),
		ClientEvidence:       c.minter.ClientEvidence(),
		VaultPolicy:          pol,
		BindingMembers:       members,
	}
	if bearer != "" {
		opts.AuthToken = vsdk.StaticToken(bearer)
	}
	return vsdk.Dial(ctx, vsdk.VaultRegistration{ID: endpoint, Endpoint: endpoint, Status: "static"}, opts)
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
	if err := c.createShares(ctx, b, b.Handle, mek, threshold); err != nil {
		// Best-effort teardown of a partial create; the owner keeps
		// DeleteKey, but the app TEE does not, so leftovers may need an
		// owner-side delete. Report the underlying error regardless.
		return Ref{}, err
	}
	ref := Ref{
		Handle: b.Handle, Endpoints: b.Endpoints,
		MrenclaveHex: b.MrenclaveHex, AttServer: b.AttServer,
		AttToken: b.AttToken, Threshold: threshold, Audience: b.Audience, Issuer: b.Issuer,
		RotatedAt: time.Now().Unix(),
	}
	c.mu.Lock()
	c.meks[b.Handle] = mek
	c.mu.Unlock()
	return c.withPolicy(ctx, ref), nil
}

// createShares Shamir-splits secret and creates one share per endpoint at
// handle under the bundle's grant. Used by both Provision (fresh material)
// and Regenerate (existing material at the next handle generation).
func (c *Client) createShares(ctx context.Context, b Bundle, handle string, secret []byte, threshold int) error {
	shares, err := vsdk.ShamirSplit(secret, threshold, len(b.Endpoints))
	if err != nil {
		return fmt.Errorf("vaultmek: split: %w", err)
	}
	var renewal *vsdk.Renewal
	if b.CarryFrom != nil {
		r, rerr := c.carriedRenewal(ctx, *b.CarryFrom, secret)
		if rerr != nil {
			return rerr
		}
		renewal = &r
	}
	for i, ep := range b.Endpoints {
		vc, derr := c.dial(ctx, ep, b.MrenclaveHex, b.AttServer, b.AttToken)
		if derr != nil {
			return fmt.Errorf("vaultmek: dial %s: %w", ep, derr)
		}
		var cerr error
		if renewal != nil {
			_, cerr = vc.CreateKeyRenewal(ctx, handle, vsdk.ShareToBytes(shares[i]), b.Grant, *renewal)
		} else {
			_, cerr = vc.CreateKey(ctx, handle, vsdk.ShareToBytes(shares[i]), b.Grant)
		}
		vc.Close()
		if cerr != nil {
			return fmt.Errorf("vaultmek: create share on %s: %w", ep, cerr)
		}
	}
	return nil
}

// NextGeneration bumps the trailing generation segment of a key handle
// (".../mek/v1" -> ".../mek/v2").
func NextGeneration(handle string) (string, error) {
	i := strings.LastIndex(handle, "/v")
	if i < 0 {
		return "", fmt.Errorf("vaultmek: handle %q has no /v<N> generation suffix", handle)
	}
	n, err := strconv.Atoi(handle[i+2:])
	if err != nil || n < 1 {
		return "", fmt.Errorf("vaultmek: handle %q has no /v<N> generation suffix", handle)
	}
	return handle[:i+2] + strconv.Itoa(n+1), nil
}

// Regenerate re-creates a tenant's key — SAME material — at the next handle
// generation, under a fresh grant, on the constellation the bundle
// addresses. This is the only renewal a vault key has: expires_at is fixed
// at CreateKey (90-day cap, 30-day default) and no operation extends it, so
// rotating the handle restarts the clock without re-wrapping any content;
// a bundle from a newer constellation also moves the key off a retiring
// one. The old record is left to age out on its TTL (the app TEE holds no
// DeleteKey; until then it doubles as a fallback).
func (c *Client) Regenerate(ctx context.Context, ref Ref, b Bundle) (Ref, error) {
	if len(b.Endpoints) == 0 || b.Grant == "" {
		return Ref{}, fmt.Errorf("vaultmek: regenerate: grant and endpoints are required")
	}
	mek, err := c.Load(ctx, ref)
	if err != nil {
		return Ref{}, fmt.Errorf("vaultmek: regenerate: load current key: %w", err)
	}
	newHandle, err := NextGeneration(ref.Handle)
	if err != nil {
		return Ref{}, err
	}
	threshold := b.Threshold
	if threshold <= 0 || threshold > len(b.Endpoints) {
		threshold = (len(b.Endpoints) + 1) / 2
	}
	newRef := Ref{
		Handle: newHandle, Endpoints: b.Endpoints,
		MrenclaveHex: b.MrenclaveHex, AttServer: b.AttServer,
		AttToken: b.AttToken, Threshold: threshold, Audience: b.Audience, Issuer: b.Issuer,
		RotatedAt: time.Now().Unix(),
	}
	if cerr := c.createShares(ctx, b, newHandle, mek, threshold); cerr != nil {
		// A crash after a previous full create but before the index commit
		// leaves the new generation on the vaults with no local ref. Adopt
		// it only if it reconstructs to the SAME material (a partial earlier
		// create mixed with this attempt's shares would not).
		if strings.Contains(strings.ToLower(cerr.Error()), "exist") {
			if got, lerr := c.loadOnce(ctx, newRef, b.AttToken); lerr == nil && subtle.ConstantTimeCompare(got, mek) == 1 {
				c.mu.Lock()
				c.meks[newHandle] = mek
				c.mu.Unlock()
				return c.withPolicy(ctx, newRef), nil
			}
		}
		return Ref{}, cerr
	}
	c.mu.Lock()
	c.meks[newHandle] = mek
	c.mu.Unlock()
	return c.withPolicy(ctx, newRef), nil
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
		ft, rerr := c.refreshToken(ctx)
		if rerr != nil {
			return nil, fmt.Errorf("%v (token self-heal failed: %v)", err, rerr)
		}
		if ft != "" && ft != tok {
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

	// A key that failed recently is not retried until its backoff is due:
	// every read of the tenant (and the indexer) would otherwise hit the
	// vaults and the control plane in a tight loop. The last failure is
	// returned, so a measurement change is still recognised.
	if err := c.fails.wait(ref.Handle, time.Now()); err != nil {
		return nil, err
	}
	tok := ref.AttToken
	if ft := c.cachedFreshToken(time.Now().Unix()); ft != "" {
		tok = ft
	}
	mek, err := c.loadOnce(ctx, ref, tok)
	if err != nil && !PrincipalMismatch(err) {
		// The stored token expires ~15 min after the last re-arm; with a
		// refresher configured the client self-heals instead of failing
		// until the owner comes back. A measurement change is not a token
		// problem, so it does not ask the control plane for one.
		ft, rerr := c.refreshToken(ctx)
		if rerr != nil {
			err = fmt.Errorf("%v (token self-heal failed: %v)", err, rerr)
		} else if ft != "" && ft != tok {
			mek, err = c.loadOnce(ctx, ref, ft)
		}
	}
	if err != nil {
		c.fails.fail(ref.Handle, err, time.Now())
		return nil, err
	}
	c.fails.reset(ref.Handle)
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

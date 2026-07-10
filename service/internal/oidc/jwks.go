package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKSVerifier validates platform OIDC bearer tokens offline via JWKS
// discovery, so a request is authorised without the enclave ever
// contacting the platform with the payload. Verification is deliberately
// stdlib-only (mirrors the enclave manager's verifier and the
// confidential-ai handler): the same issuer, `roles` claim, and
// signature algorithms (RS*, ES*). Only the (cached) JWKS is fetched.
type JWKSVerifier struct {
	issuer   string
	audience string // required aud; empty skips the check

	client *http.Client

	mu        sync.RWMutex
	keys      map[string]*jwk
	fetchedAt time.Time
}

// NewJWKSVerifier returns a verifier for tokens issued by issuer.
// audience may be empty to skip the aud check.
func NewJWKSVerifier(issuer, audience string) *JWKSVerifier {
	return &JWKSVerifier{
		issuer:   strings.TrimRight(issuer, "/"),
		audience: audience,
		client:   &http.Client{Timeout: 10 * time.Second},
		keys:     map[string]*jwk{},
	}
}

// Verify validates the token's signature, issuer, audience and expiry.
func (v *JWKSVerifier) Verify(ctx context.Context, token string) (*Identity, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil, errors.New("oidc: malformed token")
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("oidc: header parse: %w", err)
	}

	key, err := v.signingKey(ctx, header.Kid, header.Alg)
	if err != nil {
		return nil, fmt.Errorf("oidc: jwks lookup: %w", err)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: sig decode: %w", err)
	}
	if err := jwkVerify(header.Alg, key, signingInput, sig); err != nil {
		return nil, fmt.Errorf("oidc: signature: %w", err)
	}

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: claims decode: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("oidc: claims parse: %w", err)
	}

	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return nil, fmt.Errorf("oidc: issuer %q != %q", iss, v.issuer)
	}
	if v.audience != "" && !checkAudience(claims, v.audience) {
		return nil, fmt.Errorf("oidc: audience missing %q", v.audience)
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, errors.New("oidc: token expired")
		}
	}

	id := &Identity{Issuer: v.issuer, Audience: v.audience, Roles: rolesClaim(claims), Claims: claims}
	id.Sub, _ = claims["sub"].(string)
	id.Email, _ = claims["email"].(string)
	id.SID, _ = claims["sid"].(string)
	if id.Sub == "" {
		return nil, errors.New("oidc: token has no sub")
	}
	return id, nil
}

// rolesClaim extracts a string list from the `roles` claim (array form)
// and Keycloak's realm_access.roles, matching the manager's checkRole.
func rolesClaim(claims map[string]any) []string {
	var out []string
	if arr, ok := claims["roles"].([]any); ok {
		for _, r := range arr {
			if s, ok := r.(string); ok {
				out = append(out, s)
			}
		}
	}
	if ra, ok := claims["realm_access"].(map[string]any); ok {
		if arr, ok := ra["roles"].([]any); ok {
			for _, r := range arr {
				if s, ok := r.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}

func checkAudience(claims map[string]any, expected string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == expected
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

// --- JWKS ---

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (v *JWKSVerifier) signingKey(ctx context.Context, kid, alg string) (*jwk, error) {
	v.mu.RLock()
	if len(v.keys) > 0 && time.Since(v.fetchedAt) < 5*time.Minute {
		if k, ok := v.keys[kid]; ok {
			v.mu.RUnlock()
			return k, nil
		}
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keys) > 0 && time.Since(v.fetchedAt) < 5*time.Minute {
		if k, ok := v.keys[kid]; ok {
			return k, nil
		}
	}

	jwksURL, err := v.discoverJWKS(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := v.fetchJWKS(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	v.keys = keys
	v.fetchedAt = time.Now()

	if k, ok := keys[kid]; ok {
		return k, nil
	}
	if kid == "" {
		for _, k := range keys {
			if k.Alg == alg || (k.Use == "sig" && k.Alg == "") {
				return k, nil
			}
		}
	}
	return nil, fmt.Errorf("key %q not in JWKS", kid)
}

func (v *JWKSVerifier) discoverJWKS(ctx context.Context) (string, error) {
	url := v.issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var disc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &disc); err != nil {
		return "", fmt.Errorf("discovery parse: %w", err)
	}
	if disc.JwksURI == "" {
		return "", errors.New("discovery: no jwks_uri")
	}
	return disc.JwksURI, nil
}

func (v *JWKSVerifier) fetchJWKS(ctx context.Context, uri string) (map[string]*jwk, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks parse: %w", err)
	}
	keys := make(map[string]*jwk, len(doc.Keys))
	for i := range doc.Keys {
		k := doc.Keys[i]
		keys[k.Kid] = &k
	}
	if len(keys) == 0 {
		return nil, errors.New("jwks empty")
	}
	return keys, nil
}

// --- signature verification ---

func jwkVerify(alg string, key *jwk, signingInput, sig []byte) error {
	switch {
	case strings.HasPrefix(alg, "RS"):
		return jwkVerifyRSA(alg, key, signingInput, sig)
	case strings.HasPrefix(alg, "ES"):
		return jwkVerifyEC(key, signingInput, sig)
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
}

func jwkVerifyRSA(alg string, key *jwk, signingInput, sig []byte) error {
	if key.Kty != "RSA" {
		return fmt.Errorf("expected RSA key, got %s", key.Kty)
	}
	nb, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return err
	}
	eb, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}
	var h crypto.Hash
	switch alg {
	case "RS256":
		h = crypto.SHA256
	case "RS384":
		h = crypto.SHA384
	case "RS512":
		h = crypto.SHA512
	default:
		return fmt.Errorf("unsupported RSA alg %q", alg)
	}
	hh := h.New()
	hh.Write(signingInput)
	return rsa.VerifyPKCS1v15(pub, h, hh.Sum(nil), sig)
}

func jwkVerifyEC(key *jwk, signingInput, sig []byte) error {
	if key.Kty != "EC" {
		return fmt.Errorf("expected EC key, got %s", key.Kty)
	}
	xb, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return err
	}
	yb, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return err
	}
	var curve elliptic.Curve
	var size int
	var hash func([]byte) []byte
	switch key.Crv {
	case "P-256":
		curve, size = elliptic.P256(), 32
		hash = func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	case "P-384":
		curve, size = elliptic.P384(), 48
		hash = func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }
	default:
		return fmt.Errorf("unsupported curve %q", key.Crv)
	}
	if len(sig) != size*2 {
		return fmt.Errorf("EC sig wrong length %d, want %d", len(sig), size*2)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	r := new(big.Int).SetBytes(sig[:size])
	s := new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(pub, hash(signingInput), r, s) {
		return errors.New("EC signature invalid")
	}
	return nil
}

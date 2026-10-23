// Package disclosure verifies the proofs a visitor presents for a paid
// attribute.
//
// The identity verifier proves a government-backed attribute by issuing an
// SD-JWT VC: an ES256 JWS followed by "~", naming the holder (sub), the
// relying party it was made for (aud), the claim and its value. The IdP
// carries that token in the visitor's sign-in token unverified, and leaves
// the check to the relying party. Without it, anything non-empty would pass
// as proven: a value the wallet typed in, a proof that someone is NOT over
// 18, a charged failure receipt, or a proof made out to someone else.
package disclosure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DefaultIssuer is the Privasys identity verifier's public origin.
const DefaultIssuer = "https://privasys-identity-verifier.apps.privasys.org"

// Leeway past a proof's expiry. A proof lives for minutes and the link page
// redeems right after the sign-in that carried it; this absorbs clock skew
// and a slow page, not a replay days later.
const Leeway = 5 * time.Minute

// Expect is what a proof must say to count.
type Expect struct {
	Claim    string // the claim it proves ("age_over_18", "given_name")
	Subject  string // the visitor it must be made out to
	Audience string // the relying party it must be made for
}

// Verifier checks proofs against the keys their issuers publish.
type Verifier struct {
	Issuers []string
	HC      *http.Client
	Now     func() time.Time

	mu   sync.Mutex
	keys map[string]issuerKeys
}

type issuerKeys struct {
	byKID   map[string]*ecdsa.PublicKey
	fetched time.Time
}

// ErrNotProven means the value does not prove the attribute.
var ErrNotProven = errors.New("not a valid proof")

// Verify returns the proven value, as the sharer will see it, or
// ErrNotProven (wrapped with the reason).
func (v *Verifier) Verify(ctx context.Context, token string, want Expect) (string, error) {
	jws, ok := strings.CutSuffix(strings.TrimSpace(token), "~")
	if !ok {
		// An SD-JWT always ends in "~"; anything else is a plain value.
		return "", fmt.Errorf("%w: not a proof token", ErrNotProven)
	}
	if i := strings.Index(jws, "~"); i >= 0 {
		jws = jws[:i]
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("%w: malformed", ErrNotProven)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJSON(parts[0], &header); err != nil || header.Alg != "ES256" {
		return "", fmt.Errorf("%w: unsupported header", ErrNotProven)
	}
	var payload struct {
		Iss     string          `json:"iss"`
		Sub     string          `json:"sub"`
		Aud     string          `json:"aud"`
		Claim   string          `json:"claim"`
		Value   any             `json:"value"`
		Exp     int64           `json:"exp"`
		Failure json.RawMessage `json:"failure"`
	}
	if err := decodeJSON(parts[1], &payload); err != nil {
		return "", fmt.Errorf("%w: malformed payload", ErrNotProven)
	}
	if !v.trusted(payload.Iss) {
		return "", fmt.Errorf("%w: issuer %q is not trusted", ErrNotProven, payload.Iss)
	}
	key, err := v.key(ctx, payload.Iss, header.Kid)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrNotProven, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return "", fmt.Errorf("%w: malformed signature", ErrNotProven)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(key, digest[:], r, s) {
		return "", fmt.Errorf("%w: bad signature", ErrNotProven)
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	switch {
	case payload.Exp == 0 || now().After(time.Unix(payload.Exp, 0).Add(Leeway)):
		return "", fmt.Errorf("%w: expired", ErrNotProven)
	case len(payload.Failure) > 0 && string(payload.Failure) != "null":
		return "", fmt.Errorf("%w: the check did not pass", ErrNotProven)
	case payload.Sub == "" || payload.Sub != want.Subject:
		return "", fmt.Errorf("%w: made out to someone else", ErrNotProven)
	case want.Audience != "" && payload.Aud != want.Audience:
		return "", fmt.Errorf("%w: made for another relying party", ErrNotProven)
	case payload.Claim != want.Claim:
		return "", fmt.Errorf("%w: proves %q, not %q", ErrNotProven, payload.Claim, want.Claim)
	}
	switch val := payload.Value.(type) {
	case bool:
		if !val {
			return "", fmt.Errorf("%w: the answer is no", ErrNotProven)
		}
		return "true", nil
	case string:
		if strings.TrimSpace(val) == "" {
			return "", fmt.Errorf("%w: empty value", ErrNotProven)
		}
		return strings.TrimSpace(val), nil
	case float64:
		return fmt.Sprint(val), nil
	default:
		return "", fmt.Errorf("%w: no value", ErrNotProven)
	}
}

func (v *Verifier) trusted(iss string) bool {
	iss = strings.TrimRight(iss, "/")
	for _, t := range v.Issuers {
		if strings.TrimRight(strings.TrimSpace(t), "/") == iss && iss != "" {
			return true
		}
	}
	return false
}

// key returns the issuer's key for kid, from its SD-JWT VC issuer metadata,
// refetched hourly or when kid is unknown (a rotation).
func (v *Verifier) key(ctx context.Context, iss, kid string) (*ecdsa.PublicKey, error) {
	v.mu.Lock()
	cached, ok := v.keys[iss]
	v.mu.Unlock()
	if ok && time.Since(cached.fetched) < time.Hour {
		if k := pick(cached.byKID, kid); k != nil {
			return k, nil
		}
	}
	fresh, err := v.fetch(ctx, iss)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	if v.keys == nil {
		v.keys = map[string]issuerKeys{}
	}
	v.keys[iss] = fresh
	v.mu.Unlock()
	if k := pick(fresh.byKID, kid); k != nil {
		return k, nil
	}
	return nil, errors.New("unknown signing key")
}

func pick(keys map[string]*ecdsa.PublicKey, kid string) *ecdsa.PublicKey {
	if k, ok := keys[kid]; ok {
		return k
	}
	if kid == "" && len(keys) == 1 {
		for _, k := range keys {
			return k
		}
	}
	return nil
}

func (v *Verifier) fetch(ctx context.Context, iss string) (issuerKeys, error) {
	hc := v.HC
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(iss, "/")+"/.well-known/jwt-vc-issuer", nil)
	if err != nil {
		return issuerKeys{}, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return issuerKeys{}, fmt.Errorf("issuer keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return issuerKeys{}, fmt.Errorf("issuer keys: %d", resp.StatusCode)
	}
	var meta struct {
		Issuer string `json:"issuer"`
		JWKS   struct {
			Keys []struct {
				Kty, Crv, X, Y, Kid string
			} `json:"keys"`
		} `json:"jwks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return issuerKeys{}, fmt.Errorf("issuer keys: %w", err)
	}
	if strings.TrimRight(meta.Issuer, "/") != strings.TrimRight(iss, "/") {
		return issuerKeys{}, errors.New("issuer metadata names another issuer")
	}
	out := issuerKeys{byKID: map[string]*ecdsa.PublicKey{}, fetched: time.Now()}
	for _, k := range meta.JWKS.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(k.X)
		y, errY := base64.RawURLEncoding.DecodeString(k.Y)
		if errX != nil || errY != nil {
			continue
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			continue
		}
		out.byKID[k.Kid] = pub
	}
	if len(out.byKID) == 0 {
		return issuerKeys{}, errors.New("issuer publishes no usable key")
	}
	return out, nil
}

func decodeJSON(seg string, out any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

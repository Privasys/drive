package vaultmek

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakeMinter returns a self-signed leaf; it records the challenge it
// was asked to bind.
type fakeMinter struct {
	challenge []byte
	fail      bool
}

func (f *fakeMinter) mint(_ context.Context, challenge []byte) (*tls.Certificate, error) {
	if f.fail {
		return nil, context.DeadlineExceeded
	}
	f.challenge = append([]byte(nil), challenge...)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fake-identity"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// TestMgmtRefresher_FetchesToken checks the refresher presents the
// minted identity + challenge headers and parses the control plane's
// token response.
func TestMgmtRefresher_FetchesToken(t *testing.T) {
	fm := &fakeMinter{}
	var gotIdentity, gotChallenge string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/keyvaults/operated" {
			http.NotFound(w, r)
			return
		}
		gotIdentity = r.Header.Get("X-Privasys-App-Identity")
		gotChallenge = r.Header.Get("X-Privasys-App-Challenge")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"attestation_token":"tok-123","attestation_token_expires_at":1900000000}`))
	}))
	defer ts.Close()

	refresh := newMgmtRefresher(ts.URL+"/", fm, nil) // trailing slash must be tolerated
	tok, exp, err := refresh(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "tok-123" || exp != 1900000000 {
		t.Fatalf("token = %q exp = %d", tok, exp)
	}
	// The identity header is the minted leaf DER; the challenge header
	// is exactly the challenge the leaf was asked to bind.
	if gotIdentity == "" || gotChallenge == "" {
		t.Fatal("identity/challenge headers missing")
	}
	ch, err := base64.StdEncoding.DecodeString(gotChallenge)
	if err != nil || len(ch) < 8 {
		t.Fatalf("challenge header: %q (%v)", gotChallenge, err)
	}
	if string(ch) != string(fm.challenge) {
		t.Fatal("challenge header does not match the minted binding")
	}
	// Freshness contract: challenge[:8] = big-endian unix seconds ~now.
	tsec := int64(binary.BigEndian.Uint64(ch[:8]))
	if d := time.Since(time.Unix(tsec, 0)); d < -time.Minute || d > time.Minute {
		t.Fatalf("challenge timestamp prefix off by %s", d)
	}
	if _, err := base64.StdEncoding.DecodeString(gotIdentity); err != nil {
		t.Fatalf("identity header is not base64: %v", err)
	}
}

// TestMgmtRefresher_Errors covers non-2xx and empty-token responses.
func TestMgmtRefresher_Errors(t *testing.T) {
	fm := &fakeMinter{}
	status, body := 200, `{"attestation_token":""}`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer ts.Close()
	refresh := newMgmtRefresher(ts.URL, fm, nil)

	if _, _, err := refresh(context.Background()); err == nil {
		t.Fatal("empty token should error")
	}
	status, body = 401, `{"error":"app attestation failed"}`
	if _, _, err := refresh(context.Background()); err == nil {
		t.Fatal("401 should error")
	}
	if _, _, err := newMgmtRefresher(ts.URL, &fakeMinter{fail: true}, nil)(context.Background()); err == nil {
		t.Fatal("mint failure should error")
	}
}

// TestClientTokenCache checks the client caches a refreshed token and
// prefers it while valid.
func TestClientTokenCache(t *testing.T) {
	c := New("", "")
	calls := 0
	c.SetTokenRefresher(func(ctx context.Context) (string, int64, error) {
		calls++
		return "fresh-tok", time.Now().Unix() + 600, nil
	})
	if got := c.cachedFreshToken(time.Now().Unix()); got != "" {
		t.Fatalf("cache should start empty, got %q", got)
	}
	if got, rerr := c.refreshToken(context.Background()); rerr != nil || got != "fresh-tok" {
		t.Fatalf("refreshToken = %q", got)
	}
	if got := c.cachedFreshToken(time.Now().Unix()); got != "fresh-tok" {
		t.Fatalf("cached = %q", got)
	}
	// Expired cache entry is not served.
	c.tokMu.Lock()
	c.freshExp = time.Now().Unix() + 30 // inside the 60s safety margin
	c.tokMu.Unlock()
	if got := c.cachedFreshToken(time.Now().Unix()); got != "" {
		t.Fatalf("near-expiry token should not be served, got %q", got)
	}
	if calls != 1 {
		t.Fatalf("refresher calls = %d", calls)
	}
}

package vaultmek

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mintTestIdentityPEM builds a throwaway self-signed cert + key so the
// fake manager can return something tls.X509KeyPair accepts.
func mintTestIdentityPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test vault client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certPEM, keyPEM
}

// The vault refuses a client identity whose quote does not commit to the
// session channel binder (verify_challenge_binding), so the mint request
// must carry it alongside the challenge whenever the handshake derived
// one. This is the app-leg half of the binding the manager's own vault
// leg already does.
func TestMintForwardsChallengeAndBinder(t *testing.T) {
	challenge := []byte("vault-challenge-nonce-32-bytes!!")
	binder := []byte("session-channel-binder-32-bytes!")

	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer mint-token" {
			t.Errorf("mint auth = %q, want container token bearer", auth)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode mint body: %v", err)
		}
		certPEM, keyPEM := mintTestIdentityPEM(t)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	}))
	defer srv.Close()

	m := NewManagerMinter(srv.URL, "mint-token")
	cert, err := m.mint(context.Background(), challenge, binder)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("mint returned an empty certificate")
	}
	if want := base64.StdEncoding.EncodeToString(challenge); got["challenge_b64"] != want {
		t.Errorf("challenge_b64 = %q, want %q", got["challenge_b64"], want)
	}
	if want := base64.StdEncoding.EncodeToString(binder); got["binder_b64"] != want {
		t.Errorf("binder_b64 = %q, want %q", got["binder_b64"], want)
	}
}

// A non-TLS-1.3 handshake yields no binder; the field is then omitted
// entirely (the vault verifies challenge-only in that case) rather than
// sent empty.
func TestMintOmitsEmptyBinder(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode mint body: %v", err)
		}
		certPEM, keyPEM := mintTestIdentityPEM(t)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	}))
	defer srv.Close()

	m := NewManagerMinter(srv.URL, "mint-token")
	if _, err := m.mint(context.Background(), []byte("challenge"), nil); err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, present := got["binder_b64"]; present {
		t.Error("binder_b64 sent for a binder-less handshake; want the field omitted")
	}
}

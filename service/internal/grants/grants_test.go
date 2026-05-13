package grants

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func TestMintAndParseToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	env := Envelope{
		Iss:   "https://privasys.id",
		Aud:   "privasys-drive",
		Sub:   "tenant-1",
		Node:  "node-1",
		Scope: []Scope{ScopeRead},
		MRTD:  "abcdef",
		JTI:   "grant-1",
		Iat:   time.Now().Unix(),
		Exp:   time.Now().Add(time.Hour).Unix(),
		PK:    base64Pub(pub),
	}
	tok, err := MintToken(priv, env)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseToken(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != env.Sub || got.Node != env.Node {
		t.Fatalf("envelope mismatch: %+v", got)
	}

	// Tampering with the body bytes (after re-encoding) must fail.
	bad := tok[:len(tok)-2] + "AA"
	if _, err := ParseToken(bad); err == nil {
		t.Fatal("tampered token must fail")
	}
}

func TestGrantActiveAndScope(t *testing.T) {
	now := time.Now()
	exp := now.Add(time.Hour)
	g := &Grant{Scope: []Scope{ScopeRead, ScopeShare}, ExpiresAt: &exp}
	if !g.IsActive(now) {
		t.Fatal("grant should be active")
	}
	if !g.HasScope(ScopeRead) || g.HasScope(ScopeWrite) {
		t.Fatal("scope check wrong")
	}
	rev := now
	g.RevokedAt = &rev
	if g.IsActive(now) {
		t.Fatal("revoked grant must not be active")
	}
}

func base64Pub(pk ed25519.PublicKey) string {
	return base64.RawStdEncoding.EncodeToString(pk)
}

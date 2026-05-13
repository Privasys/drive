package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestDeriveDEK_StableForSameInputs(t *testing.T) {
	mek := []byte("0123456789abcdef0123456789abcdef")
	a, err := DeriveDEK(mek, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveDEK(mek, "tenant-1")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("DEK not deterministic: %x vs %x", a, b)
	}
	c, err := DeriveDEK(mek, "tenant-2")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("DEK collision across tenants")
	}
	if len(a) != KeySize {
		t.Fatalf("unexpected key size: %d", len(a))
	}
}

func TestNameHMAC_FixedLengthAndLowercase(t *testing.T) {
	key, _ := RandomKey()
	a := NameHMAC(key, "Foo.PDF")
	b := NameHMAC(key, "foo.pdf")
	if !bytes.Equal(a, b) {
		t.Fatal("NameHMAC not case-folded")
	}
	if len(a) != HMACSize {
		t.Fatalf("HMAC length %d, want %d", len(a), HMACSize)
	}
	c := NameHMAC(key, "different.pdf")
	if bytes.Equal(a, c) {
		t.Fatal("NameHMAC collision")
	}
}

func TestSealOpen_RoundTrip(t *testing.T) {
	key, _ := RandomKey()
	nonce, _ := RandomNonce()
	pt := []byte("hello, drive")
	ct, err := Seal(key, nonce, pt, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, nonce, ct, []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %q", got)
	}
	if _, err := Open(key, nonce, ct, []byte("wrong-aad")); err == nil {
		t.Fatal("open with wrong AAD must fail")
	}
}

func TestWrapUnwrap(t *testing.T) {
	wrap, _ := RandomKey()
	cek, _ := RandomKey()
	w, err := WrapKey(wrap, cek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(wrap, w)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, cek) {
		t.Fatal("wrap/unwrap round trip failed")
	}

	// Tamper with the ciphertext: must fail.
	w[len(w)-1] ^= 0x01
	if _, err := UnwrapKey(wrap, w); err == nil {
		t.Fatal("tampered wrap must fail to unwrap")
	}
}

func TestMerkleRoot_KnownVector(t *testing.T) {
	// Two-chunk input: the root is sha256(h0 || h1).
	h0 := sha256.Sum256([]byte("a"))
	h1 := sha256.Sum256([]byte("b"))
	want := sha256.Sum256(append(h0[:], h1[:]...))
	got := MerkleRoot([][]byte{h0[:], h1[:]})
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("MerkleRoot mismatch: got %s want %s", hex.EncodeToString(got), hex.EncodeToString(want[:]))
	}
}

func TestMerkleRoot_OddDuplicatesLast(t *testing.T) {
	h0 := sha256.Sum256([]byte("a"))
	h1 := sha256.Sum256([]byte("b"))
	h2 := sha256.Sum256([]byte("c"))
	// Odd-length: last hash is duplicated.
	want01 := sha256.Sum256(append(h0[:], h1[:]...))
	want22 := sha256.Sum256(append(h2[:], h2[:]...))
	want := sha256.Sum256(append(want01[:], want22[:]...))
	got := MerkleRoot([][]byte{h0[:], h1[:], h2[:]})
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("odd-length Merkle mismatch")
	}
}

func TestMerkleRoot_DetectsTampering(t *testing.T) {
	hs := [][]byte{}
	for _, b := range []string{"a", "b", "c", "d", "e"} {
		h := sha256.Sum256([]byte(b))
		hs = append(hs, h[:])
	}
	r1 := MerkleRoot(hs)
	hs[2][0] ^= 0x01
	r2 := MerkleRoot(hs)
	if bytes.Equal(r1, r2) {
		t.Fatal("Merkle root failed to detect tampering")
	}
}

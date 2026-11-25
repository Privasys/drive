package vaultmek

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	vsdk "github.com/Privasys/enclave-vaults-client/go/vault"
)

// stored is a vault's stored form of a policy: its own serialisation, every
// field written (here: a default "approval" added, keys sorted).
func stored(t *testing.T, in json.RawMessage) json.RawMessage {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(in, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["approval"]; !ok {
		m["approval"] = nil
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func pd(t *testing.T, b json.RawMessage) string {
	t.Helper()
	d, err := vsdk.PolicyDigestJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// fakeVault answers CanonicalisePolicy with its stored form. asSent selects
// vault-v0.44.0's meaning of pd (the digest of the policy as sent); without
// it, the older meaning (the digest of what it returns).
type fakeVault struct {
	t      *testing.T
	asSent bool
	// lie makes the reported digest wrong; drift makes every answer differ.
	lie, drift bool
	calls      int
	form       func(*testing.T, json.RawMessage) json.RawMessage
}

func (v *fakeVault) CanonicalPolicy(_ context.Context, in json.RawMessage) (json.RawMessage, string, error) {
	v.calls++
	f := v.form
	if f == nil {
		f = stored
	}
	out := f(v.t, in)
	if v.drift {
		var m map[string]any
		_ = json.Unmarshal(out, &m)
		m["n"] = v.calls
		out, _ = json.Marshal(m)
	}
	d := pd(v.t, out)
	if v.asSent {
		d = pd(v.t, in)
	}
	if v.lie {
		d = strings.Repeat("0", 64)
	}
	return out, strings.ToUpper(d), nil
}

const newPolicy = `{"principals":{"tees":[{"name":"drive"}]},"operations":[]}`

func TestStoredFormNewAndOldVaults(t *testing.T) {
	want := stored(t, json.RawMessage(newPolicy))
	for _, asSent := range []bool{true, false} {
		v := &fakeVault{t: t, asSent: asSent}
		got, d, err := storedForm(context.Background(), v, json.RawMessage(newPolicy))
		if err != nil {
			t.Fatalf("asSent=%v: %v", asSent, err)
		}
		if string(got) != string(want) || d != pd(t, want) {
			t.Fatalf("asSent=%v: got %s %s", asSent, got, d)
		}
		if v.calls != 2 {
			t.Fatalf("asSent=%v: %d calls, want 2", asSent, v.calls)
		}
	}
}

func TestStoredFormRefusesWrongDigestOrDrift(t *testing.T) {
	if _, _, err := storedForm(context.Background(), &fakeVault{t: t, asSent: true, lie: true}, json.RawMessage(newPolicy)); err == nil || !strings.Contains(err.Error(), "does not match its digest") {
		t.Fatalf("lying digest: %v", err)
	}
	if _, _, err := storedForm(context.Background(), &fakeVault{t: t, drift: true}, json.RawMessage(newPolicy)); err == nil || !strings.Contains(err.Error(), "not stable") {
		t.Fatalf("drifting form: %v", err)
	}
}

func across(vaults map[string]canonicaliser) func(string) (canonicaliser, func(), error) {
	return func(ep string) (canonicaliser, func(), error) {
		v, ok := vaults[ep]
		if !ok {
			return nil, nil, errors.New("no such vault")
		}
		return v, func() {}, nil
	}
}

func TestCanonicalAcrossNeedsByteIdenticalForms(t *testing.T) {
	ctx := context.Background()
	eps := []string{"a:1", "b:2"}
	same := across(map[string]canonicaliser{
		"a:1": &fakeVault{t: t, asSent: true},
		"b:2": &fakeVault{t: t},
	})
	got, d, err := canonicalAcross(ctx, eps, same, json.RawMessage(newPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if d != pd(t, got) {
		t.Fatal("the digest is not PD of the bytes returned")
	}

	// One member writes the same policy differently: the same digest
	// would not even be checked; the bytes must be identical.
	other := func(t *testing.T, in json.RawMessage) json.RawMessage {
		s := stored(t, in)
		return json.RawMessage(strings.Replace(string(s), ":", ": ", 1))
	}
	differ := across(map[string]canonicaliser{
		"a:1": &fakeVault{t: t, asSent: true},
		"b:2": &fakeVault{t: t, asSent: true, form: other},
	})
	if _, _, err := canonicalAcross(ctx, eps, differ, json.RawMessage(newPolicy)); err == nil || !strings.Contains(err.Error(), "different stored forms") {
		t.Fatalf("differing members: %v", err)
	}

	liar := across(map[string]canonicaliser{
		"a:1": &fakeVault{t: t, asSent: true},
		"b:2": &fakeVault{t: t, asSent: true, lie: true},
	})
	if _, _, err := canonicalAcross(ctx, eps, liar, json.RawMessage(newPolicy)); err == nil || !strings.Contains(err.Error(), "b:2") {
		t.Fatalf("lying member: %v", err)
	}
}

package attrref

import "testing"

// The assurance fallback decides which way an under-specified document is
// read, and it must read towards the government-backed answer: a Drive
// running against an issuer older than the "assurance" field would
// otherwise treat a passport disclosure as something the holder typed.
func TestAssuranceFallsBackToTheIdentityScope(t *testing.T) {
	ref, err := Parse([]byte(`{"attributes":[
		{"key":"nickname","scope":"profile"},
		{"key":"place_of_birth","scope":"identity"},
		{"key":"birthdate","scope":"identity","assurance":"self_asserted","govKey":"birthdate_id"},
		{"key":"birthdate_id","scope":"identity","assurance":"gov_verified","marketplace":{"key":"privasys:birthdate","billable":true}}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]bool{
		"nickname":       false,
		"place_of_birth": true,  // stated nowhere, read from the scope
		"birthdate":      false, // an identity key that says it is the typed one
		"birthdate_id":   true,
	} {
		a, ok := ref.Lookup(key)
		if !ok {
			t.Fatalf("%s missing", key)
		}
		if a.GovBacked() != want {
			t.Errorf("%s: gov-backed = %v, want %v", key, a.GovBacked(), want)
		}
	}

	// The reverse index is how a stored link key reaches the claim that
	// proves it; rebuilding it as "privasys:" + key would land on the
	// self-asserted twin.
	ca, ok := ref.ForMarketplaceKey("privasys:birthdate")
	if !ok || ca.Key != "birthdate_id" {
		t.Fatalf("privasys:birthdate resolved to %q (%v)", ca.Key, ok)
	}
	if _, ok := ref.ForMarketplaceKey("privasys:nickname"); ok {
		t.Fatal("an attribute the registry sells nothing for gained a row")
	}
}

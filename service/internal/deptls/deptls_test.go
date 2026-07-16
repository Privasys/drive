package deptls

import (
	"strings"
	"testing"
)

// TestParseDependencySet covers the fail-closed validation: canonical
// sets parse, empty/typoed ones are rejected.
func TestParseDependencySet(t *testing.T) {
	good := `{"entries":[{"app_id":"a8eb1c97-38b5-4ba4-bf32-e5f922217f71",
		"measurements":[{"tdx":{"mrtd":"aa","rtmr1":"bb","rtmr2":"cc"}}],
		"required_oids":[{"OID":"1.3.6.1.4.1.65230.3.2","ExpectedValue":"c2hh"}]}]}`
	set, err := ParseDependencySet(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Entries) != 1 || set.Entries[0].AppID == "" {
		t.Fatalf("parsed set = %+v", set)
	}
	if string(set.Entries[0].RequiredOids[0].ExpectedValue) != "sha" {
		t.Fatalf("expected value = %q", set.Entries[0].RequiredOids[0].ExpectedValue)
	}

	for name, raw := range map[string]string{
		"empty set":      `{"entries":[]}`,
		"no measurement": `{"entries":[{"app_id":"x","measurements":[],"required_oids":[]}]}`,
		"missing app id": `{"entries":[{"measurements":[{"sgx":"aa"}],"required_oids":[]}]}`,
		"unknown field":  `{"entries":[],"extra":true}`,
		"not json":       `pin please`,
	} {
		if _, err := ParseDependencySet(raw); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// TestParseDependencySet_TrimsWhitespace: configure payloads pasted
// from a terminal often carry stray whitespace.
func TestParseDependencySet_TrimsWhitespace(t *testing.T) {
	raw := "\n  " + `{"entries":[{"app_id":"x","measurements":[{"sgx":"aa"}],"required_oids":[]}]}` + "  \n"
	if _, err := ParseDependencySet(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseDependencySet(strings.TrimSpace(raw) + "{}"); err == nil {
		t.Error("trailing garbage should error")
	}
}

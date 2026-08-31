// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package api

import "testing"

// The configured assistant set is a comma-separated list: one Drive instance
// accepts several assistant enclaves (confidential-ai for chat RAG, the
// Privasys Harness for agent sessions). A single value keeps its historical
// meaning; matching is case-insensitive on app id (OID 3.6) or code hash
// (OID 3.2).
func TestAssistantMeasurementAllowed(t *testing.T) {
	const cai = "3a545cb7740e4d31839b7341359631a2"
	const harness = "be129fce28d740bf85d044a94a78ed43"
	const digest = "b09b839a2dc2c696a06d72d69332d4208894a7caeb9b120f9a1e389427096394"

	cases := []struct {
		name       string
		configured string
		appID      string
		digest     string
		want       bool
	}{
		{"single value, historical", cai, cai, "", true},
		{"single value, wrong peer", cai, harness, "", false},
		{"list admits first", cai + "," + harness, cai, "", true},
		{"list admits second", cai + "," + harness, harness, "", true},
		{"list with spaces", cai + ", " + harness, harness, "", true},
		{"list rejects stranger", cai + "," + harness, "0000000000000000000000000000dead", "", false},
		{"digest form matches", digest, "", digest, true},
		{"case-insensitive", harness, "BE129FCE28D740BF85D044A94A78ED43", "", true},
		{"empty config refuses", "", cai, cai, false},
		{"whitespace-only config refuses", " , ", cai, cai, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := assistantMeasurementAllowed(c.configured, c.appID, c.digest); got != c.want {
				t.Fatalf("assistantMeasurementAllowed(%q, %q, %q) = %v, want %v",
					c.configured, c.appID, c.digest, got, c.want)
			}
		})
	}
}

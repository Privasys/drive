package manifest

import "testing"

// A file's history keeps each revision under its own object id, so a reader
// has to recover that id from the row it came from rather than assume the
// node id. Content written before versioning recorded no reference, which
// is what the fallback covers.
func TestObjectID(t *testing.T) {
	const node = "6f1a3e8c-0000-4000-8000-000000000001"
	for _, tc := range []struct {
		name, ref, want string
	}{
		{"versioned reference", "t/61626364/m/" + node + ".v7", node + ".v7"},
		{"current reference", "t/61626364/m/" + node, node},
		{"no reference recorded", "", node},
	} {
		if got := ObjectID(tc.ref, node); got != tc.want {
			t.Fatalf("%s: ObjectID(%q) = %q, want %q", tc.name, tc.ref, got, tc.want)
		}
	}
}

// The id a version is written under must round-trip through the key layout,
// or history becomes unreadable the moment a manifest moves.
func TestObjectIDRoundTripsManifestKey(t *testing.T) {
	const tenant = "tenant-1"
	for _, id := range []string{"node-1", "node-1.v2", "node-1.v1234567"} {
		if got := ObjectID(manifestKey(tenant, id), "fallback"); got != id {
			t.Fatalf("round trip %q: got %q", id, got)
		}
	}
}

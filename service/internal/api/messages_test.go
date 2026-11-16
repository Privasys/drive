package api

import (
	"strings"
	"testing"
)

// The relay refuses a path that is not rooted, starts with "//", is longer
// than 512 characters or holds whitespace or a backslash.
func TestAppMessagePaths(t *testing.T) {
	req := requestMessage("031b5151-c496-4373-8377-5f17b72795dc", map[string]string{"name": "Test Person"})
	for _, m := range []map[string]any{req, requestMessage("t", nil), responseMessage()} {
		p, _ := m["path"].(string)
		if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || len(p) > 512 ||
			strings.ContainsAny(p, " \t\r\n\\") {
			t.Fatalf("path the relay would refuse: %q", p)
		}
	}
	if req["kind"] != "request" || responseMessage()["kind"] != "response" {
		t.Fatal("wrong kinds")
	}
	if _, ok := requestMessage("t", nil)["presented"]; ok {
		t.Fatal("an empty presented must be left out")
	}
}

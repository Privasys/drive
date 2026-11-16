package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/store"
)

// The relay refuses a path that is not rooted, starts with "//", is longer
// than 512 characters or holds whitespace or a backslash.
func validPath(p string) bool {
	return strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") && len(p) <= 512 &&
		!strings.ContainsAny(p, " \t\r\n\\")
}

func TestAppMessagePaths(t *testing.T) {
	m := responseMessage()
	if m["kind"] != "response" || !validPath(m["path"].(string)) {
		t.Fatalf("response message: %v", m)
	}
}

// The form holds only what the IdP accepts: the documented keys, a short
// title, limited text with nothing invisible, and rooted paths.
func TestRequestForm(t *testing.T) {
	lr := &store.LinkRequest{ID: "5b1e4c1a-0d6f-4b36-9a43-7d1f3b0c2e11", TenantID: "031b5151-c496-4373-8377-5f17b72795dc", Scope: "read"}
	form := requestForm(lr, "Q3‮report.pdf\x00", map[string]string{
		"name":  "Test Person",
		"email": strings.Repeat("a", 201) + "@example.org", // too long: left out, never cut
	})
	var f struct {
		V        int                 `json:"v"`
		ID       string              `json:"id"`
		Title    string              `json:"title"`
		Blocks   []map[string]any    `json:"blocks"`
		Actions  []map[string]string `json:"actions"`
		Callback string              `json:"callback"`
		Link     string              `json:"link"`
	}
	dec := json.NewDecoder(strings.NewReader(form))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("form: %v: %s", err, form)
	}
	if f.V != 1 || f.ID != lr.ID || f.Title == "" || len(f.Title) > 80 || len(f.Actions) != 2 ||
		!validPath(f.Callback) || !validPath(f.Link) {
		t.Fatalf("form: %s", form)
	}
	if strings.ContainsAny(form, "‮\x00") || strings.Contains(form, `\u0000`) {
		t.Fatalf("form keeps an invisible character: %s", form)
	}
	attrs := f.Blocks[0]["values"].(map[string]any)
	if attrs["name"] != "Test Person" || attrs["email"] != nil {
		t.Fatalf("attributes: %v", attrs)
	}
	if formDigest(form) != formDigest(form) || len(formDigest(form)) != 64 {
		t.Fatal("digest")
	}
}

package api

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"*.go", "main.go", true},
		{"*.go", "pkg/a/main.go", true}, // basename at any depth
		{"*.go", "main.txt", false},
		{"pkg/*.go", "pkg/main.go", true},
		{"pkg/*.go", "pkg/a/main.go", false},
		{"pkg/**/*.go", "pkg/main.go", true},
		{"pkg/**/*.go", "pkg/a/b/main.go", true},
		{"**/test_*.py", "a/b/test_x.py", true},
		{"**/test_*.py", "test_x.py", true},
		{"src/**", "src/a/b/c", true},
		{"src/**", "lib/a", false},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.name); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestGrepStreamLinesAndTruncation(t *testing.T) {
	re := regexp.MustCompile(`needle`)
	var out []grepMatch
	long := strings.Repeat("x", 5000) + "needle"
	in := "a needle\nnothing\n" + long + "\nneedle at end"
	n, exhausted := grepStream(strings.NewReader(in), re, "f.txt", 2000, 10, &out)
	if n != int64(len(in)) || exhausted {
		t.Fatalf("read %d exhausted %v", n, exhausted)
	}
	// Line 1 and line 4 match; line 3's needle sits beyond the 2000-byte cap
	// so it is NOT matched (the tool only sees the first max_line_bytes).
	if len(out) != 2 || out[0].Line != 1 || out[1].Line != 4 {
		t.Fatalf("matches %+v", out)
	}
	// Budget exhaustion stops early.
	out = nil
	_, exhausted = grepStream(strings.NewReader("needle\nneedle\nneedle\n"), re, "f", 100, 2, &out)
	if !exhausted || len(out) != 2 {
		t.Fatalf("budget: exhausted %v matches %d", exhausted, len(out))
	}
}

// grep and glob over a granted subtree, via the tool surface.
func TestGrepAndGlobTools(t *testing.T) {
	ts := newFullServer(t, nil)
	_, body := doJSON(t, "POST", ts.URL+"/v1/tenants", devAuth, `{"kind":"user","name":"a"}`)
	var tenant struct{ ID string }
	_ = json.Unmarshal(body, &tenant)
	put := func(p, content string) {
		st, b, _ := rawReq(t, "PUT", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path="+p, devAuth, content, map[string]string{"X-Drive-Parents": "create"})
		if st != 201 {
			t.Fatalf("put %s: %d %s", p, st, b)
		}
	}
	put("proj/src/main.go", "package main\nfunc main() { hello() }\n")
	put("proj/src/util.go", "package main\nfunc hello() {}\n")
	put("proj/README.md", "hello world\n")
	put("other/notes.txt", "hello from outside\n")

	// Resolve the root folder id for "proj".
	_, pb, _ := rawReq(t, "GET", ts.URL+"/v1/tenants/"+tenant.ID+"/path?root=&path=proj", devAuth, "", nil)
	var proj struct{ ID string }
	_ = json.Unmarshal(pb, &proj)

	// grep confined to proj: three hits (main.go, util.go, README), none from other/.
	resp, gb := doJSON(t, "POST", ts.URL+"/tools/grep", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","root":"%s","pattern":"hello"}`, tenant.ID, proj.ID))
	if resp.StatusCode != 200 {
		t.Fatalf("grep: %d %s", resp.StatusCode, gb)
	}
	var g struct {
		Matches      []grepMatch `json:"matches"`
		Truncated    bool        `json:"truncated"`
		BytesScanned int64       `json:"bytes_scanned"`
	}
	_ = json.Unmarshal(gb, &g)
	paths := map[string]int{}
	for _, m := range g.Matches {
		paths[m.Path] = m.Line
	}
	if len(g.Matches) != 3 || paths["src/main.go"] != 2 || paths["src/util.go"] != 2 || paths["README.md"] != 1 || g.BytesScanned == 0 {
		t.Fatalf("grep result %s", gb)
	}
	for p := range paths {
		if strings.HasPrefix(p, "other") {
			t.Fatalf("grep escaped the root: %s", p)
		}
	}
	// include narrows to Go files; max_matches truncates.
	resp, gb = doJSON(t, "POST", ts.URL+"/tools/grep", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","root":"%s","pattern":"hello","include":"*.go","max_matches":1}`, tenant.ID, proj.ID))
	_ = json.Unmarshal(gb, &g)
	if resp.StatusCode != 200 || len(g.Matches) != 1 || !g.Truncated || !strings.HasSuffix(g.Matches[0].Path, ".go") {
		t.Fatalf("grep include/max: %s", gb)
	}
	// Invalid RE2 is a 400, not a crash.
	resp, _ = doJSON(t, "POST", ts.URL+"/tools/grep", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","root":"%s","pattern":"(?<=x)y"}`, tenant.ID, proj.ID))
	if resp.StatusCode != 400 {
		t.Fatalf("lookbehind: want 400, got %d", resp.StatusCode)
	}

	// glob with ** under proj.
	resp, gb = doJSON(t, "POST", ts.URL+"/tools/glob", devAuth,
		fmt.Sprintf(`{"tenant_id":"%s","root":"%s","pattern":"**/*.go"}`, tenant.ID, proj.ID))
	var gl struct {
		Paths     []string `json:"paths"`
		Truncated bool     `json:"truncated"`
	}
	_ = json.Unmarshal(gb, &gl)
	if resp.StatusCode != 200 || len(gl.Paths) != 2 {
		t.Fatalf("glob: %d %s", resp.StatusCode, gb)
	}
	for _, p := range gl.Paths {
		if !strings.HasPrefix(p, "src/") {
			t.Fatalf("glob path %q", p)
		}
	}
}

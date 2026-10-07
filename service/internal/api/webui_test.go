package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/platform"
)

func webUIServer(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"index.html":               "<html><head><script async src=\"/_next/a.js\"></script></head><body>drive</body></html>",
		"l/index.html":             "<html><head></head><body>link</body></html>",
		"_next/static/chunks/a.js": "console.log(1)",
		"index.txt":                "rsc",
	} {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	srv := &Server{WebDir: dir, Platform: platform.Env{AppID: "02104572ca2f41e8ae2d24c0294e6f5e"}}
	return srv.Handler("")
}

func get(t *testing.T, h http.Handler, host, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWebUIServesTheExport(t *testing.T) {
	h := webUIServer(t)
	const host = "drive-demo.apps.test.privasys.org"

	if rec := get(t, h, host, "/"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "drive") {
		t.Fatalf("/ = %d %q", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, host, "/l/?id=x"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "link") {
		t.Fatalf("/l/ = %d %q", rec.Code, rec.Body.String())
	}
	// The config is the first thing in <head>, ahead of every chunk, so a
	// warm cache cannot run the app before it.
	for _, p := range []string{"/", "/l/?id=x"} {
		body := get(t, h, host, p).Body.String()
		if !strings.HasPrefix(body, "<html><head><script>window.__DRIVE_CFG__={") ||
			!strings.Contains(body, `"appHost":"`+host+`"`) {
			t.Fatalf("%s: config not first in head: %q", p, body)
		}
	}
	// The page payload Next fetches when it navigates client-side.
	if rec := get(t, h, host, "/index.txt?_rsc=1"); rec.Code != http.StatusOK || rec.Body.String() != "rsc" {
		t.Fatalf("/index.txt = %d %q", rec.Code, rec.Body.String())
	}
	rec := get(t, h, host, "/_next/static/chunks/a.js")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("static chunk = %d, cache %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	// A share link keeps its query across the redirect to the export's page.
	rec = get(t, h, host, "/l?id=abc&a=email")
	if rec.Code != http.StatusPermanentRedirect || rec.Header().Get("Location") != "/l/?id=abc&a=email" {
		t.Fatalf("/l = %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
	// The API is untouched: an unknown /v1 path is still the API's 404, not
	// the UI.
	if rec := get(t, h, host, "/v1/nope"); strings.Contains(rec.Body.String(), "<html>") {
		t.Fatalf("/v1 served the UI: %q", rec.Body.String())
	}
}

func TestWebUIConfigNamesThePlatform(t *testing.T) {
	h := webUIServer(t)
	cases := map[string]string{
		"drive-demo.apps.test.privasys.org": `"apiBase":"https://api-test.developer.privasys.org"`,
		"privasys-drive.apps.privasys.org":  `"apiBase":"https://api.developer.privasys.org"`,
	}
	for host, want := range cases {
		rec := get(t, h, host, "/privasys-config.js")
		body, _ := io.ReadAll(rec.Body)
		s := string(body)
		if !strings.HasPrefix(s, "window.__DRIVE_CFG__=") || !strings.Contains(s, want) ||
			!strings.Contains(s, `"appHost":"`+host+`"`) ||
			!strings.Contains(s, `"appId":"02104572-ca2f-41e8-ae2d-24c0294e6f5e"`) {
			t.Fatalf("%s: %s", host, s)
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: cache %q", host, rec.Header().Get("Cache-Control"))
		}
	}
	// A Host that is not a plain DNS name is never written into the script.
	rec := get(t, h, `evil";alert(1);".example`, "/privasys-config.js")
	if strings.Contains(rec.Body.String(), "alert") {
		t.Fatalf("hostile host echoed: %s", rec.Body.String())
	}
}

func TestNoWebDirServesAPIOnly(t *testing.T) {
	srv := &Server{}
	h := srv.Handler("")
	if rec := get(t, h, "x.apps.privasys.org", "/privasys-config.js"); rec.Code == http.StatusOK {
		t.Fatalf("config served without a UI: %d", rec.Code)
	}
}

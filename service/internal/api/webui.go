package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// The Drive UI, served from inside the attested image.
//
// The browser shell is a static Next.js export built into the image at
// WebDir, so the code a user runs is part of what the enclave's attestation
// covers; an unattested web host never gets to hand them a different page.
// Its paths are listed in the image's org.privasys.static-unsealed-prefixes
// label (service/Dockerfile), which lets the runtime serve these GET/HEAD
// loads in the clear before a sealed session exists. Everything else stays
// sealed.
//
// The UI learns where its backend is from /privasys-config.js, written here
// per request, so one image serves every platform. An adopter hostname in
// front of Drive is a gateway alias that rewrites Host to the platform
// hostname, so the host named here is always the one the wallet attests.

// webUIPaths are the static prefixes the export produces. Keep in step with
// the static-unsealed-prefixes label in service/Dockerfile.
var webUIPaths = []string{"/_next/", "/l/", "/favicon/", "/favicon.svg"}

// mountWebUI adds the UI to mux when the image carries one; a build without
// WebDir (tests, a bare service) serves the API only.
func (s *Server) mountWebUI(mux *http.ServeMux) {
	if s.WebDir == "" {
		return
	}
	if fi, err := os.Stat(filepath.Join(s.WebDir, "index.html")); err != nil || fi.IsDir() {
		return
	}
	files := http.FileServer(http.Dir(s.WebDir))
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/_next/static/") {
			// Content-hashed names: a new build never reuses one.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
	mux.Handle("GET /{$}", static)
	for _, p := range webUIPaths {
		mux.Handle("GET "+p, static)
	}
	// Share links are /l?id=…#secret; the export's page is /l/. The browser
	// carries the fragment across the redirect.
	mux.HandleFunc("GET /l", func(w http.ResponseWriter, r *http.Request) {
		target := "/l/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
	mux.HandleFunc("GET /privasys-config.js", s.handleWebUIConfig)
}

// webUIConfig is what the UI reads as window.__DRIVE_CFG__.
type webUIConfig struct {
	APIBase string `json:"apiBase"`
	AppID   string `json:"appId"`
	AppHost string `json:"appHost"`
}

var hostnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

func (s *Server) handleWebUIConfig(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}
	if !hostnameRE.MatchString(host) {
		host = ""
	}
	cfg := webUIConfig{APIBase: controlPlaneFor(host), AppID: dashedAppID(s.Platform.AppID), AppHost: host}
	body, _ := json.Marshal(cfg)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte("window.__DRIVE_CFG__=" + string(body) + ";\n"))
}

// controlPlaneFor names the control plane that runs the platform host. The
// runtime does not tell an app which control plane it answers to, so the
// platform's hostname conventions decide, and DRIVE_UI_API_BASE overrides
// both for any other platform.
func controlPlaneFor(host string) string {
	if v := strings.TrimRight(strings.TrimSpace(os.Getenv("DRIVE_UI_API_BASE")), "/"); strings.HasPrefix(v, "https://") {
		return v
	}
	if strings.HasSuffix(host, ".apps.test.privasys.org") {
		return "https://api-test.developer.privasys.org"
	}
	return "https://api.developer.privasys.org"
}

// dashedAppID writes a 32-hex app id in the 8-4-4-4-12 form the control
// plane's URLs use; anything else passes through.
func dashedAppID(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		return id
	}
	return id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
}

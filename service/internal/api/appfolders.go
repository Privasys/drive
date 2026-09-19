package api

// App folders: the holder's window, from Drive, onto the working files an
// app keeps for them in its own storage (the enclave OS's holder folders,
// plan holder-folders §5.9 and Phase 4).
//
//	GET    /v1/app-folders                       the apps that hold a folder for this holder
//	GET    /v1/app-folders/{app}/files?path=     a listing, or a file's bytes
//	DELETE /v1/app-folders/{app}/files?path=     remove a file or a tree
//
// Nothing is copied into Drive. Every call is the holder's own: it must
// carry their bearer (the session token the browser holds), which Drive
// forwards to the app's host, where the enclave OS authenticates it exactly
// as it does the wallet's. Drive adds only the attested dial: the app is
// resolved through the control plane (host, image digest) and the
// connection completes only when the peer proves by quote that it is that
// app running that image (deptls.NewIdentityHTTPClient), so the holder's
// bearer never reaches anything else. The candidate apps are those holding
// a grant on this tenant (apps with access): an app the holder never let
// near their Drive is not asked.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Privasys/drive/service/internal/deptls"
	"github.com/Privasys/drive/service/internal/grants"
	"github.com/Privasys/drive/service/internal/vaultmek"
)

const holderFilesPath = "/__privasys/v1/holders/files"

var appIDPattern = regexp.MustCompile(`^[0-9a-fA-F-]{32,36}$`)

// appFolderView is one app that holds a folder for the holder.
type appFolderView struct {
	AppID       string `json:"app_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Hostname    string `json:"hostname"`
	Label       string `json:"label"`
	UsedBytes   int64  `json:"used_bytes"`
}

// appFolderClient dials one app by identity, forwarding the holder's bearer.
func (s *Server) appFolderClient(ctx context.Context, appID string) (*http.Client, *appResolution, error) {
	cfg := s.CurrentConfig()
	if cfg == nil || cfg.MgmtBaseURL == "" {
		return nil, nil, errNoControlPlane
	}
	res, err := resolveApp(ctx, cfg.MgmtBaseURL, appID)
	if err != nil {
		return nil, nil, err
	}
	v, ok := s.MEKs.(*vaultmek.Client)
	if !ok || v == nil {
		return nil, nil, errNoControlPlane
	}
	return deptls.NewIdentityHTTPClient(strings.ReplaceAll(strings.ToLower(res.AppID), "-", ""), res.ImageDigest, v.AttestationCredentials, cfg.EmbeddingsAllowDebug), res, nil
}

type appResolution struct {
	AppID       string `json:"app_id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Hostname    string `json:"hostname"`
	ImageDigest string `json:"image_digest"`
}

// resolveApp asks the control plane's public resolve endpoint for an app's
// host and deployed image digest.
func resolveApp(ctx context.Context, mgmtBaseURL, appID string) (*appResolution, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	u := strings.TrimRight(mgmtBaseURL, "/") + "/api/v1/apps/" + url.PathEscape(appID) + "/resolve"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errAppUnresolved
	}
	var out appResolution
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return nil, err
	}
	if out.Hostname == "" || out.ImageDigest == "" || out.AppID == "" {
		return nil, errAppUnresolved
	}
	return &out, nil
}

// holderTokenHeader carries the holder's own IdP token on a sealed-session
// call: the sealed envelope leaves Authorization to the session itself, so
// the browser sends the token it holds here instead. It is verified like a
// bearer and must name the session's subject before it is forwarded.
const holderTokenHeader = "X-Holder-Token"

// holderBearer is the credential these calls forward: the holder's own,
// from the bearer or from the header above. Without one the app cannot
// tell whose folder is asked for, so the call is refused with what to do.
func (s *Server) holderBearer(w http.ResponseWriter, r *http.Request, p *Principal) (string, bool) {
	if !p.IsUser() {
		http.Error(w, "only a user may look at their app folders", http.StatusForbidden)
		return "", false
	}
	if p.Bearer != "" {
		return p.Bearer, true
	}
	tok := strings.TrimSpace(r.Header.Get(holderTokenHeader))
	if tok == "" {
		http.Error(w, "app folders need your own session token: send it in "+holderTokenHeader, http.StatusUnauthorized)
		return "", false
	}
	id, err := s.Verifier.Verify(r.Context(), tok)
	if err != nil || id == nil || id.Sub != p.Sub {
		http.Error(w, "the token in "+holderTokenHeader+" is not yours or not valid", http.StatusUnauthorized)
		return "", false
	}
	return tok, true
}

// handleAppFolders lists the apps that hold a folder for the holder: every
// app with a grant on this tenant is asked, with the holder's bearer, whether
// it has one. Apps that do not answer, or answer no, are left out.
func (s *Server) handleAppFolders(w http.ResponseWriter, r *http.Request, p *Principal) {
	bearer, ok := s.holderBearer(w, r, p)
	if !ok {
		return
	}
	tenant, err := s.Store.PersonalTenantOf(r.Context(), p.Sub)
	if err != nil {
		httpError(w, storeErrorStatus(err), err)
		return
	}
	rows, err := s.Grants.ListAppGrantsForTenant(r.Context(), tenant.ID)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	seen := map[string]bool{}
	var apps []string
	for _, g := range rows {
		id := strings.ToLower(strings.TrimSpace(appIDOfGrant(g)))
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		apps = append(apps, id)
	}
	out := make([]appFolderView, 0, len(apps))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range apps {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			cli, res, err := s.appFolderClient(ctx, id)
			if err != nil {
				return
			}
			listing, status, err := fetchHolderListing(ctx, cli, res.Hostname, bearer, "")
			if err != nil || status != http.StatusOK {
				if err != nil {
					log.Printf("app folders: %s: %v", res.Hostname, err)
				}
				return
			}
			mu.Lock()
			out = append(out, appFolderView{AppID: res.AppID, Name: res.Name, DisplayName: res.DisplayName, Hostname: res.Hostname, Label: listing.Label, UsedBytes: listing.UsedBytes})
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"app_folders": out})
}

// holderListing is the enclave OS's answer for a directory.
type holderListing struct {
	Label     string          `json:"label"`
	Path      string          `json:"path"`
	Entries   json.RawMessage `json:"entries"`
	UsedBytes int64           `json:"used_bytes"`
}

func fetchHolderListing(ctx context.Context, cli *http.Client, host, bearer, path string) (*holderListing, int, error) {
	u := "https://" + host + holderFilesPath + "?path=" + url.QueryEscape(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := cli.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var l holderListing
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&l); err != nil {
		return nil, resp.StatusCode, err
	}
	return &l, resp.StatusCode, nil
}

// handleAppFolderFiles forwards GET (listing or bytes) and DELETE for one
// app's folder. The app's answer is relayed as it is: status, type, bytes.
func (s *Server) handleAppFolderFiles(w http.ResponseWriter, r *http.Request, p *Principal) {
	bearer, ok := s.holderBearer(w, r, p)
	if !ok {
		return
	}
	appID := strings.TrimSpace(r.PathValue("app"))
	if !appIDPattern.MatchString(appID) {
		http.Error(w, "app id required", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	cli, res, err := s.appFolderClient(ctx, appID)
	if err != nil {
		http.Error(w, "the app could not be resolved: "+err.Error(), http.StatusBadGateway)
		return
	}
	u := "https://" + res.Hostname + holderFilesPath + "?path=" + url.QueryEscape(r.URL.Query().Get("path"))
	req, err := http.NewRequestWithContext(ctx, r.Method, u, nil)
	if err != nil {
		httpError(w, http.StatusInternalServerError, err)
		return
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if r.Method == http.MethodGet {
		req.Header.Set("Accept", r.Header.Get("Accept"))
	}
	resp, err := cli.Do(req)
	if err != nil {
		http.Error(w, "the app could not be reached: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for _, h := range []string{"Content-Type", "Content-Disposition", "Content-Length", "Last-Modified"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

var (
	errNoControlPlane = errors.New("no control plane is configured for this deployment")
	errAppUnresolved  = errors.New("the control plane does not resolve this app")
)

// appIDOfGrant names the app behind a grant: the id its wallet capability
// recorded, else the grant's subject when it is an app.
func appIDOfGrant(g *grants.Grant) string {
	var meta struct {
		AppID string `json:"app_id"`
	}
	if g.Meta != "" && json.Unmarshal([]byte(g.Meta), &meta) == nil && meta.AppID != "" {
		return meta.AppID
	}
	return grants.NormaliseAppSubject(g.Subject)
}

// Package platform reads the enclave-os-virtual manager's injected
// environment and talks to its loopback API. Off-platform (local dev,
// tests) every field is empty and the helpers are no-ops.
package platform

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// defaultManagerURL is the in-TD manager's loopback API (config-complete
// et al.); the manager listens on :9443.
const defaultManagerURL = "http://localhost:9443"

// Env holds the platform-injected inputs: the app id (for the
// configure-authz role), the manager loopback URL, the per-container
// token and the container name.
type Env struct {
	AppID          string
	ManagerURL     string
	ContainerToken string
	ContainerName  string
}

// Load reads the manager-injected environment.
func Load() Env {
	url := os.Getenv("PRIVASYS_MANAGER_URL")
	if url == "" {
		url = defaultManagerURL
	}
	return Env{
		AppID:          os.Getenv("PRIVASYS_APP_ID"),
		ManagerURL:     url,
		ContainerToken: os.Getenv("PRIVASYS_CONTAINER_TOKEN"),
		ContainerName:  os.Getenv("PRIVASYS_CONTAINER_NAME"),
	}
}

// OnPlatform reports whether the process runs under the enclave manager.
func (e Env) OnPlatform() bool { return e.ContainerName != "" }

// AppIDHex is the undashed lowercase app id, as used in the per-app
// role names (privasys-platform:app:<hex>:owner|admin) and the OID 3.6
// certificate extension.
func (e Env) AppIDHex() string {
	return strings.ToLower(strings.ReplaceAll(e.AppID, "-", ""))
}

// LiftFreeze tells the in-TD manager the app is configured, lifting the
// configure-then-freeze gate without an external /configure call (used
// to recover after a restart). No-op off-platform.
func (e Env) LiftFreeze() error {
	if !e.OnPlatform() {
		return nil
	}
	url := e.ManagerURL + "/api/v1/containers/" + e.ContainerName + "/config-complete"
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+e.ContainerToken)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("config-complete: status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// ErrNotOnPlatform is returned by helpers that require the manager.
var ErrNotOnPlatform = errors.New("platform: not running under the enclave manager")

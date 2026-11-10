package api

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

// A person who signed in without the wallet reaches Drive on a direct name,
// where the runtime stamps the transport and how they signed in. They may
// open what was shared with them, never own a drive; a wallet sign-in on the
// same leg, or any sealed one (no stamp), owns as before.
func TestDirectGuestOwnsNothing(t *testing.T) {
	ts := newFullServer(t, nil)
	call := func(sub, method, path, transport, level string) (*http.Response, []byte) {
		req, _ := http.NewRequest(method, ts.URL+path, nil)
		req.Header.Set("X-Privasys-Sub", sub)
		if transport != "" {
			req.Header.Set("X-Privasys-Transport", transport)
		}
		if level != "" {
			req.Header.Set("X-Privasys-Attestation-Level", level)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, b
	}

	resp, body := call("guest-1", "GET", "/v1/me", "direct", "unverified")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("guest /v1/me: %d %s", resp.StatusCode, body)
	}
	var me struct{ Guest bool }
	_ = json.Unmarshal(body, &me)
	if !me.Guest {
		t.Fatalf("guest /v1/me must say guest: %s", body)
	}
	for _, path := range []string{"/v1/me/tenant", "/v1/tenants"} {
		if resp, body := call("guest-1", "POST", path, "direct", "unverified"); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("guest POST %s: %d %s", path, resp.StatusCode, body)
		}
	}
	// No level at all on a direct request is not the wallet either.
	if resp, _ := call("guest-2", "POST", "/v1/me/tenant", "direct", ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("direct without a level: %d", resp.StatusCode)
	}

	if resp, body := call("wallet-1", "POST", "/v1/me/tenant", "direct", "verified"); resp.StatusCode != http.StatusCreated {
		t.Fatalf("wallet on direct: %d %s", resp.StatusCode, body)
	}
	if resp, body := call("wallet-2", "POST", "/v1/me/tenant", "sealed", ""); resp.StatusCode != http.StatusCreated {
		t.Fatalf("wallet on sealed: %d %s", resp.StatusCode, body)
	}
}

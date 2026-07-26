package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Privasys/drive/service/internal/config"
)

// TestAttestedAssistantAuth covers the FINAL §8.7 gate: the confidential-AI
// enclave is admitted on its ATTESTED identity, with no shared secret
// anywhere, and is refused whenever any part of that identity is missing or
// wrong.
//
// The spoofing case is the important one. These headers are only trustworthy
// because enclave-os strips the X-Privasys-Peer-* namespace from every
// request that did not pass mutual-RA-TLS verification — but Drive must still
// refuse a caller whose verified identity is not the configured peer, so a
// DIFFERENT attested app on the same host cannot read a user's Drive.
func TestAttestedAssistantAuth(t *testing.T) {
	base, srv := newTestServer(t)
	ts := httptest.NewServer(srv.Handler(""))
	t.Cleanup(ts.Close)
	const owner = "user-1"
	const caiAppID = "3a545cb7740e4d31839b7341359631a2"

	// Pin the assistant enclave by app id (OID 3.6). No token configured:
	// this proves the path needs no shared secret at all.
	srv.InstallConfig(&config.Config{
		Mode:                        config.ModeSovereign,
		AssistantEnclaveMeasurement: caiAppID,
	})

	code, b := doReq(t, bearerReq(t, "POST", base.URL+"/v1/tenants", owner, `{"kind":"user","name":"Owner"}`))
	if code != 201 {
		t.Fatalf("tenant: %d %s", code, b)
	}
	var tenant struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(b, &tenant)
	mpayload, _ := json.Marshal(map[string]any{
		"tenant_id": tenant.ID, "name": "pref", "summary": "a pref", "body": "the preference",
	})
	if code, b = doReq(t, bearerReq(t, "POST", ts.URL+"/tools/write_memory", owner, string(mpayload))); code != 200 && code != 201 {
		t.Fatalf("write_memory: %d %s", code, b)
	}

	call := func(hdrs map[string]string) int {
		body, _ := json.Marshal(map[string]any{"tenant_id": tenant.ID})
		req, _ := http.NewRequest("POST", ts.URL+"/tools/get_memory", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range hdrs {
			req.Header.Set(k, v)
		}
		code, _ := doReq(t, req)
		return code
	}

	// Verified peer, correct app id, acting user named: admitted.
	if got := call(map[string]string{
		peerVerifiedHeader: "true",
		peerAppIDHeader:    caiAppID,
		onBehalfOfHeader:   owner,
	}); got != 200 {
		t.Fatalf("attested assistant should be admitted, got %d", got)
	}

	// A DIFFERENT attested app must not be able to read this user's Drive,
	// even though enclave-os verified it: co-located apps share a host.
	if got := call(map[string]string{
		peerVerifiedHeader: "true",
		peerAppIDHeader:    "0000000000000000000000000000dead",
		onBehalfOfHeader:   owner,
	}); got != http.StatusUnauthorized {
		t.Fatalf("wrong attested app must be refused, got %d", got)
	}

	// Peer headers without the verification verdict grant nothing — this is
	// what a client trying to forge the identity would send.
	if got := call(map[string]string{
		peerAppIDHeader:  caiAppID,
		onBehalfOfHeader: owner,
	}); got != http.StatusUnauthorized {
		t.Fatalf("unverified peer must be refused, got %d", got)
	}

	// Verified peer but no acting user: refused rather than defaulting to
	// anyone.
	if got := call(map[string]string{
		peerVerifiedHeader: "true",
		peerAppIDHeader:    caiAppID,
	}); got != http.StatusUnauthorized {
		t.Fatalf("missing on-behalf-of must be refused, got %d", got)
	}

	// With the path unconfigured it stays closed even for a correct peer.
	srv.InstallConfig(&config.Config{Mode: config.ModeSovereign})
	if got := call(map[string]string{
		peerVerifiedHeader: "true",
		peerAppIDHeader:    caiAppID,
		onBehalfOfHeader:   owner,
	}); got != http.StatusUnauthorized {
		t.Fatalf("unconfigured path must be closed, got %d", got)
	}
}

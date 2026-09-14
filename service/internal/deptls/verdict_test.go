// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package deptls

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type scriptedRT struct {
	answers []*http.Response
	bodies  []string
}

func (s *scriptedRT) RoundTrip(req *http.Request) (*http.Response, error) {
	body := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
	}
	s.bodies = append(s.bodies, body)
	resp := s.answers[0]
	s.answers = s.answers[1:]
	return resp, nil
}

func answer(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}
}

const lapsed = `{"error":"caller attestation failed: caller presented a certificate without current evidence on this connection (attest with client evidence)"}`

func TestStaleVerdictIsRetriedOverAFreshDial(t *testing.T) {
	rt := &scriptedRT{answers: []*http.Response{answer(403, lapsed), answer(200, `{"data":[]}`)}}
	evictions := 0
	req, _ := http.NewRequest("POST", "https://confidential-ai.example/v1/embeddings", bytes.NewReader([]byte(`{"input":"acme"}`)))
	resp, err := roundTripStaleVerdict(rt, func() { evictions++ }, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || evictions != 1 || len(rt.bodies) != 2 || rt.bodies[1] != `{"input":"acme"}` {
		t.Fatalf("status=%d evictions=%d bodies=%q; want the request replayed once after one eviction", resp.StatusCode, evictions, rt.bodies)
	}
}

func TestOtherForbiddenPassesThrough(t *testing.T) {
	rt := &scriptedRT{answers: []*http.Response{answer(403, `{"error":"caller is not an allowed caller of this app"}`)}}
	evictions := 0
	req, _ := http.NewRequest("GET", "https://confidential-ai.example/v1/models", nil)
	resp, _ := roundTripStaleVerdict(rt, func() { evictions++ }, req)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 403 || !strings.Contains(string(body), "allowed caller") || evictions != 0 || len(rt.bodies) != 1 {
		t.Fatalf("a policy refusal must pass through untouched: status=%d evictions=%d calls=%d", resp.StatusCode, evictions, len(rt.bodies))
	}
}

func TestUnreplayableBodyEvictsOnClose(t *testing.T) {
	rt := &scriptedRT{answers: []*http.Response{answer(403, lapsed)}}
	evictions := 0
	// A streamed body (no GetBody): the refusal is returned whole and the
	// pool is evicted only once the caller has closed it.
	req, _ := http.NewRequest("POST", "https://confidential-ai.example/v1/embeddings", io.NopCloser(strings.NewReader("stream")))
	if req.GetBody != nil {
		t.Fatal("test premise: a NopCloser body must not be replayable")
	}
	resp, err := roundTripStaleVerdict(rt, func() { evictions++ }, req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || !strings.Contains(string(body), staleVerdictMarker) || evictions != 0 || len(rt.bodies) != 1 {
		t.Fatalf("before close: status=%d evictions=%d calls=%d body=%q", resp.StatusCode, evictions, len(rt.bodies), body)
	}
	resp.Body.Close()
	if evictions != 1 {
		t.Fatalf("closing the refusal must evict the pool once, got %d", evictions)
	}
}

func TestNewHTTPClientCarriesTheVerdictTransport(t *testing.T) {
	set, err := ParseDependencySet(`{"entries":[{"app_id":"x","measurements":[{"sgx":"aa"}],"required_oids":[]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	cli := NewHTTPClient(set, nil, false)
	vt, ok := cli.Transport.(*verdictTransport)
	if !ok {
		t.Fatalf("transport is %T, want the verdict-aware one", cli.Transport)
	}
	if vt.pool == nil || vt.pool.DialTLSContext == nil {
		t.Fatal("the pool must be the attesting transport")
	}
	cli.CloseIdleConnections()
}

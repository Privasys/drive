// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0.

package deptls

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// verdictWindow is how long a pooled verified connection may be reused
// before it is retired. The dependency's runtime records this caller's
// attestation as a verdict PER CONNECTION and forgets it after its
// re-attestation window (enclave-os-virtual ingress, six minutes): from then
// on every request over that connection is refused with "caller presented a
// certificate without current evidence on this connection". A connection
// kept warm by steady traffic (a bulk upload embedding file after file, with
// never a minute of quiet) would otherwise outlive the window and turn into
// a permanent refusal. Idle connections are evicted every half window, so a
// fresh dial, which attests again, happens well inside it.
const verdictWindow = 5 * time.Minute

// staleVerdictMarker is the peer runtime's wording when its verdict for the
// connection is gone: the window passed, or its manager restarted and lost
// the verdict while the TLS connection survived.
const staleVerdictMarker = "without current evidence on this connection"

// verdictTransport is the client's RoundTripper: the pooled transport whose
// dials attest the peer, retired inside the peer's verdict window and healed
// on the peer's lapsed-verdict refusal. The two mechanisms are independent:
// the ticker covers the window, the replay covers a peer manager restart that
// loses verdicts without any window passing.
type verdictTransport struct {
	pool *http.Transport
}

func newVerdictTransport(pool *http.Transport) *verdictTransport {
	t := &verdictTransport{pool: pool}
	// The client lives as long as the process.
	go func() {
		for range time.Tick(verdictWindow / 2) {
			pool.CloseIdleConnections()
		}
	}()
	return t
}

func (t *verdictTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return roundTripStaleVerdict(t.pool, t.pool.CloseIdleConnections, req)
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach the pool.
func (t *verdictTransport) CloseIdleConnections() { t.pool.CloseIdleConnections() }

// roundTripStaleVerdict sends the request and, when the peer's runtime
// answers that it holds no current verdict for the connection, evicts the
// pooled connections and sends the request once more over a fresh, newly
// attested dial. A request whose body cannot be replayed is not retried: the
// refusal is returned as is and the eviction happens when the caller closes
// the body (the connection is only idle, hence evictable, after that), so
// the next request dials anew. Any other 403 passes through untouched: those
// are the peer's decisions about the caller, not about the channel.
func roundTripStaleVerdict(rt http.RoundTripper, evict func(), req *http.Request) (*http.Response, error) {
	resp, err := rt.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusForbidden {
		return resp, err
	}
	if !peekStaleVerdict(resp) {
		return resp, nil
	}
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	if !replayable {
		resp.Body = &evictOnClose{ReadCloser: resp.Body, evict: evict}
		return resp, nil
	}
	log.Printf("[deptls] %s: the peer holds no current verdict for the pooled connection; re-attesting on a fresh dial", req.URL.Host)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	evict()
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		body, gerr := req.GetBody()
		if gerr != nil {
			return nil, fmt.Errorf("deptls: replaying the request after re-attestation: %w", gerr)
		}
		retry.Body = body
	}
	return rt.RoundTrip(retry)
}

// peekStaleVerdict reads the head of a 403 body, reports whether it carries
// the peer runtime's lapsed-verdict wording, and puts the bytes back so the
// caller still reads the whole body.
func peekStaleVerdict(resp *http.Response) bool {
	if resp.Body == nil {
		return false
	}
	head := make([]byte, 4096)
	n, _ := io.ReadFull(resp.Body, head)
	head = head[:n]
	resp.Body = &prefixedBody{Reader: io.MultiReader(bytes.NewReader(head), resp.Body), Closer: resp.Body}
	return bytes.Contains(head, []byte(staleVerdictMarker))
}

// prefixedBody is a response body whose first bytes were already read.
type prefixedBody struct {
	io.Reader
	io.Closer
}

// evictOnClose evicts the pool's idle connections once the caller has closed
// a response that proved the connection's verdict lapsed.
type evictOnClose struct {
	io.ReadCloser
	evict func()
}

func (e *evictOnClose) Close() error {
	err := e.ReadCloser.Close()
	e.evict()
	return err
}

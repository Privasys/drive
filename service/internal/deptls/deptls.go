// Package deptls dials attested cross-enclave dependencies. It builds an
// *http.Client whose TLS leg speaks RA-TLS to a Privasys app host (the
// gateway splices the connection straight to the enclave when the RA-TLS
// ALPN marker is advertised) and completes the handshake only when the
// peer proves, by quote, that it IS the pinned dependency: measurement
// registers plus required OID values (code hash, app id), verified with
// the same certificate matcher the platform uses everywhere else. Any
// mismatch aborts the connection before a byte of application data is
// sent — fail closed.
package deptls

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"
)

// egressIdentity returns this container's manager-minted RA-TLS v2 client
// identity, presented on the dependency dial so a callee running ingress
// mutual RA-TLS can verify WHO is calling (app id + measurement) instead of
// trusting a bearer token. The identity carries no evidence; the manager
// quotes it per connection when the callee requires client evidence. Nil
// off platform (no manager to mint from), which leaves the dial server-auth
// only: a callee that does NOT require a client identity still accepts it,
// and one that DOES rejects the handshake, the correct fail-closed outcome.
func egressIdentity() *ratls.EgressIdentity {
	mgrURL := os.Getenv("PRIVASYS_MANAGER_URL")
	if mgrURL == "" {
		return nil
	}
	return ratls.NewEgressIdentity(mgrURL, os.Getenv("PRIVASYS_CONTAINER_TOKEN"))
}

// CredentialSource supplies the attestation-server endpoint and a
// currently-valid verification token for remote quote verification.
// Called at dial time so a long-lived client always verifies with fresh
// credentials (attestation tokens expire in minutes).
type CredentialSource func(ctx context.Context) (attestationServer, token string, err error)

// ParseDependencySet decodes the canonical dependency-set JSON (the
// exact object the control plane stores and returns on the app record).
// It rejects an empty set: a pinned dialler with nothing pinned would
// be indistinguishable from a typo.
func ParseDependencySet(raw string) (ratls.DependencySet, error) {
	var set ratls.DependencySet
	if err := unmarshalStrict(raw, &set); err != nil {
		return set, fmt.Errorf("dependency set is not valid JSON: %w", err)
	}
	if len(set.Entries) == 0 {
		return set, errors.New("dependency set declares no entries")
	}
	for _, e := range set.Entries {
		if e.AppID == "" {
			return set, errors.New("dependency entry missing app_id")
		}
		if len(e.Measurements) == 0 {
			return set, fmt.Errorf("dependency %s pins no measurement", e.AppID)
		}
	}
	return set, nil
}

// NewHTTPClient returns an *http.Client restricted to pinned attested
// dependencies. Every connection handshakes RA-TLS, verifies the peer's
// quote against the attestation server, and matches the certificate
// against the pinned set; web-PKI verification is intentionally
// replaced, not supplemented (the peer's authority IS its quote).
// allowDebugImages permits dev-profile enclave images and must stay
// false in production.
func NewHTTPClient(set ratls.DependencySet, creds CredentialSource, allowDebugImages bool) *http.Client {
	// Built once and reused across connections; nil off platform
	// (server-auth-only dial).
	id := egressIdentity()
	dial := func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			host, portStr = addr, "443"
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("deptls: port %q: %w", portStr, err)
		}
		server, token, err := creds(ctx)
		if err != nil {
			return nil, fmt.Errorf("deptls: attestation credentials: %w", err)
		}
		// Challenge mode (the default): the peer's evidence is requested after
		// the handshake and bound to this connection's exporter value, so a
		// replayed quote cannot pass. Connect advertises the RA-TLS ALPN marker
		// that routes the gateway onto the splice path (pure L4 to the enclave)
		// and http/1.1 for the transport below.
		opts := &ratls.Options{
			ServerName: host,
			Timeout:    15 * time.Second,
		}
		if id != nil {
			// Mutual leg: present our manager-minted identity, quoted for this
			// connection when the callee requires it (ingress mutual RA-TLS).
			opts.GetClientCertificate = id.GetClientCertificate
			opts.ClientEvidence = id.ClientEvidence
		}
		cli, err := ratls.Connect(host, port, opts)
		if err != nil {
			return nil, fmt.Errorf("deptls: %w", err)
		}
		// Verify before the connection carries any application data: any
		// failure closes it here, so nothing is ever sent to an unverified
		// peer. Web PKI is intentionally replaced (the peer's authority IS its
		// quote); the Privasys intermediate signs the leaf.
		info, err := cli.VerifyCertificate(&ratls.VerificationPolicy{
			TEE:               ratls.TeeTypeTDX,
			QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: server, Token: token},
			AllowDebugImages:  allowDebugImages,
		})
		if err != nil {
			cli.Close()
			return nil, fmt.Errorf("deptls: peer attestation failed: %w", err)
		}
		if err := matchPinned(info, set); err != nil {
			cli.Close()
			return nil, err
		}
		return cli.Conn(), nil
	}
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext:      dial,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
		},
		Timeout: 120 * time.Second,
	}
}

// matchPinned enforces the pin against a verified peer certificate.
// A peer that advertises the app-id OID (4.1) goes through the ordinary
// top-level gate (entry selected by the peer's app id). A standing
// workload certificate without an app id carries only the other workload OIDs,
// so with a single pinned entry the entry is selected by construction —
// this client dials exactly one dependency — and matched in full
// (measurements + required OIDs). Multiple entries without a peer
// app id cannot be disambiguated and fail closed.
func matchPinned(info ratls.CertInfo, set ratls.DependencySet) error {
	if ratls.AppIDFromCert(info) != "" {
		return ratls.VerifyPeerIsDependency(info, ratls.TeeTypeTDX, set)
	}
	if len(set.Entries) != 1 {
		return errors.New("deptls: peer certificate carries no app id and the pin is not a single entry (fail closed)")
	}
	return ratls.MatchDependency(info, ratls.TeeTypeTDX, set.Entries[0])
}

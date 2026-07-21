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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	ratls "enclave-os-mini/clients/go/ratls"
)

// egressClientCert returns the GetClientCertificate callback that presents
// this container's attested client cert on the RA-TLS dial, so a callee
// running ingress mutual RA-TLS can verify WHO is calling (app-id +
// measurement) instead of trusting a bearer token. The manager mints the
// cert per connection, bound to the callee-provided channel binder. Returns
// nil when the manager identity is unavailable (off-platform, tests, or a
// non-ratls build) — the dial then stays server-auth only, which a callee
// that does NOT require a client cert still accepts. Never fatal: a callee
// that DOES require one will reject the certless handshake, which is the
// correct fail-closed behaviour.
func egressClientCert() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	mgrURL := os.Getenv("PRIVASYS_MANAGER_URL")
	if mgrURL == "" {
		return nil
	}
	_, getCert, err := ratls.EgressClientCert(mgrURL, os.Getenv("PRIVASYS_CONTAINER_TOKEN"))
	if err != nil {
		log.Printf("deptls: egress client identity unavailable, dialling server-auth only: %v", err)
		return nil
	}
	return getCert
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
	// Built once and reused across connections: the callback mints a fresh
	// per-connection cert bound to each handshake's channel binder. Nil off
	// platform (server-auth-only dial).
	getClientCert := egressClientCert()
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		server, token, err := creds(ctx)
		if err != nil {
			return nil, fmt.Errorf("deptls: attestation credentials: %w", err)
		}
		nd := &net.Dialer{Timeout: 15 * time.Second}
		raw, err := nd.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		conf := &tls.Config{
			ServerName: host,
			// RA-TLS certificates are self-signed by design; trust is
			// established by the quote check below, never by web PKI.
			InsecureSkipVerify: true,
			// The marker routes the gateway onto the splice path (pure
			// L4 to the enclave); http/1.1 lets the enclave's TLS
			// server negotiate a real protocol. No h2: the transport
			// below speaks HTTP/1.1.
			NextProtos: []string{ratls.RATLSALPNProto, "http/1.1"},
			// Mutual leg: present our attested client cert when the callee
			// requests one (ingress mutual RA-TLS). Nil off platform, which
			// leaves the dial server-auth only.
			GetClientCertificate: getClientCert,
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return errors.New("deptls: peer sent no certificate")
				}
				leaf, err := x509.ParseCertificate(rawCerts[0])
				if err != nil {
					return fmt.Errorf("deptls: parse peer certificate: %w", err)
				}
				info, err := ratls.VerifyRaTlsCert(leaf, &ratls.VerificationPolicy{
					TEE:               ratls.TeeTypeTDX,
					ReportData:        ratls.ReportDataDeterministic,
					QuoteVerification: &ratls.QuoteVerificationConfig{Endpoint: server, Token: token},
					AllowDebugImages:  allowDebugImages,
				})
				if err != nil {
					return fmt.Errorf("deptls: peer attestation failed: %w", err)
				}
				return matchPinned(info, set)
			},
		}
		tc := tls.Client(raw, conf)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
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
// A peer that advertises the management app-id OID goes through the
// ordinary top-level gate (entry selected by the peer's app id). A
// standing workload certificate carries only the 3.1-3.4 workload OIDs,
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

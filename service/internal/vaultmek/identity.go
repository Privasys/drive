package vaultmek

import (
	"context"
	"crypto/tls"
	"strings"

	"enclave-os-mini/clients/go/ratls"
)

// ManagerMinter holds this app's manager-minted RA-TLS v2 client identity
// and produces its evidence on demand. The measured manager is the
// platform's sole identity minter: a certificate it stamps with this app's
// id (OID 4.1) is trustworthy by construction, and the vault authorises the
// app by that id. The identity carries no evidence; a quote committing to
// its key is produced per connection (mutual RA-TLS v2) or per control-plane
// call (header flow), so the certificate itself can be long-lived.
type ManagerMinter struct {
	id *ratls.EgressIdentity
}

// NewManagerMinter builds a minter for the in-TD manager. managerURL may be
// the manager base URL or the legacy mint endpoint
// (.../api/v1/vault-identity); token is the per-app mint token the launcher
// injected.
func NewManagerMinter(managerURL, token string) *ManagerMinter {
	return &ManagerMinter{id: ratls.NewEgressIdentity(managerBase(managerURL), token)}
}

// managerBase strips the legacy mint path so an environment still pointing
// at .../api/v1/vault-identity reaches the manager's identity endpoints.
func managerBase(managerURL string) string {
	return strings.TrimSuffix(strings.TrimSuffix(managerURL, "/"), "/api/v1/vault-identity")
}

// GetClientCertificate returns the TLS GetClientCertificate callback: the
// cached manager-minted identity. Evidence for it is produced per connection
// by ClientEvidence.
func (m *ManagerMinter) GetClientCertificate() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.id.GetClientCertificate
}

// ClientEvidence quotes the presented identity for one connection when the
// vault requires it (client_evidence: required).
func (m *ManagerMinter) ClientEvidence() ratls.ClientEvidenceSource {
	return m.id.ClientEvidence
}

// headerIdentity returns the identity leaf (DER) and a quote proving it for
// the given 32-byte challenge, the credential of the control plane's
// app-identity gate (the quote commits to the leaf key, the challenge and
// ratls.HeaderIdentityHctx).
func (m *ManagerMinter) headerIdentity(_ context.Context, challenge []byte) (der, quote []byte, err error) {
	return m.id.HeaderEvidence(challenge)
}

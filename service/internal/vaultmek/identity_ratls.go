//go:build ratls

package vaultmek

import (
	"context"
	"crypto/tls"
	"errors"
	"time"
)

// GetClientCertificate asks the manager to mint a fresh identity bound
// to the vault's RA-TLS challenge for each connection. The challenge
// arrives on CertificateRequestInfo.RATLSChallenge (the Privasys Go
// fork); production images build with -tags ratls on that toolchain.
// The session channel binder is forwarded alongside so the minted quote
// commits to this exact vault handshake: the vault recomputes the
// binder from its own key schedule and refuses a cert without it
// (verify_challenge_binding), which is what stops a relayed cert from
// another session.
func (m *ManagerMinter) GetClientCertificate() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if len(info.RATLSChallenge) == 0 {
			return nil, errors.New("vaultmek: vault sent no RA-TLS challenge (mutual RA-TLS required)")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return m.mint(ctx, info.RATLSChallenge, info.RATLSChannelBinder)
	}
}

//go:build !ratls

package vaultmek

import (
	"crypto/tls"
	"errors"
)

// GetClientCertificate on a stock-Go build cannot complete mutual
// RA-TLS (the challenge rides a Go-fork TLS field); the production
// image builds with -tags ratls on the forked toolchain. This stub
// keeps tests and local builds compiling.
func (m *ManagerMinter) GetClientCertificate() func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return nil, errors.New("vaultmek: vault identity requires the ratls build (production image)")
	}
}

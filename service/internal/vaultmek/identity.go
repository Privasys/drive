package vaultmek

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ManagerMinter requests one-shot vault client identities from the in-TD
// manager. The measured manager is the platform's sole identity minter:
// a certificate it stamps with this app's id (OID 3.6) is trustworthy by
// construction, and the vault authorises the app by that id. Mutual
// RA-TLS binds the quote to the vault's per-connection challenge, so a
// fresh certificate is minted per connection.
type ManagerMinter struct {
	url   string
	token string
	hc    *http.Client
}

// NewManagerMinter builds a minter for the manager mint endpoint (e.g.
// http://localhost:9443/api/v1/vault-identity) authenticated with the
// per-app mint token the launcher injected.
func NewManagerMinter(managerURL, token string) *ManagerMinter {
	return &ManagerMinter{
		url:   managerURL,
		token: token,
		hc:    &http.Client{Timeout: 15 * time.Second},
	}
}

func (m *ManagerMinter) mint(ctx context.Context, challenge []byte) (*tls.Certificate, error) {
	body, err := json.Marshal(map[string]string{
		"challenge_b64": base64.StdEncoding.EncodeToString(challenge),
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+m.token)
	resp, err := m.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vaultmek: ask manager to mint identity: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("vaultmek: manager mint %s: %s", resp.Status, string(data))
	}
	var out struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("vaultmek: decode mint response: %w", err)
	}
	cert, err := tls.X509KeyPair([]byte(out.CertPEM), []byte(out.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("vaultmek: parse minted certificate: %w", err)
	}
	return &cert, nil
}

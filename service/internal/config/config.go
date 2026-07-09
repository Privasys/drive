// Package config holds the owner-submitted instance configuration,
// persisted on the sealed /data volume so a restart re-applies it (and
// re-lifts the manager's configure-then-freeze gate) with no owner
// present.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Mode is the instance operating mode. It says one thing: whether anyone
// besides a tenant can ever unlock tenant data. Immutable once set — it
// is part of the attested configuration both sides rely on.
type Mode string

const (
	// ModeSovereign: tenant keys have the tenant as the only owner; the
	// operator holds no key and no unlock path.
	ModeSovereign Mode = "sovereign"
	// ModeEscrowed: tenant keys additionally carry an escrow wrap under
	// the org master key, openable only via the audited recovery path.
	ModeEscrowed Mode = "escrowed"
)

// RecoveryPolicy governs escrowed-mode recovery (recover_tenant). It is
// part of the attested configuration, so an escrowed instance's users
// can read exactly which policy governs unlocking their data.
type RecoveryPolicy struct {
	// Issuer is the OIDC issuer that authenticates approvers. Enterprises
	// use their own IdP, so this is not necessarily privasys.id.
	Issuer string `json:"issuer"`
	// Quorum is k: how many distinct approvals a recovery needs.
	Quorum int `json:"quorum"`
	// Approvers are the permitted approver subjects. Empty means the
	// approver *role* (<issuer>:app:<app-id>:approver) is used instead,
	// resolved by the recovery gate.
	Approvers []string `json:"approvers,omitempty"`
	// Disclose records that every recovery is disclosed to the affected
	// user. Forced true — it is the contract of escrowed mode.
	Disclose bool `json:"disclose"`
}

// Config is the persisted instance configuration.
type Config struct {
	Mode              Mode  `json:"mode"`
	QuotaDefaultBytes int64 `json:"quota_default_bytes,omitempty"`

	// MgmtBaseURL is the control-plane API base (e.g.
	// https://api-test.developer.privasys.org). When set, the instance
	// refreshes stale vault attestation tokens itself via its
	// manager-minted app identity instead of waiting for an owner
	// re-arm. Mutable (an ops setting, not part of the trust contract).
	MgmtBaseURL string `json:"mgmt_base_url,omitempty"`

	// Escrowed-mode fields. OrgMEKRef is the vault reference (a
	// vaultmek.Ref JSON) for MEK_org — the org's BYOK master key, a
	// RawShare the attested build reconstructs in-enclave to escrow-wrap
	// tenant MEKs. Recovery is the policy governing recover_tenant.
	OrgMEKRef string          `json:"org_mek_ref,omitempty"`
	Recovery  *RecoveryPolicy `json:"recovery,omitempty"`
}

// DefaultIssuer is used when a recovery policy omits its issuer.
const DefaultIssuer = "https://privasys.id"

// Validate rejects malformed configurations.
func (c *Config) Validate() error {
	if c.MgmtBaseURL != "" &&
		!strings.HasPrefix(c.MgmtBaseURL, "https://") && !strings.HasPrefix(c.MgmtBaseURL, "http://") {
		return errors.New("mgmt_base_url must be an http(s) URL")
	}
	switch c.Mode {
	case ModeSovereign:
		return nil
	case ModeEscrowed:
		if c.OrgMEKRef == "" {
			return errors.New("escrowed mode requires org_mek_ref (the MEK_org vault reference)")
		}
		if c.Recovery == nil {
			return errors.New("escrowed mode requires a recovery policy")
		}
		if c.Recovery.Quorum < 1 {
			return errors.New("recovery.quorum must be at least 1")
		}
		if len(c.Recovery.Approvers) > 0 && len(c.Recovery.Approvers) < c.Recovery.Quorum {
			return fmt.Errorf("recovery lists %d approvers but needs a quorum of %d",
				len(c.Recovery.Approvers), c.Recovery.Quorum)
		}
		if c.Recovery.Issuer == "" {
			c.Recovery.Issuer = DefaultIssuer
		}
		c.Recovery.Disclose = true // the escrowed contract: recovery is always disclosed
		return nil
	case "":
		return errors.New("mode required (sovereign|escrowed)")
	default:
		return fmt.Errorf("unknown mode %q (sovereign|escrowed)", c.Mode)
	}
}

func path(stateDir string) string { return filepath.Join(stateDir, "config.json") }

// Load reads the persisted config from stateDir. Returns (nil, nil) when
// none has been saved yet.
func Load(stateDir string) (*Config, error) {
	b, err := os.ReadFile(path(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path(stateDir), err)
	}
	return &c, nil
}

// Save atomically persists c to stateDir.
func (c *Config) Save(stateDir string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path(stateDir))
}

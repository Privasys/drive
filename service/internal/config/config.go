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

// Config is the persisted instance configuration.
type Config struct {
	Mode              Mode  `json:"mode"`
	QuotaDefaultBytes int64 `json:"quota_default_bytes,omitempty"`
}

// Validate rejects malformed or not-yet-supported configurations.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeSovereign:
		return nil
	case ModeEscrowed:
		// Escrowed needs the MEK_org ceremony + recovery policy (Phase 3).
		return errors.New("escrowed mode requires the org master-key setup, which this build does not ship yet")
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

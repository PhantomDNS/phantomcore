// SPDX-License-Identifier: GPL-3.0-or-later

package ha

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Role is the statically assigned role of a node in an active-passive pair.
type Role string

const (
	// RolePrimary is the preferred active node. It stays active whenever it is
	// running, regardless of peer state.
	RolePrimary Role = "primary"
	// RoleBackup is the standby node. It promotes itself to active only when
	// the peer (primary) is detected down, and demotes on recovery.
	RoleBackup Role = "backup"
)

// Default tuning values for the heartbeat state machine.
const (
	DefaultCheckInterval     = 2 * time.Second
	DefaultFailureThreshold  = 3
	DefaultRecoveryThreshold = 3
	DefaultDialTimeout       = 1 * time.Second
)

// Config holds the active-passive HA configuration. HA is OFF unless Enabled
// is true; a zero Config is a valid, disabled configuration.
type Config struct {
	// Enabled turns the HA heartbeat on. Default OFF.
	Enabled bool
	// Role is primary or backup.
	Role Role
	// PeerAddr is the host:port of the peer node used for liveness probing
	// (e.g. the peer's heartbeat/health endpoint). Required when Enabled.
	PeerAddr string
	// VIP is the virtual IP shared by the pair. It is informational for the
	// heartbeat and is consumed by the keepalived generator.
	VIP string
	// CheckInterval is how often the peer is probed.
	CheckInterval time.Duration
	// FailureThreshold is the number of consecutive failed probes required
	// before the peer is declared down (hysteresis to avoid flapping).
	FailureThreshold int
	// RecoveryThreshold is the number of consecutive successful probes required
	// before a down peer is declared up again.
	RecoveryThreshold int
	// DialTimeout bounds each individual peer probe.
	DialTimeout time.Duration
}

// withDefaults returns a copy of the config with zero-valued tunables filled in.
func (c Config) withDefaults() Config {
	if c.CheckInterval <= 0 {
		c.CheckInterval = DefaultCheckInterval
	}
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = DefaultFailureThreshold
	}
	if c.RecoveryThreshold <= 0 {
		c.RecoveryThreshold = DefaultRecoveryThreshold
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	return c
}

// Validate checks that an enabled configuration is usable. A disabled config
// always validates.
func (c Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	switch c.Role {
	case RolePrimary, RoleBackup:
	default:
		return fmt.Errorf("ha: invalid role %q (want primary or backup)", c.Role)
	}
	if strings.TrimSpace(c.PeerAddr) == "" {
		return fmt.Errorf("ha: HA_PEER_ADDR is required when HA is enabled")
	}
	return nil
}

// ConfigFromEnv builds a Config from environment variables. It performs no
// validation beyond parsing; call Config.Validate (or New) to check it.
//
// Recognized variables:
//
//	HA_ENABLED    "true"/"1" to enable (default off)
//	HA_ROLE       "primary" or "backup"
//	HA_PEER_ADDR  host:port of the peer to probe
//	HA_VIP        virtual IP (informational / used by keepalived generator)
func ConfigFromEnv() Config {
	cfg := Config{
		Enabled:  parseBool(os.Getenv("HA_ENABLED")),
		Role:     Role(strings.ToLower(strings.TrimSpace(os.Getenv("HA_ROLE")))),
		PeerAddr: strings.TrimSpace(os.Getenv("HA_PEER_ADDR")),
		VIP:      strings.TrimSpace(os.Getenv("HA_VIP")),
	}
	return cfg.withDefaults()
}

func parseBool(s string) bool {
	b, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	return b
}

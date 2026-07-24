// SPDX-License-Identifier: GPL-3.0-or-later

package ha

import (
	"testing"
	"time"
)

func TestConfigFromEnv_DefaultDisabled(t *testing.T) {
	// No HA_* variables set -> disabled with sane defaults.
	t.Setenv("HA_ENABLED", "")
	t.Setenv("HA_ROLE", "")
	t.Setenv("HA_PEER_ADDR", "")
	t.Setenv("HA_VIP", "")

	cfg := ConfigFromEnv()
	if cfg.Enabled {
		t.Fatalf("expected HA disabled by default")
	}
	if cfg.CheckInterval != DefaultCheckInterval {
		t.Errorf("CheckInterval = %v, want %v", cfg.CheckInterval, DefaultCheckInterval)
	}
	if cfg.FailureThreshold != DefaultFailureThreshold {
		t.Errorf("FailureThreshold = %d, want %d", cfg.FailureThreshold, DefaultFailureThreshold)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should validate, got %v", err)
	}
}

func TestConfigFromEnv_Enabled(t *testing.T) {
	t.Setenv("HA_ENABLED", "true")
	t.Setenv("HA_ROLE", "Backup") // case/space-insensitive
	t.Setenv("HA_PEER_ADDR", " 10.0.0.1:9000 ")
	t.Setenv("HA_VIP", "192.168.1.100")

	cfg := ConfigFromEnv()
	if !cfg.Enabled {
		t.Fatalf("expected HA enabled")
	}
	if cfg.Role != RoleBackup {
		t.Errorf("Role = %q, want %q", cfg.Role, RoleBackup)
	}
	if cfg.PeerAddr != "10.0.0.1:9000" {
		t.Errorf("PeerAddr = %q, want trimmed value", cfg.PeerAddr)
	}
	if cfg.VIP != "192.168.1.100" {
		t.Errorf("VIP = %q, want 192.168.1.100", cfg.VIP)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("valid enabled config should validate, got %v", err)
	}
}

func TestConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{"disabled always ok", Config{Enabled: false, Role: Role("nonsense")}, false},
		{"enabled primary ok", Config{Enabled: true, Role: RolePrimary, PeerAddr: "h:1"}, false},
		{"enabled bad role", Config{Enabled: true, Role: Role("leader"), PeerAddr: "h:1"}, true},
		{"enabled missing peer", Config{Enabled: true, Role: RoleBackup}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr != (err != nil) {
				t.Fatalf("Validate() err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

func TestConfig_WithDefaults(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.CheckInterval != DefaultCheckInterval {
		t.Errorf("CheckInterval = %v, want %v", cfg.CheckInterval, DefaultCheckInterval)
	}
	if cfg.RecoveryThreshold != DefaultRecoveryThreshold {
		t.Errorf("RecoveryThreshold = %d, want %d", cfg.RecoveryThreshold, DefaultRecoveryThreshold)
	}
	if cfg.DialTimeout != DefaultDialTimeout {
		t.Errorf("DialTimeout = %v, want %v", cfg.DialTimeout, DefaultDialTimeout)
	}
	// Explicit values are preserved.
	custom := Config{CheckInterval: 5 * time.Second}.withDefaults()
	if custom.CheckInterval != 5*time.Second {
		t.Errorf("explicit CheckInterval overwritten: %v", custom.CheckInterval)
	}
}

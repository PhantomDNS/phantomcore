// SPDX-License-Identifier: GPL-3.0-or-later
package config

import (
	"reflect"
	"testing"
)

func TestParseAbusedTLDs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple", "zip,mov,top", []string{"zip", "mov", "top"}},
		{"trims spaces", " zip , mov ,top ", []string{"zip", "mov", "top"}},
		{"lowercases", "ZIP,Mov,TOP", []string{"zip", "mov", "top"}},
		{"drops empties", "zip,,mov,", []string{"zip", "mov"}},
		{"single", "xyz", []string{"xyz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseAbusedTLDs(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseAbusedTLDs(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTLSConfigMode(t *testing.T) {
	tests := []struct {
		name string
		tls  TLSConfig
		want TLSMode
	}{
		{
			name: "default is http",
			tls:  TLSConfig{},
			want: TLSModeDisabled,
		},
		{
			name: "cert and key provided serves tls",
			tls:  TLSConfig{CertFile: "server.crt", KeyFile: "server.key"},
			want: TLSModeProvided,
		},
		{
			name: "cert only is ignored, falls through to disabled",
			tls:  TLSConfig{CertFile: "server.crt"},
			want: TLSModeDisabled,
		},
		{
			name: "key only is ignored, falls through to disabled",
			tls:  TLSConfig{KeyFile: "server.key"},
			want: TLSModeDisabled,
		},
		{
			name: "auto self-signed when no pair provided",
			tls:  TLSConfig{AutoSelfSigned: true},
			want: TLSModeSelfSigned,
		},
		{
			name: "partial pair falls back to self-signed when enabled",
			tls:  TLSConfig{CertFile: "server.crt", AutoSelfSigned: true},
			want: TLSModeSelfSigned,
		},
		{
			name: "provided pair wins over auto self-signed",
			tls:  TLSConfig{CertFile: "server.crt", KeyFile: "server.key", AutoSelfSigned: true},
			want: TLSModeProvided,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.tls.Mode(); got != tc.want {
				t.Fatalf("Mode() = %v, want %v", got, tc.want)
			}
			wantEnabled := tc.want != TLSModeDisabled
			if got := tc.tls.Enabled(); got != wantEnabled {
				t.Fatalf("Enabled() = %v, want %v", got, wantEnabled)
			}
		})
	}
}

func TestApplyDataPlaneGRPCAddrEnv(t *testing.T) {
	t.Run("empty config and empty env falls back to default", func(t *testing.T) {
		t.Setenv("DATAPLANE_GRPC_ADDR", "")

		cfg := ControlPlaneConfig{}
		applyDataPlaneGRPCAddrEnv(&cfg)

		if cfg.DataPlaneGRPCAddr != DefaultDataPlaneGRPCAddr {
			t.Fatalf("DataPlaneGRPCAddr = %q, want default %q", cfg.DataPlaneGRPCAddr, DefaultDataPlaneGRPCAddr)
		}
	})

	t.Run("config file value is kept when env is unset", func(t *testing.T) {
		t.Setenv("DATAPLANE_GRPC_ADDR", "")

		cfg := ControlPlaneConfig{DataPlaneGRPCAddr: "localhost:50051"}
		applyDataPlaneGRPCAddrEnv(&cfg)

		if cfg.DataPlaneGRPCAddr != "localhost:50051" {
			t.Fatalf("DataPlaneGRPCAddr = %q, want %q", cfg.DataPlaneGRPCAddr, "localhost:50051")
		}
	})

	t.Run("env overrides config file value (docker compose topology)", func(t *testing.T) {
		t.Setenv("DATAPLANE_GRPC_ADDR", "dataplane:50051")

		cfg := ControlPlaneConfig{DataPlaneGRPCAddr: "localhost:50051"}
		applyDataPlaneGRPCAddrEnv(&cfg)

		if cfg.DataPlaneGRPCAddr != "dataplane:50051" {
			t.Fatalf("DataPlaneGRPCAddr = %q, want %q (env override)", cfg.DataPlaneGRPCAddr, "dataplane:50051")
		}
	})

	t.Run("env overrides even an empty config file value", func(t *testing.T) {
		t.Setenv("DATAPLANE_GRPC_ADDR", "dataplane:50051")

		cfg := ControlPlaneConfig{}
		applyDataPlaneGRPCAddrEnv(&cfg)

		if cfg.DataPlaneGRPCAddr != "dataplane:50051" {
			t.Fatalf("DataPlaneGRPCAddr = %q, want %q (env override)", cfg.DataPlaneGRPCAddr, "dataplane:50051")
		}
	})
}

func TestDefaultConfigDataPlaneGRPCAddr(t *testing.T) {
	cfg := defaultConfig()
	if cfg.ControlPlane.DataPlaneGRPCAddr != DefaultDataPlaneGRPCAddr {
		t.Fatalf("defaultConfig().ControlPlane.DataPlaneGRPCAddr = %q, want %q",
			cfg.ControlPlane.DataPlaneGRPCAddr, DefaultDataPlaneGRPCAddr)
	}
	// The dataplane's own bind address (used for its GRPCServer.Port listen,
	// see internal/grpc/dataplane.New) and the control-plane's dial address
	// must be independently configurable, even though they share the same
	// bare-metal default value.
	if cfg.DataPlane.GRPCServer.ListenAddr != cfg.ControlPlane.DataPlaneGRPCAddr {
		t.Fatalf("bare-metal defaults should coincide: dataplane bind %q, controlplane dial %q",
			cfg.DataPlane.GRPCServer.ListenAddr, cfg.ControlPlane.DataPlaneGRPCAddr)
	}
}

// TestDefaultConfigMetricsAddr verifies the Prometheus /metrics listener
// defaults to loopback-only (127.0.0.1:9153), not 0.0.0.0. Operators opt into
// wider exposure explicitly via config.yaml or the METRICS_LISTEN_ADDR env var.
func TestDefaultConfigMetricsAddr(t *testing.T) {
	const wantDefault = "127.0.0.1:9153"

	cfg := defaultConfig()
	if cfg.DataPlane.MetricsAddr != wantDefault {
		t.Fatalf("defaultConfig().DataPlane.MetricsAddr = %q, want %q", cfg.DataPlane.MetricsAddr, wantDefault)
	}
}

func TestApplyTLSEnv(t *testing.T) {
	t.Run("empty env fills default self-signed dir", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "")
		t.Setenv("TLS_KEY_FILE", "")
		t.Setenv("TLS_AUTO_SELF_SIGNED", "")
		t.Setenv("TLS_SELF_SIGNED_DIR", "")

		var tls TLSConfig
		applyTLSEnv(&tls)

		if tls.SelfSignedDir != DefaultSelfSignedDir {
			t.Fatalf("SelfSignedDir = %q, want default %q", tls.SelfSignedDir, DefaultSelfSignedDir)
		}
		if tls.Mode() != TLSModeDisabled {
			t.Fatalf("Mode() = %v, want disabled", tls.Mode())
		}
	})

	t.Run("provided cert and key via env", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "/etc/hydra/tls.crt")
		t.Setenv("TLS_KEY_FILE", "/etc/hydra/tls.key")
		t.Setenv("TLS_AUTO_SELF_SIGNED", "")
		t.Setenv("TLS_SELF_SIGNED_DIR", "")

		var tls TLSConfig
		applyTLSEnv(&tls)

		if tls.CertFile != "/etc/hydra/tls.crt" || tls.KeyFile != "/etc/hydra/tls.key" {
			t.Fatalf("cert/key not applied from env: %+v", tls)
		}
		if tls.Mode() != TLSModeProvided {
			t.Fatalf("Mode() = %v, want provided", tls.Mode())
		}
	})

	t.Run("auto self-signed with custom dir via env", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "")
		t.Setenv("TLS_KEY_FILE", "")
		t.Setenv("TLS_AUTO_SELF_SIGNED", "true")
		t.Setenv("TLS_SELF_SIGNED_DIR", "/var/lib/hydra/tls")

		var tls TLSConfig
		applyTLSEnv(&tls)

		if !tls.AutoSelfSigned {
			t.Fatal("AutoSelfSigned should be true")
		}
		if tls.SelfSignedDir != "/var/lib/hydra/tls" {
			t.Fatalf("SelfSignedDir = %q, want /var/lib/hydra/tls", tls.SelfSignedDir)
		}
		if tls.Mode() != TLSModeSelfSigned {
			t.Fatalf("Mode() = %v, want self-signed", tls.Mode())
		}
	})

	t.Run("invalid bool is ignored", func(t *testing.T) {
		t.Setenv("TLS_CERT_FILE", "")
		t.Setenv("TLS_KEY_FILE", "")
		t.Setenv("TLS_AUTO_SELF_SIGNED", "not-a-bool")
		t.Setenv("TLS_SELF_SIGNED_DIR", "")

		tls := TLSConfig{AutoSelfSigned: false}
		applyTLSEnv(&tls)

		if tls.AutoSelfSigned {
			t.Fatal("invalid TLS_AUTO_SELF_SIGNED should leave value unchanged")
		}
	})
}

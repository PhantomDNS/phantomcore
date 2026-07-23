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

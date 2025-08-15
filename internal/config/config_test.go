package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	// Create a temporary config file for testing
	content := `
dataplane:
  listen_addr: "0.0.0.0:53"
  upstream_resolvers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
controlplane:
  listen_addr: "0.0.0.0:8086"
`
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test loading the config
	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Assert values
	if cfg.DataPlane.ListenAddr != "0.0.0.0:53" {
		t.Errorf("expected listen_addr %q, got %q", "0.0.0.0:53", cfg.DataPlane.ListenAddr)
	}
	if len(cfg.DataPlane.UpstreamResolvers) != 2 {
		t.Errorf("expected 2 upstream resolvers, got %d", len(cfg.DataPlane.UpstreamResolvers))
	}
	if cfg.ControlPlane.ListenAddr != "0.0.0.0:8086" {
		t.Errorf("expected listen_addr %q, got %q", "0.0.0.0:8086", cfg.ControlPlane.ListenAddr)
	}
}

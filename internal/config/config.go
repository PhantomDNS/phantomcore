package config

// SPDX-License-Identifier: GPL-3.0-or-later
import (
	"os"
	"strconv"
	"strings"

	"github.com/lopster568/phantomDNS/internal/logger"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataPlane    DataPlaneConfig    `yaml:"dataplane"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`
}

type GRPCServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	Port       int    `yaml:"port"`
}

type DataPlaneConfig struct {
	ListenAddr              string           `yaml:"listen_addr"`
	UpstreamResolvers       []string         `yaml:"upstream_resolvers"`
	GRPCServer              GRPCServerConfig `yaml:"grpc_server"`
	BlocklistUpdateInterval string           `yaml:"blocklist_update_interval"`

	// ThreatBlockThreshold enables enforcement of the heuristic threat detector.
	// When > 0, a query scored suspicious with ThreatScore >= threshold is blocked
	// (or logged as a would-be block when ThreatBlockDryRun is set). 0 disables
	// enforcement, preserving the historical log-only behaviour.
	ThreatBlockThreshold float64 `yaml:"threat_block_threshold"`
	// ThreatBlockDryRun logs would-be threat blocks without actually blocking.
	ThreatBlockDryRun bool `yaml:"threat_block_dryrun"`

	// AbusedTLDs is the set of high-abuse TLDs (e.g. "zip", "mov", "top") to
	// block on the default allow path. Empty (the default) disables the feature.
	AbusedTLDs []string `yaml:"abused_tlds"`

	// RebindProtection rejects upstream answers that map a public name to a
	// private/loopback/link-local IP (DNS rebinding defense). Default false.
	RebindProtection bool `yaml:"rebind_protection"`

	// ClientRateLimitPerSec caps DNS queries accepted per client IP each second.
	// 0 (the default) disables rate limiting entirely.
	ClientRateLimitPerSec int `yaml:"client_rate_limit_per_sec"`
}

type ControlPlaneConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

func defaultConfig() *Config {
	return &Config{
		DataPlane: DataPlaneConfig{
			ListenAddr:              "0.0.0.0:1053",
			UpstreamResolvers:       []string{"8.8.8.8:53", "1.1.1.1:53"},
			BlocklistUpdateInterval: "6h",
			GRPCServer: GRPCServerConfig{
				Port:       50051,
				ListenAddr: "localhost:50051",
			},
		},
		ControlPlane: ControlPlaneConfig{
			ListenAddr: "0.0.0.0:8080",
		},
	}
}

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Log.Warnf("Config file not found (%s), using defaults", path)
		return defaultConfig()
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logger.Log.Errorf("Failed to unmarshal config: %v, using defaults", err)
		return defaultConfig()
	}

	return &cfg
}

var DefaultConfig = func() *Config {
	cfg := loadConfig(configPath())
	if addr := os.Getenv("DNS_LISTEN_ADDR"); addr != "" {
		cfg.DataPlane.ListenAddr = addr
	}
	if interval := os.Getenv("BLOCKLIST_UPDATE_INTERVAL"); interval != "" {
		cfg.DataPlane.BlocklistUpdateInterval = interval
	}
	if v := os.Getenv("THREAT_BLOCK_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.DataPlane.ThreatBlockThreshold = f
		} else {
			logger.Log.Warnf("Invalid THREAT_BLOCK_THRESHOLD %q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("THREAT_BLOCK_DRYRUN"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.ThreatBlockDryRun = b
		} else {
			logger.Log.Warnf("Invalid THREAT_BLOCK_DRYRUN %q, ignoring: %v", v, err)
		}
	}
	if v := os.Getenv("ABUSED_TLDS"); v != "" {
		cfg.DataPlane.AbusedTLDs = parseAbusedTLDs(v)
	}
	if v := os.Getenv("REBIND_PROTECTION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.DataPlane.RebindProtection = b
		} else {
			logger.Log.Warnf("Invalid REBIND_PROTECTION value %q: %v", v, err)
		}
	}
	if v := os.Getenv("CLIENT_RATE_LIMIT_PER_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.DataPlane.ClientRateLimitPerSec = n
		} else {
			logger.Log.Warnf("Invalid CLIENT_RATE_LIMIT_PER_SEC=%q, ignoring: %v", v, err)
		}
	}
	return cfg
}()

// parseAbusedTLDs splits a comma-separated env value into a normalized list of
// TLDs: split on ",", trim surrounding spaces, lowercase, and drop empties.
func parseAbusedTLDs(v string) []string {
	parts := strings.Split(v, ",")
	tlds := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			tlds = append(tlds, p)
		}
	}
	return tlds
}

func configPath() string {
	if p := os.Getenv("PHANTOM_CONFIG"); p != "" {
		return p
	}
	return "/app/configs/config.yaml"
}

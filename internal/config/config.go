package config

// SPDX-License-Identifier: GPL-3.0-or-later
import (
	"os"
	"strconv"

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
	// DNSSECValidation enables validation of RRSIG signatures over upstream answer
	// RRsets. Default false (off): resolution behaviour is unchanged unless enabled.
	DNSSECValidation bool `yaml:"dnssec_validation"`
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
	if v := os.Getenv("DNSSEC_VALIDATION"); v != "" {
		cfg.DataPlane.DNSSECValidation = parseBoolEnv(v, cfg.DataPlane.DNSSECValidation)
	}
	return cfg
}()

// parseBoolEnv parses a boolean environment variable, falling back to def on an
// unparseable value (and logging a warning) rather than silently flipping a flag.
func parseBoolEnv(v string, def bool) bool {
	b, err := strconv.ParseBool(v)
	if err != nil {
		logger.Log.Warnf("invalid boolean env value %q, using %v", v, def)
		return def
	}
	return b
}

func configPath() string {
	if p := os.Getenv("PHANTOM_CONFIG"); p != "" {
		return p
	}
	return "/app/configs/config.yaml"
}

package config

import (
	"os"

	"github.com/lopster568/phantomDNS/internal/logger"
	"gopkg.in/yaml.v3"
)

type Config struct {
	DataPlane    DataPlaneConfig    `yaml:"dataplane"`
	ControlPlane ControlPlaneConfig `yaml:"controlplane"`
}

type DataPlaneConfig struct {
	ListenAddr        string   `yaml:"listen_addr"`
	UpstreamResolvers []string `yaml:"upstream_resolvers"`
}

type ControlPlaneConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

func loadConfig(path string) *Config {
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Log.Error("Failed to read config file: " + err.Error())
		return nil
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		logger.Log.Error("Failed to unmarshal config: " + err.Error())
		return nil
	}

	return &cfg
}

var DefaultConfig = loadConfig("/app/configs/config.yaml")

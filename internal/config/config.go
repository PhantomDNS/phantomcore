package config

import (
	"os"
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

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

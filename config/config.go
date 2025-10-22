package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	BaseDomain string
	Logs       []Log

	CAKeyPath  string
	CACertPath string

	Parallelism int
	Iterations  int
}

// Log configuration. TODO: Make this match the log.v3.json format
type Log struct {
	// PublicKey is the public key to verify log signatures with.
	PublicKey string

	// URL is the url to the write path of the log.
	URL string

	// Monitoring Prefix to read from
	Monitoring string

	// NotAfterStart is the start of the validity range for certificates
	// accepted by this log instance, as an RFC 3339 date.
	NotAfterStart string

	// NotAfterLimit is the end of the validity range (not included) for
	// certificates accepted by this log instance, as an RFC 3339 date.
	NotAfterLimit string
}

func Load(configPath string) (*Config, error) {
	file, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	cfg := Config{}

	if err := yaml.Unmarshal(file, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshalling: %w", err)
	}

	return &cfg, nil
}

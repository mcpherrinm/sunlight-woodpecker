package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"

	"github.com/mcpherrinm/sunlight-woodpecker/internal/issue"
	"github.com/mcpherrinm/sunlight-woodpecker/internal/sunclient"
	"github.com/mcpherrinm/sunlight-woodpecker/internal/woodpecker"
)

type Config struct {
	BaseDomain string
	Logs       []Log

	CAKeyPath  string
	CACertPath string

	Parallelism int
	Iterations  int
}

type Log struct {
	// PublicKey is the public key to verify log signatures with.
	PublicKey string

	// URL is the url to the write path of the log.
	URL string

	// Region is the region for the bucket.
	Region string

	// Bucket is the bucket we'll read tiles from.
	Bucket string

	// Endpoint to connect to the bucket.
	Endpoint string

	// NotAfterStart is the start of the validity range for certificates
	// accepted by this log instance, as an RFC 3339 date.
	NotAfterStart string

	// NotAfterLimit is the end of the validity range (not included) for
	// certificates accepted by this log instance, as an RFC 3339 date.
	NotAfterLimit string
}

func loadConfig(configPath string) (*Config, error) {
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

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	configFlag := flag.String("c", "woodpecker.yaml", "path to the config file")
	flag.Parse()

	cfg, err := loadConfig(*configFlag)
	if err != nil {
		logger.Error("Error loading config", "err", err)
		os.Exit(1)
	}

	issuer, err := issue.New(cfg.CACertPath, cfg.CAKeyPath)
	if err != nil {
		logger.Error("Error creating issuer", "err", err)
		os.Exit(1)
	}

	group, ctx := errgroup.WithContext(context.Background())
	for _, log := range cfg.Logs {
		lc, err := sunclient.New(log.URL, log.PublicKey)
		if err != nil {
			logger.Error("Error setting up log client", "url", log.URL, "err", err)
			os.Exit(2)
		}

		wp, err := woodpecker.New(cfg.BaseDomain, issuer, lc)
		if err != nil {
			logger.Error("Error setting up woodpecker", "url", log.URL, "err", err)
			os.Exit(2)
		}

		for i := 0; i < cfg.Parallelism; i++ {
			group.Go(func() error { return wp.Peck(ctx, cfg.Iterations) })
		}
	}

	if err = group.Wait(); err != nil {
		logger.Error("Error woodpecking", "err", err)
		os.Exit(3)
	}

	logger.Info("success")
}

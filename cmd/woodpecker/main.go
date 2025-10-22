package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"

	"github.com/mcpherrinm/sunlight-woodpecker/config"
	"golang.org/x/sync/errgroup"

	"github.com/mcpherrinm/sunlight-woodpecker/internal/issue"
	"github.com/mcpherrinm/sunlight-woodpecker/internal/woodpecker"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	configFlag := flag.String("c", "woodpecker.yaml", "path to the config file")
	flag.Parse()

	cfg, err := config.Load(*configFlag)
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
		wp, err := woodpecker.New(cfg.BaseDomain, issuer, log)
		if err != nil {
			logger.Error("Error setting up woodpecker", "url", log.URL, "err", err)
			os.Exit(2)
		}

		for range cfg.Parallelism {
			group.Go(func() error {
				var errs []error
				for range cfg.Iterations {
					err := wp.Peck(ctx)
					if err != nil {
						errs = append(errs, err)
					}
				}
				return errors.Join(errs...)
			})
		}
	}

	if err = group.Wait(); err != nil {
		logger.Error("Error woodpecking", "err", err)
		os.Exit(3)
	}

	logger.Info("success")
}

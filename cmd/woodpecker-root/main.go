package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/mcpherrinm/sunlight-woodpecker/internal/issue"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	var certFile = flag.String("certFile", "", "Path to certificate file")
	var keyFile = flag.String("keyFile", "", "Path to key file")
	flag.Parse()

	if *certFile == "" || *keyFile == "" {
		logger.Error("Both -certFile and -keyFile arguments are required")
		os.Exit(1)
	}

	if err := issue.CreateRoot(*certFile, *keyFile); err != nil {
		logger.Error("Error creating root", "err", err)
		os.Exit(1)
	}
}

package main

import (
	"os"

	"charm.land/log/v2"
	"github.com/alecthomas/kong"

	"sshmux/internal/config"
	"sshmux/internal/server"
)

// CLI defines the command-line interface parsed by Kong.
var CLI struct {
	Host    string   `arg:"" optional:"" default:"0.0.0.0:22" help:"Address to listen on (host:port)."`
	Config  string   `short:"c" required:"" help:"Path to the YAML config file."`
	HostKey []string `help:"Path to the SSH host key."`
}

func main() {
	if err := run(); err != nil {
		log.Error("Failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	kong.Parse(&CLI,
		kong.Name("sshmux"),
		kong.Description("A simple SSH multiplexer."),
		kong.UsageOnError(),
	)

	cfg, err := config.Load(CLI.Config)
	if err != nil {
		return err
	}
	return server.Run(server.Options{
		Host:     CLI.Host,
		HostKeys: CLI.HostKey,
		Config:   cfg,
	})
}

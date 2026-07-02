package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"charm.land/log/v2"
	"charm.land/wish/v2"
	"charm.land/wish/v2/logging"
	"github.com/charmbracelet/ssh"
	gossh "golang.org/x/crypto/ssh"

	"sshmux/internal/cloud"
	"sshmux/internal/config"
)

type Options struct {
	Host     string
	HostKeys []string
	Config   *config.Config
	Provider cloud.Providers
}

func Run(opts Options) error {
	providers := opts.Provider
	if providers == nil {
		var err error
		providers, err = cloud.BuildProviders(opts.Config)
		if err != nil {
			return err
		}
	}

	sshOpts := ServerOptions(opts.Config, providers, opts.Host, opts.HostKeys)
	s, err := wish.NewServer(sshOpts...)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	signals := make(chan os.Signal, 3)
	shutdown := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(signals)
	log.Info("Starting SSH muxer", "addr", opts.Host)

	serverErr := make(chan error, 1)
	go func() {
		count := 0
		for range signals {
			count++
			switch count {
			case 1:
				close(shutdown)
			case 2:
				log.Warn("Shutdown pending; press Ctrl-C again to force close active connections")
			default:
				log.Warn("Force closing active connections")
				_ = s.Close()
				return
			}
		}
	}()

	go func() {
		if err := s.ListenAndServe(); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case <-shutdown:
	case err := <-serverErr:
		return fmt.Errorf("server error: %w", err)
	}

	log.Info("Shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil && !errors.Is(err, ssh.ErrServerClosed) {
		return fmt.Errorf("shutdown server: %w", err)
	}
	return nil
}

func ServerOptions(cfg *config.Config, providers cloud.Providers, host string, hostKeys []string) []ssh.Option {
	opts := []ssh.Option{
		wish.WithAddress(host),
		WithPtyRequests(),
		WithAuth(cfg),
		WithSessionRoutingPolicy(cfg),
		wish.WithMiddleware(
			MuxMiddleware(cfg, providers),
			logging.Middleware(),
		),
	}
	for _, key := range hostKeys {
		opts = append(opts, ssh.HostKeyFile(key))
	}
	if len(hostKeys) == 0 {
		opts = append(opts, wish.WithHostKeyPath(".ssh/id_sshmux"))
	}
	return opts
}

func WithSessionRoutingPolicy(cfg *config.Config) ssh.Option {
	return func(srv *ssh.Server) error {
		srv.SessionRequestCallback = func(s ssh.Session, _ string) bool {
			return findRoute(cfg, s.User(), G(s.Context())) != nil
		}
		return nil
	}
}

func ExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	var sshExitErr *gossh.ExitError
	if errors.As(err, &sshExitErr) {
		return sshExitErr.ExitStatus()
	}
	return 1
}

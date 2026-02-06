package serve

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

var (
	DefaultReadTimeout              = 5 * time.Second
	DefaultWriteTimeout             = 10 * time.Second
	DefaultIdleTimeout              = 120 * time.Second
	DefaultReadHeaderTimeout        = 5 * time.Second
	DefaultShutdownDelay            = 5 * time.Second
	DefaultDrainTimeout             = 10 * time.Second
)

func WithDefaults(srv *http.Server) *http.Server {
	if srv.ReadTimeout == 0 {
		srv.ReadTimeout = DefaultReadTimeout
	}
	if srv.ReadHeaderTimeout == 0 {
		srv.ReadHeaderTimeout = DefaultReadHeaderTimeout
	}
	if srv.WriteTimeout == 0 {
		srv.WriteTimeout = DefaultWriteTimeout
	}
	if srv.IdleTimeout == 0 {
		srv.IdleTimeout = DefaultIdleTimeout
	}

	return srv
}

type Config struct {
	ShutdownDelay time.Duration
	DrainTimeout  time.Duration
}

func ListenAndServe(ctx context.Context, srv *http.Server, logger *slog.Logger, cfg Config) error {
	return listenAndShutdown(ctx, srv, logger, srv.ListenAndServe, cfg)
}

func ListenAndServeTLS(ctx context.Context, srv *http.Server, logger *slog.Logger, certFile, keyFile string, cfg Config) error {
	return listenAndShutdown(ctx, srv, logger, func() error {
		return srv.ListenAndServeTLS(certFile, keyFile)
	}, cfg)
}

func listenAndShutdown(ctx context.Context, srv *http.Server, logger *slog.Logger, startFn func() error, cfg Config) error {
	if cfg.ShutdownDelay == 0 {
		cfg.ShutdownDelay = DefaultShutdownDelay
	}
	if cfg.DrainTimeout == 0 {
		cfg.DrainTimeout = DefaultDrainTimeout
	}
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- startFn()
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		logger.Debug("shutdown signal received, waiting for load balancer to deregister", "delay", cfg.ShutdownDelay)
		time.Sleep(cfg.ShutdownDelay)

		logger.Debug("draining existing connections")
		drainCtx, cancel := context.WithTimeout(context.Background(), cfg.DrainTimeout)
		defer cancel()

		if err := srv.Shutdown(drainCtx); err != nil {
			return fmt.Errorf("shutdown failed: %w", err)
		}

		logger.Debug("server shutdown complete")
	}
	return nil
}

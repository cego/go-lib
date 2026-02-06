package serve

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

var (
	DefaultReadTimeout       = 5 * time.Second
	DefaultWriteTimeout      = 10 * time.Second
	DefaultIdleTimeout       = 120 * time.Second
	DefaultReadHeaderTimeout = 5 * time.Second
	DefaultShutdownDelay     = 5 * time.Second
	DefaultDrainTimeout      = 10 * time.Second
)

type Server struct {
	*http.Server
	ShutdownDelay time.Duration
	DrainTimeout  time.Duration
}

func WithDefaults(srv *http.Server) *Server {
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

	return &Server{
		Server:        srv,
		ShutdownDelay: DefaultShutdownDelay,
		DrainTimeout:  DefaultDrainTimeout,
	}
}

func ListenAndServe(ctx context.Context, srv *Server, logger *slog.Logger) error {
	return listenAndShutdown(ctx, srv, logger, srv.ListenAndServe)
}

func ListenAndServeTLS(ctx context.Context, srv *Server, logger *slog.Logger, certFile, keyFile string) error {
	return listenAndShutdown(ctx, srv, logger, func() error {
		return srv.ListenAndServeTLS(certFile, keyFile)
	})
}

func listenAndShutdown(ctx context.Context, srv *Server, logger *slog.Logger, startFn func() error) error {
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- startFn()
	}()

	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		logger.Debug("shutdown signal received, waiting for load balancer to deregister", "delay", srv.ShutdownDelay)
		time.Sleep(srv.ShutdownDelay)

		logger.Debug("draining existing connections")
		drainCtx, cancel := context.WithTimeout(context.Background(), srv.DrainTimeout)
		defer cancel()

		if err := srv.Shutdown(drainCtx); err != nil {
			return fmt.Errorf("shutdown failed: %w", err)
		}

		logger.Debug("server shutdown complete")
	}
	return nil
}

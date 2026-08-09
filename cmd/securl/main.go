package main

import (
	"context"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"securl.click/securl"
)

func main() {
	logger := zerolog.New(os.Stdout).
		Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		stop()
	}()
	args := os.Args[1:]
	if err := run(ctx, args, &logger); err != nil {
		message := "securl stopped"
		if len(args) > 0 && args[0] == "healthcheck" {
			message = "health check failed"
		}
		logger.Error().Err(err).Msg(message)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *zerolog.Logger) error {
	application, err := securl.New(logger)
	if err != nil {
		return err
	}
	if len(args) > 0 && args[0] == "healthcheck" {
		healthContext, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return securl.CheckHealth(
			healthContext, application.ListenNetwork(), application.ListenAddress(),
		)
	}
	listener, err := net.Listen(application.ListenNetwork(), application.ListenAddress())
	if err != nil {
		return err
	}
	defer listener.Close()
	return application.Serve(ctx, listener)
}

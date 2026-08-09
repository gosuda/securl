package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"

	"securl.click/securl"
)

const exitOnStdinEOFEnvironment = "SECURL_EXIT_ON_STDIN_EOF"

func main() {
	logger := zerolog.New(os.Stdout).
		Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()
	if err := loadDotEnv(); err != nil {
		logger.Error().Err(err).Msg("load environment")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	exitOnStdinEOF, err := stdinEOFShutdownEnabled()
	if err != nil {
		logger.Error().Err(err).Msg("invalid environment")
		os.Exit(1)
	}
	if exitOnStdinEOF {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		go shutdownOnStdinEOF(ctx, os.Stdin, cancel, &logger)
	}
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

func loadDotEnv() error {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load .env: %w", err)
	}
	return nil
}

func stdinEOFShutdownEnabled() (bool, error) {
	value, configured := os.LookupEnv(exitOnStdinEOFEnvironment)
	if !configured {
		return false, nil
	}
	enabled, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s: %w", exitOnStdinEOFEnvironment, err)
	}
	return enabled, nil
}

func shutdownOnStdinEOF(
	ctx context.Context, reader io.Reader, cancel context.CancelFunc, logger *zerolog.Logger,
) {
	_, err := io.Copy(io.Discard, reader)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		logger.Warn().Err(err).Msg("parent pipe read failed; shutting down")
	} else {
		logger.Info().Msg("parent pipe closed; shutting down")
	}
	cancel()
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

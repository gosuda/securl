package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	accessservice "securl.click/securl/internal/access"
	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/cleanup"
	"securl.click/securl/internal/config"
	"securl.click/securl/internal/frontend"
	"securl.click/securl/internal/httpapi"
	"securl.click/securl/internal/safebrowsing"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/mariadb"
	"securl.click/securl/internal/store/memory"
	"securl.click/securl/internal/store/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger); err != nil {
		logger.Error("securl stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, logger *slog.Logger) error {
	applicationConfig, err := config.Load()
	if err != nil {
		return err
	}

	var repository store.Repository
	switch applicationConfig.StoreBackend {
	case "memory":
		repository = memory.New()
	case "postgres":
		repository, err = postgres.Open(ctx, applicationConfig.PostgresURL)
		if err != nil {
			return err
		}
	case "mariadb":
		repository, err = mariadb.Open(ctx, applicationConfig.MariaDBDSN)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported store backend")
	}

	var wrapper *captcha.KeyWrapper
	var verifier captcha.Verifier = captcha.NewDisabledVerifier()
	if applicationConfig.CaptchaProvider != securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE {
		wrapper, err = captcha.NewKeyWrapper(applicationConfig.CaptchaWrapKey)
		if err != nil {
			repository.Close()
			return err
		}
		switch applicationConfig.CaptchaProvider {
		case securlv1.CaptchaProvider_CAPTCHA_PROVIDER_TURNSTILE:
			verifier, err = captcha.NewTurnstileVerifier(
				applicationConfig.CaptchaSecretKey,
				applicationConfig.CaptchaAllowedHostnames,
				&http.Client{},
				captcha.DefaultProviderTimeout,
			)
		case securlv1.CaptchaProvider_CAPTCHA_PROVIDER_RECAPTCHA:
			verifier, err = captcha.NewRecaptchaVerifier(
				applicationConfig.CaptchaSecretKey,
				applicationConfig.CaptchaAllowedHostnames,
				&http.Client{},
				captcha.DefaultProviderTimeout,
			)
		}
		if err != nil {
			repository.Close()
			return err
		}
	}
	access := accessservice.NewService(repository, verifier, wrapper)

	var safeBrowsing safebrowsing.LookupClient
	if applicationConfig.SafeBrowsingEnabled {
		client, clientErr := safebrowsing.NewClient(
			applicationConfig.SafeBrowsingAPIKey,
			&http.Client{},
			applicationConfig.SafeBrowsingTimeout,
		)
		if clientErr != nil {
			repository.Close()
			return clientErr
		}
		safeBrowsing = safebrowsing.NewCache(client, applicationConfig.SafeBrowsingCacheEntries)
	}

	frontendHandler, err := frontend.ForMode(applicationConfig.FrontendMode)
	if err != nil {
		repository.Close()
		return err
	}
	runtimeConfig := &securlv1.RuntimeConfig{
		SafeBrowsingEnabled: applicationConfig.SafeBrowsingEnabled,
		CaptchaProvider:     applicationConfig.CaptchaProvider,
		CaptchaSiteKey:      applicationConfig.CaptchaSiteKey,
		AllowedTtlSeconds:   append([]uint32(nil), applicationConfig.AllowedTTLSeconds...),
		DefaultTtlSeconds:   uint32(applicationConfig.DefaultTTL / time.Second),
		MaxUrlBytes:         applicationConfig.MaxURLBytes,
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Repository:         repository,
		Access:             access,
		CaptchaWrapper:     wrapper,
		SafeBrowsing:       safeBrowsing,
		RuntimeConfig:      runtimeConfig,
		AllowedTTLs:        applicationConfig.AllowedTTLSet,
		MaxEnvelopeBytes:   applicationConfig.MaxEnvelopeBytes,
		Frontend:           frontendHandler,
		PublicOrigins:      applicationConfig.PublicOrigins,
		CORSAllowedOrigins: applicationConfig.CORSOrigins,
		EnableHSTS:         applicationConfig.EnableHSTS,
		Logger:             logger,
	})
	server := httpapi.NewServer(applicationConfig.HTTPAddr, router)
	worker := cleanup.NewWorker(
		repository,
		applicationConfig.CleanupInterval,
		applicationConfig.CleanupBatch,
		logger,
	)
	workerContext, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.Run(workerContext)
	}()
	serverError := make(chan error, 1)
	go func() {
		logger.Info("securl listening", "address", applicationConfig.HTTPAddr)
		serverError <- server.ListenAndServe()
	}()

	var listenErr error
	select {
	case <-ctx.Done():
	case listenErr = <-serverError:
		if errors.Is(listenErr, http.ErrServerClosed) {
			listenErr = nil
		}
	}
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
	shutdownErr := server.Shutdown(shutdownContext)
	cancelShutdown()
	cancelWorker()
	<-workerDone
	repository.Close()
	if listenErr != nil {
		return listenErr
	}
	return shutdownErr
}

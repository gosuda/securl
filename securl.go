package securl

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"

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

const gracefulShutdownTimeout = 8 * time.Second

// Application contains the environment-derived configuration required to run SecURL.
type Application struct {
	config          config.Config
	logger          *zerolog.Logger
	openRepository  func(context.Context) (store.Repository, error)
	shutdownTimeout time.Duration
}

type handlerTracker struct {
	handler   http.Handler
	mutex     sync.Mutex
	sealed    bool
	waitGroup sync.WaitGroup
}

func newHandlerTracker(handler http.Handler) *handlerTracker {
	return &handlerTracker{handler: handler}
}
func (tracker *handlerTracker) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	tracker.mutex.Lock()
	if tracker.sealed {
		tracker.mutex.Unlock()
		http.Error(writer, "Server is shutting down.", http.StatusServiceUnavailable)
		return
	}
	tracker.waitGroup.Add(1)
	tracker.mutex.Unlock()
	defer tracker.waitGroup.Done()
	tracker.handler.ServeHTTP(writer, request)
}
func (tracker *handlerTracker) Seal() {
	tracker.mutex.Lock()
	tracker.sealed = true
	tracker.mutex.Unlock()
}

func (tracker *handlerTracker) Wait() {
	tracker.waitGroup.Wait()
}

// New loads the SecURL configuration without opening network or storage resources.
func New(logger *zerolog.Logger) (*Application, error) {
	applicationConfig, err := config.Load()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		nopLogger := zerolog.Nop()
		logger = &nopLogger
	}
	return &Application{
		config: applicationConfig,
		logger: logger,
		openRepository: func(ctx context.Context) (store.Repository, error) {
			return openRepository(ctx, applicationConfig)
		},
		shutdownTimeout: gracefulShutdownTimeout,
	}, nil
}

// ListenNetwork returns tcp or unix for the configured listener.
func (application *Application) ListenNetwork() string {
	return application.config.HTTPNetwork
}

// ListenAddress returns the configured TCP address or Unix socket path.
func (application *Application) ListenAddress() string {
	return application.config.HTTPAddr
}

// Serve runs SecURL on a listener owned by the caller until the context is canceled.
func (application *Application) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("listener is required")
	}
	if ctx.Err() != nil {
		return nil
	}

	repository, err := application.openRepository(ctx)
	if err != nil {
		return err
	}

	var wrapper *captcha.KeyWrapper
	var verifier captcha.Verifier = captcha.NewDisabledVerifier()
	if application.config.CaptchaProvider != securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE {
		wrapper, err = captcha.NewKeyWrapper(application.config.CaptchaWrapKey)
		if err != nil {
			return closeRepositoryAfterError(repository, err)
		}
		switch application.config.CaptchaProvider {
		case securlv1.CaptchaProvider_CAPTCHA_PROVIDER_TURNSTILE:
			verifier, err = captcha.NewTurnstileVerifier(
				application.config.CaptchaSecretKey,
				application.config.CaptchaAllowedHostnames,
				&http.Client{},
				captcha.DefaultProviderTimeout,
			)
		case securlv1.CaptchaProvider_CAPTCHA_PROVIDER_RECAPTCHA:
			verifier, err = captcha.NewRecaptchaVerifier(
				application.config.CaptchaSecretKey,
				application.config.CaptchaAllowedHostnames,
				&http.Client{},
				captcha.DefaultProviderTimeout,
			)
		}
		if err != nil {
			return closeRepositoryAfterError(repository, err)
		}
	}
	access := accessservice.NewService(repository, verifier, wrapper)

	var safeBrowsing safebrowsing.LookupClient
	if application.config.SafeBrowsingEnabled {
		client, clientErr := safebrowsing.NewClient(
			application.config.SafeBrowsingAPIKey,
			&http.Client{},
			application.config.SafeBrowsingTimeout,
		)
		if clientErr != nil {
			return closeRepositoryAfterError(repository, clientErr)
		}
		safeBrowsing = safebrowsing.NewCache(client, application.config.SafeBrowsingCacheEntries)
	}

	frontendHandler, err := frontend.ForMode(application.config.FrontendMode)
	if err != nil {
		return closeRepositoryAfterError(repository, err)
	}
	runtimeConfig := &securlv1.RuntimeConfig{
		SafeBrowsingEnabled:   application.config.SafeBrowsingEnabled,
		CaptchaProvider:       application.config.CaptchaProvider,
		CaptchaSiteKey:        application.config.CaptchaSiteKey,
		AllowedTtlSeconds:     append([]uint32(nil), application.config.AllowedTTLSeconds...),
		DefaultTtlSeconds:     uint32(application.config.DefaultTTL / time.Second),
		MaxUrlBytes:           application.config.MaxURLBytes,
		CreateCaptchaRequired: application.config.CreateCaptchaRequired,
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Repository:         repository,
		Access:             access,
		CaptchaVerifier:    verifier,
		CaptchaWrapper:     wrapper,
		SafeBrowsing:       safeBrowsing,
		RuntimeConfig:      runtimeConfig,
		AllowedTTLs:        application.config.AllowedTTLSet,
		MaxEnvelopeBytes:   application.config.MaxEnvelopeBytes,
		Frontend:           frontendHandler,
		PublicOrigins:      application.config.PublicOrigins,
		CORSAllowedOrigins: application.config.CORSOrigins,
		EnableHSTS:         application.config.EnableHSTS,
		Logger:             application.logger,
	})
	handlers := newHandlerTracker(router)
	server := httpapi.NewServer(handlers, application.logger)
	worker := cleanup.NewWorker(
		repository,
		application.config.CleanupInterval,
		application.config.CleanupBatch,
		application.logger,
	)
	workerContext, cancelWorker := context.WithCancel(context.Background())
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		worker.Run(workerContext)
	}()
	serverError := make(chan error, 1)
	go func() {
		application.logger.Info().
			Str("network", listener.Addr().Network()).
			Str("address", listener.Addr().String()).
			Msg("securl listening")
		serverError <- server.Serve(listener)
	}()

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-serverError:
		if errors.Is(serveErr, http.ErrServerClosed) {
			serveErr = nil
		}
	}
	shutdownErr := shutdownApplication(
		server, handlers, cancelWorker, workerDone, repository, application.shutdownTimeout,
	)
	return errors.Join(serveErr, shutdownErr)
}

func shutdownApplication(
	server *http.Server,
	handlers *handlerTracker,
	cancelWorker context.CancelFunc,
	workerDone <-chan struct{},
	repository store.Repository,
	timeout time.Duration,
) error {
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), timeout)
	defer cancelShutdown()
	cancelWorker()
	gracefulErr := server.Shutdown(shutdownContext)
	handlers.Seal()
	var closeErr error
	if gracefulErr != nil {
		closeErr = server.Close()
	}
	workerStopped := false
	var workerErr error
	select {
	case <-workerDone:
		workerStopped = true
	default:
		select {
		case <-workerDone:
			workerStopped = true
		case <-shutdownContext.Done():
			workerErr = fmt.Errorf("cleanup worker shutdown: %w", shutdownContext.Err())
		}
	}
	var repositoryErr error
	if gracefulErr == nil && workerStopped {
		handlers.Wait()
		repositoryErr = closeRepository(shutdownContext, repository)
	} else {
		closeRepositoryAfterRoutines(handlers, workerDone, repository)
	}
	return errors.Join(gracefulErr, closeErr, workerErr, repositoryErr)
}

func closeRepositoryAfterRoutines(
	handlers *handlerTracker,
	workerDone <-chan struct{},
	repository store.Repository,
) {
	go func() {
		handlers.Wait()
		<-workerDone
		repository.Close()
	}()
}

func closeRepositoryAfterError(repository store.Repository, cause error) error {
	closeContext, cancelClose := context.WithTimeout(context.Background(), gracefulShutdownTimeout)
	defer cancelClose()
	return errors.Join(cause, closeRepository(closeContext, repository))
}

func closeRepository(ctx context.Context, repository store.Repository) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("repository shutdown: %w", err)
	}
	closed := make(chan struct{})
	go func() {
		repository.Close()
		close(closed)
	}()
	select {
	case <-closed:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("repository shutdown: %w", ctx.Err())
	}
}

func openRepository(ctx context.Context, applicationConfig config.Config) (store.Repository, error) {
	switch applicationConfig.StoreBackend {
	case "memory":
		return memory.New(), nil
	case "postgres":
		return postgres.Open(ctx, applicationConfig.PostgresURL)
	case "mariadb":
		return mariadb.Open(ctx, applicationConfig.MariaDBDSN)
	default:
		return nil, errors.New("unsupported store backend")
	}
}

// CheckHealth verifies the SecURL readiness endpoint at an explicit listener target.
func CheckHealth(ctx context.Context, network, address string) error {
	dialer := &net.Dialer{}
	transport := &http.Transport{DialContext: dialer.DialContext}
	var target string
	var err error
	switch network {
	case "tcp", "tcp4", "tcp6":
		target, err = healthCheckURL(address)
	case "unix":
		if address == "" {
			return errors.New("Unix socket path is required")
		}
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", address)
		}
		target = "http://unix/readyz"
	default:
		return fmt.Errorf("unsupported listener network %q", network)
	}
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned %s", response.Status)
	}
	return nil
}

func healthCheckURL(address string) (string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid HTTP listen address %q: %w", address, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/readyz", nil
}

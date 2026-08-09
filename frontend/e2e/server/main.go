package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	accessservice "securl.click/securl/internal/access"
	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/frontend"
	"securl.click/securl/internal/httpapi"
	"securl.click/securl/internal/safebrowsing"
	"securl.click/securl/internal/store/memory"
)

type captchaVerifier struct{}

func (captchaVerifier) Verify(_ context.Context, token string) error {
	if token != "e2e-token" {
		return captcha.ErrCaptchaFailed
	}
	return nil
}

type cleanLookup struct{}

func (cleanLookup) Lookup(context.Context, [][4]byte) (safebrowsing.LookupResult, error) {
	return safebrowsing.LookupResult{CacheSeconds: 60}, nil
}

func main() {
	const origin = "http://127.0.0.1:4179"
	logger := zerolog.Nop()
	repository := memory.New()
	verifier := captchaVerifier{}
	wrapper, err := captcha.NewKeyWrapper(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	if err != nil {
		panic(err)
	}
	access := accessservice.NewService(repository, verifier, wrapper)
	frontendHandler, err := frontend.NewHandler()
	if err != nil {
		panic(err)
	}
	allowedTTLs := map[uint32]struct{}{
		0: {}, 3600: {}, 86400: {}, 604800: {}, 2592000: {},
	}
	router := httpapi.NewRouter(httpapi.Dependencies{
		Repository:      repository,
		Access:          access,
		CaptchaVerifier: verifier,
		CaptchaWrapper:  wrapper,
		SafeBrowsing:    cleanLookup{},
		RuntimeConfig: &securlv1.RuntimeConfig{
			SafeBrowsingEnabled:   true,
			CaptchaProvider:       securlv1.CaptchaProvider_CAPTCHA_PROVIDER_TURNSTILE,
			CaptchaSiteKey:        "e2e-site-key",
			AllowedTtlSeconds:     []uint32{3600, 86400, 604800, 2592000, 0},
			DefaultTtlSeconds:     604800,
			MaxUrlBytes:           8192,
			CreateCaptchaRequired: true,
		},
		AllowedTTLs:      allowedTTLs,
		MaxEnvelopeBytes: 6144,
		Frontend:         frontendHandler,
		PublicOrigins:    map[string]struct{}{origin: {}},
		Logger:           &logger,
	})
	listener, err := net.Listen("tcp", "127.0.0.1:4179")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	server := httpapi.NewServer(router, &logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		panic(err)
	}
	repository.Close()
}

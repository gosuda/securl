package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRunStartsAndShutsDownMemoryExternalMode(t *testing.T) {
	t.Setenv("SECURL_HTTP_ADDR", "127.0.0.1:65535")
	t.Setenv("HOST", "127.0.0.1")
	t.Setenv("PORT", "0")
	t.Setenv("SECURL_PUBLIC_ORIGINS", "https://one.example,https://two.example")
	t.Setenv("SECURL_STORE_BACKEND", "memory")
	t.Setenv("SECURL_FRONTEND_MODE", "external")
	t.Setenv("SECURL_CORS_ALLOWED_ORIGINS", "https://app.example")
	t.Setenv("SECURL_SAFE_BROWSING_ENABLED", "false")
	t.Setenv("SECURL_CAPTCHA_PROVIDER", "none")
	t.Setenv("SECURL_CREATE_CAPTCHA_REQUIRED", "false")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	done := make(chan error, 1)
	go func() { done <- run(ctx, logger) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not shut down")
	}
}

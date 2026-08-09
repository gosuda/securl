package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type channelWriter chan []byte

func (writer channelWriter) Write(message []byte) (int, error) {
	copyOfMessage := append([]byte(nil), message...)
	writer <- copyOfMessage
	return len(message), nil
}

func setMainTestEnvironment(t *testing.T, host, port string) {
	t.Helper()
	t.Setenv("HOST", host)
	t.Setenv("IP", "invalid")
	t.Setenv("PORT", port)
	t.Setenv("SECURL_PUBLIC_ORIGINS", "https://one.example")
	t.Setenv("SECURL_STORE_BACKEND", "memory")
	t.Setenv("SECURL_FRONTEND_MODE", "external")
	t.Setenv("SECURL_CORS_ALLOWED_ORIGINS", "https://app.example")
	t.Setenv("SECURL_SAFE_BROWSING_ENABLED", "false")
	t.Setenv("SECURL_CAPTCHA_PROVIDER", "none")
	t.Setenv("SECURL_CREATE_CAPTCHA_REQUIRED", "false")
}

func unixSocketPath(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "securl-main-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return filepath.Join(directory, "s.sock")
}

func TestRunCreatesListenerAndServesApplication(t *testing.T) {
	setMainTestEnvironment(t, "127.0.0.1", "0")
	logMessages := make(channelWriter, 8)
	logger := zerolog.New(logMessages)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, nil, &logger) }()

	var address string
	select {
	case message := <-logMessages:
		var entry map[string]any
		if err := json.Unmarshal(message, &entry); err != nil {
			t.Fatal(err)
		}
		address, _ = entry["address"].(string)
	case <-time.After(5 * time.Second):
		t.Fatal("application did not start")
	}
	if address == "" {
		t.Fatal("listening address was not logged")
	}
	response, err := http.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("service did not shut down")
	}
}

func TestRunHealthCheckCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/readyz" {
			t.Fatalf("path=%q", request.URL.Path)
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	setMainTestEnvironment(t, host, port)
	logger := zerolog.Nop()
	if err := run(context.Background(), []string{"healthcheck"}, &logger); err != nil {
		t.Fatal(err)
	}
}

func TestRunCreatesUnixSocketAndHealthCheck(t *testing.T) {
	setMainTestEnvironment(t, "127.0.0.1", "0")
	socketPath := unixSocketPath(t)
	t.Setenv("SECURL_HTTP_ADDR", "unix:"+socketPath)
	logMessages := make(channelWriter, 8)
	logger := zerolog.New(logMessages)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- run(ctx, nil, &logger) }()

	select {
	case message := <-logMessages:
		var entry map[string]any
		if err := json.Unmarshal(message, &entry); err != nil {
			t.Fatal(err)
		}
		if entry["network"] != "unix" || entry["address"] != socketPath {
			t.Fatalf("entry=%v", entry)
		}
	case err := <-done:
		t.Fatalf("Unix socket application failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Unix socket application did not start")
	}
	healthLogger := zerolog.Nop()
	if err := run(context.Background(), []string{"healthcheck"}, &healthLogger); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Unix socket service did not shut down")
	}
}

func TestExitOnStdinEOFEnvironmentStopsApplication(t *testing.T) {
	setMainTestEnvironment(t, "127.0.0.1", "0")
	socketPath := unixSocketPath(t)
	t.Setenv("SECURL_HTTP_ADDR", "unix:"+socketPath)
	t.Setenv(exitOnStdinEOFEnvironment, "true")
	logMessages := make(channelWriter, 8)
	logger := zerolog.New(logMessages)
	reader, writer := io.Pipe()
	t.Cleanup(func() {
		_ = reader.Close()
		_ = writer.Close()
	})

	enabled, err := stdinEOFShutdownEnabled()
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go shutdownOnStdinEOF(ctx, reader, cancel, &logger)
	done := make(chan error, 1)
	go func() { done <- run(ctx, nil, &logger) }()

	select {
	case <-logMessages:
	case err := <-done:
		t.Fatalf("application failed to start: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("application did not start")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("application did not stop after parent pipe EOF")
	}
}

func TestStdinEOFEnvironmentLoadsFromDotEnv(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(directory, ".env"),
		[]byte(exitOnStdinEOFEnvironment+"=true\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	original, configured := os.LookupEnv(exitOnStdinEOFEnvironment)
	if err := os.Unsetenv(exitOnStdinEOFEnvironment); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if configured {
			_ = os.Setenv(exitOnStdinEOFEnvironment, original)
		} else {
			_ = os.Unsetenv(exitOnStdinEOFEnvironment)
		}
	})
	t.Chdir(directory)

	if err := loadDotEnv(); err != nil {
		t.Fatal(err)
	}
	enabled, err := stdinEOFShutdownEnabled()
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
}

func TestRunCleanupRejectsMemoryStore(t *testing.T) {
	setMainTestEnvironment(t, "127.0.0.1", "0")
	logger := zerolog.Nop()
	err := run(context.Background(), []string{"cleanup"}, &logger)
	if err == nil || !strings.Contains(err.Error(), "persistent store backend") {
		t.Fatalf("err=%v", err)
	}
}

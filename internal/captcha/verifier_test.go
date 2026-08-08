package captcha

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteVerifierSendsOnlySecretAndTokenAndChecksHostname(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		if request.Form.Get("secret") != "secret" || request.Form.Get("response") != "token" {
			t.Errorf("unexpected form fields: %v", request.Form)
		}
		if request.Form.Has("remoteip") || len(request.Form) != 2 {
			t.Errorf("privacy-sensitive form fields sent: %v", request.Form)
		}
		writer.Header().Set("Content-Type", "application/json")
		fmt.Fprint(writer, `{"success":true,"hostname":"example.com"}`)
	}))
	defer server.Close()

	verifier, err := newRemoteVerifier(
		server.URL,
		"secret",
		[]string{"example.com"},
		server.Client(),
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), "token"); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteVerifierFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{
			name: "provider rejection",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(writer, `{"success":false}`)
			},
			timeout: time.Second,
		},
		{
			name: "hostname mismatch",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				fmt.Fprint(writer, `{"success":true,"hostname":"other.example"}`)
			},
			timeout: time.Second,
		},
		{
			name: "dependency status",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusServiceUnavailable)
			},
			timeout: time.Second,
		},
		{
			name: "timeout",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				time.Sleep(50 * time.Millisecond)
				fmt.Fprint(writer, `{"success":true,"hostname":"example.com"}`)
			},
			timeout: 5 * time.Millisecond,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			verifier, err := newRemoteVerifier(
				server.URL,
				"secret",
				[]string{"example.com"},
				server.Client(),
				test.timeout,
			)
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.Verify(context.Background(), "token")
			if err == nil {
				t.Fatal("verification unexpectedly succeeded")
			}
		})
	}
}

func TestRemoteVerifierValidatesTokenAndConcurrencyBeforeCallingProvider(t *testing.T) {
	verifier, err := newRemoteVerifier(
		"https://example.invalid",
		"secret",
		[]string{"example.com"},
		http.DefaultClient,
		time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), ""); !errors.Is(err, ErrCaptchaFailed) {
		t.Fatalf("empty token error = %v", err)
	}
	if err := verifier.Verify(context.Background(), strings.Repeat("x", MaxTokenBytes+1)); !errors.Is(err, ErrCaptchaFailed) {
		t.Fatalf("oversized token error = %v", err)
	}
	verifier.semaphore = make(chan struct{}, 1)
	verifier.semaphore <- struct{}{}
	if err := verifier.Verify(context.Background(), "token"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("saturated verifier error = %v", err)
	}
}

func TestProviderConstructorsUseFixedEndpoints(t *testing.T) {
	turnstile, err := NewTurnstileVerifier("secret", []string{"example.com"}, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if turnstile.(*remoteVerifier).endpoint != turnstileEndpoint {
		t.Fatal("Turnstile endpoint changed")
	}
	recaptcha, err := NewRecaptchaVerifier("secret", []string{"example.com"}, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if recaptcha.(*remoteVerifier).endpoint != recaptchaEndpoint {
		t.Fatal("reCAPTCHA endpoint changed")
	}
}

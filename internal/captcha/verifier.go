package captcha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrCaptchaFailed         = errors.New("captcha: verification failed")
	ErrDependencyUnavailable = errors.New("captcha: dependency unavailable")
	ErrFeatureUnavailable    = errors.New("captcha: feature unavailable")
	ErrRateLimited           = errors.New("captcha: rate limited")
)

const (
	DefaultProviderTimeout = 3 * time.Second
	MaxTokenBytes          = 4096
	MaxConcurrentRequests  = 32
)

type Verifier interface {
	Verify(context.Context, string) error
}

type providerResponse struct {
	Success  bool     `json:"success"`
	Hostname string   `json:"hostname"`
	Errors   []string `json:"error-codes"`
}

type remoteVerifier struct {
	endpoint         string
	secret           string
	allowedHostnames map[string]struct{}
	client           *http.Client
	timeout          time.Duration
	semaphore        chan struct{}
}

func newRemoteVerifier(
	endpoint string,
	secret string,
	allowedHostnames []string,
	client *http.Client,
	timeout time.Duration,
) (*remoteVerifier, error) {
	if secret == "" || len(allowedHostnames) == 0 {
		return nil, ErrFeatureUnavailable
	}
	allowed := make(map[string]struct{}, len(allowedHostnames))
	for _, hostname := range allowedHostnames {
		if hostname == "" || strings.TrimSpace(hostname) != hostname {
			return nil, ErrFeatureUnavailable
		}
		allowed[hostname] = struct{}{}
	}
	if client == nil {
		client = &http.Client{}
	}
	if timeout <= 0 {
		timeout = DefaultProviderTimeout
	}
	return &remoteVerifier{
		endpoint:         endpoint,
		secret:           secret,
		allowedHostnames: allowed,
		client:           client,
		timeout:          timeout,
		semaphore:        make(chan struct{}, MaxConcurrentRequests),
	}, nil
}

func (verifier *remoteVerifier) Verify(ctx context.Context, token string) error {
	if len(token) < 1 || len(token) > MaxTokenBytes {
		return ErrCaptchaFailed
	}
	select {
	case verifier.semaphore <- struct{}{}:
		defer func() { <-verifier.semaphore }()
	default:
		return ErrRateLimited
	}

	requestContext, cancel := context.WithTimeout(ctx, verifier.timeout)
	defer cancel()
	form := url.Values{"secret": {verifier.secret}, "response": {token}}
	request, err := http.NewRequestWithContext(
		requestContext,
		http.MethodPost,
		verifier.endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return ErrDependencyUnavailable
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := verifier.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrDependencyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return ErrDependencyUnavailable
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrCaptchaFailed
	}

	var result providerResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&result); err != nil {
		return ErrDependencyUnavailable
	}
	if !result.Success {
		return ErrCaptchaFailed
	}
	if _, ok := verifier.allowedHostnames[result.Hostname]; !ok {
		return ErrCaptchaFailed
	}
	return nil
}

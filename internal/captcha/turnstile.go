package captcha

import (
	"net/http"
	"time"
)

const turnstileEndpoint = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

func NewTurnstileVerifier(
	secret string,
	allowedHostnames []string,
	client *http.Client,
	timeout time.Duration,
) (Verifier, error) {
	return newRemoteVerifier(turnstileEndpoint, secret, allowedHostnames, client, timeout)
}

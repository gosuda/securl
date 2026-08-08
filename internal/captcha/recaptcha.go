package captcha

import (
	"net/http"
	"time"
)

const recaptchaEndpoint = "https://www.google.com/recaptcha/api/siteverify"

func NewRecaptchaVerifier(
	secret string,
	allowedHostnames []string,
	client *http.Client,
	timeout time.Duration,
) (Verifier, error) {
	return newRemoteVerifier(recaptchaEndpoint, secret, allowedHostnames, client, timeout)
}

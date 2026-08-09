package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/idna"

	securlv1 "securl.click/securl/gen/go/securl/v1"
)

const maxTTL = 720 * time.Hour

type Config struct {
	HTTPNetwork              string
	HTTPAddr                 string
	PublicOrigins            map[string]struct{}
	StoreBackend             string
	PostgresURL              string
	MariaDBDSN               string
	FrontendMode             string
	CORSOrigins              map[string]struct{}
	AllowedTTLs              []time.Duration
	AllowedTTLSeconds        []uint32
	AllowedTTLSet            map[uint32]struct{}
	DefaultTTL               time.Duration
	CleanupInterval          time.Duration
	CleanupBatch             int32
	MaxEnvelopeBytes         int
	MaxURLBytes              uint32
	SafeBrowsingEnabled      bool
	SafeBrowsingAPIKey       string
	SafeBrowsingTimeout      time.Duration
	SafeBrowsingCacheEntries int
	CaptchaProvider          securlv1.CaptchaProvider
	CreateCaptchaRequired    bool
	CaptchaSiteKey           string
	CaptchaSecretKey         string
	CaptchaWrapKey           string
	CaptchaAllowedHostnames  []string
	EnableHSTS               bool
}

func Load() (Config, error) {
	return parseConfig(os.LookupEnv)
}

// resolveHTTPListener accepts unix:/absolute/path for Unix sockets. Explicit
// Unix sockets take precedence over PaaS PORT discovery; TCP addresses retain
// github.com/lemon-mint/envaddr-compatible PORT, HOST, and IP semantics.
func resolveHTTPListener(defaultAddr string, lookup func(string) (string, bool)) (string, string, error) {
	if strings.HasPrefix(defaultAddr, "unix:") {
		address := strings.TrimPrefix(defaultAddr, "unix:")
		if !filepath.IsAbs(address) {
			return "", "", errors.New("Unix socket path must be absolute")
		}
		return "unix", address, nil
	}
	port, portFound := lookup("PORT")
	if !portFound {
		return "tcp", defaultAddr, nil
	}
	host, _ := lookup("HOST")
	if configuredIP, ok := lookup("IP"); ok {
		if ip := net.ParseIP(configuredIP); ip != nil {
			if ip.To4() != nil {
				host = ip.String()
			} else if ip.To16() != nil {
				host = "[" + ip.String() + "]"
			}
		}
	}
	return "tcp", host + ":" + port, nil
}

func parseConfig(lookup func(string) (string, bool)) (Config, error) {
	value := func(name, fallback string) string {
		if configured, ok := lookup(name); ok {
			return configured
		}
		return fallback
	}
	httpNetwork, httpAddr, err := resolveHTTPListener(value("SECURL_HTTP_ADDR", ":8080"), lookup)
	if err != nil {
		return Config{}, fmt.Errorf("SECURL_HTTP_ADDR: %w", err)
	}
	config := Config{
		HTTPNetwork:        httpNetwork,
		HTTPAddr:           httpAddr,
		StoreBackend:       value("SECURL_STORE_BACKEND", "memory"),
		PostgresURL:        value("SECURL_POSTGRES_URL", ""),
		MariaDBDSN:         value("SECURL_MARIADB_DSN", ""),
		FrontendMode:       value("SECURL_FRONTEND_MODE", "embedded"),
		CaptchaSiteKey:     value("SECURL_CAPTCHA_SITE_KEY", ""),
		CaptchaSecretKey:   value("SECURL_CAPTCHA_SECRET_KEY", ""),
		CaptchaWrapKey:     value("SECURL_CAPTCHA_WRAP_KEY", ""),
		SafeBrowsingAPIKey: value("SECURL_SAFE_BROWSING_API_KEY", ""),
		MaxURLBytes:        4096,
	}
	if config.PublicOrigins, err = parseOrigins(value("SECURL_PUBLIC_ORIGINS", "http://localhost:8080")); err != nil {
		return Config{}, fmt.Errorf("SECURL_PUBLIC_ORIGINS: %w", err)
	}
	if config.CORSOrigins, err = parseOrigins(value("SECURL_CORS_ALLOWED_ORIGINS", "")); err != nil {
		return Config{}, fmt.Errorf("SECURL_CORS_ALLOWED_ORIGINS: %w", err)
	}
	if config.AllowedTTLs, config.AllowedTTLSeconds, config.AllowedTTLSet, err = parseTTLs(
		value("SECURL_ALLOWED_TTLS", "1h,24h,168h,720h,forever"),
	); err != nil {
		return Config{}, fmt.Errorf("SECURL_ALLOWED_TTLS: %w", err)
	}
	if config.DefaultTTL, err = parseTTL(value("SECURL_DEFAULT_TTL", "168h")); err != nil {
		return Config{}, fmt.Errorf("SECURL_DEFAULT_TTL: %w", err)
	}
	if _, ok := config.AllowedTTLSet[uint32(config.DefaultTTL/time.Second)]; !ok {
		return Config{}, errors.New("SECURL_DEFAULT_TTL must be in SECURL_ALLOWED_TTLS")
	}
	if config.CleanupInterval, err = positiveDuration(value("SECURL_CLEANUP_INTERVAL", "1m")); err != nil {
		return Config{}, fmt.Errorf("SECURL_CLEANUP_INTERVAL: %w", err)
	}
	if config.CleanupBatch, err = positiveInt32(value("SECURL_CLEANUP_BATCH", "500")); err != nil {
		return Config{}, fmt.Errorf("SECURL_CLEANUP_BATCH: %w", err)
	}
	if config.MaxEnvelopeBytes, err = positiveInt(value("SECURL_MAX_ENVELOPE_BYTES", "6144")); err != nil {
		return Config{}, fmt.Errorf("SECURL_MAX_ENVELOPE_BYTES: %w", err)
	}
	if config.SafeBrowsingEnabled, err = strconv.ParseBool(value("SECURL_SAFE_BROWSING_ENABLED", "false")); err != nil {
		return Config{}, fmt.Errorf("SECURL_SAFE_BROWSING_ENABLED: %w", err)
	}
	if config.SafeBrowsingTimeout, err = positiveDuration(value("SECURL_SAFE_BROWSING_TIMEOUT", "3s")); err != nil {
		return Config{}, fmt.Errorf("SECURL_SAFE_BROWSING_TIMEOUT: %w", err)
	}
	if config.SafeBrowsingCacheEntries, err = positiveInt(value("SECURL_SAFE_BROWSING_CACHE_ENTRIES", "4096")); err != nil {
		return Config{}, fmt.Errorf("SECURL_SAFE_BROWSING_CACHE_ENTRIES: %w", err)
	}
	if config.SafeBrowsingEnabled && config.SafeBrowsingAPIKey == "" {
		return Config{}, errors.New("SECURL_SAFE_BROWSING_API_KEY is required when Safe Browsing is enabled")
	}
	if config.CaptchaProvider, err = parseCaptchaProvider(value("SECURL_CAPTCHA_PROVIDER", "none")); err != nil {
		return Config{}, err
	}
	if config.CreateCaptchaRequired, err = strconv.ParseBool(
		value("SECURL_CREATE_CAPTCHA_REQUIRED", "false"),
	); err != nil {
		return Config{}, fmt.Errorf("SECURL_CREATE_CAPTCHA_REQUIRED: %w", err)
	}
	if config.CaptchaAllowedHostnames, err = parseHostnames(
		value("SECURL_CAPTCHA_ALLOWED_HOSTNAMES", "localhost"),
	); err != nil {
		return Config{}, fmt.Errorf("SECURL_CAPTCHA_ALLOWED_HOSTNAMES: %w", err)
	}
	if config.CaptchaProvider != securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE {
		if config.CaptchaSiteKey == "" || config.CaptchaSecretKey == "" || config.CaptchaWrapKey == "" {
			return Config{}, errors.New("CAPTCHA site, secret, and wrap keys are required")
		}
	}
	if config.CreateCaptchaRequired &&
		config.CaptchaProvider == securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE {
		return Config{}, errors.New("SECURL_CAPTCHA_PROVIDER is required when create CAPTCHA is enabled")
	}
	if config.EnableHSTS, err = strconv.ParseBool(value("SECURL_ENABLE_HSTS", "false")); err != nil {
		return Config{}, fmt.Errorf("SECURL_ENABLE_HSTS: %w", err)
	}
	switch config.StoreBackend {
	case "memory":
	case "postgres":
		if config.PostgresURL == "" {
			return Config{}, errors.New("SECURL_POSTGRES_URL is required for postgres")
		}
	case "mariadb":
		if config.MariaDBDSN == "" {
			return Config{}, errors.New("SECURL_MARIADB_DSN is required for mariadb")
		}
	default:
		return Config{}, errors.New("SECURL_STORE_BACKEND must be memory, postgres, or mariadb")
	}
	if config.FrontendMode != "embedded" && config.FrontendMode != "external" {
		return Config{}, errors.New("SECURL_FRONTEND_MODE must be embedded or external")
	}
	if config.FrontendMode == "external" && len(config.CORSOrigins) == 0 {
		return Config{}, errors.New("SECURL_CORS_ALLOWED_ORIGINS is required in external mode")
	}
	return config, nil
}

func parseOrigins(value string) (map[string]struct{}, error) {
	origins := make(map[string]struct{})
	if value == "" {
		return origins, nil
	}
	for _, item := range strings.Split(value, ",") {
		origin, err := normalizeOrigin(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		origins[origin] = struct{}{}
	}
	return origins, nil
}

func normalizeOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" ||
		parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("origin must contain only an http(s) scheme and host")
	}
	hostname, err := normalizeHostname(parsed.Hostname())
	if err != nil {
		return "", err
	}
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return strings.ToLower(parsed.Scheme) + "://" + host, nil
}

func normalizeHostname(value string) (string, error) {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), nil
	}
	normalized, err := idna.Lookup.ToASCII(value)
	if err != nil || normalized == "" {
		return "", errors.New("invalid internationalized hostname")
	}
	return strings.ToLower(normalized), nil
}

func parseHostnames(value string) ([]string, error) {
	seen := make(map[string]struct{})
	hostnames := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		hostname, err := normalizeHostname(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		if _, ok := seen[hostname]; !ok {
			seen[hostname] = struct{}{}
			hostnames = append(hostnames, hostname)
		}
	}
	if len(hostnames) == 0 {
		return nil, errors.New("at least one hostname is required")
	}
	return hostnames, nil
}

func parseTTL(value string) (time.Duration, error) {
	if value == "forever" {
		return 0, nil
	}
	duration, err := positiveDuration(value)
	if err != nil || duration > maxTTL || duration%time.Second != 0 {
		return 0, errors.New("must be forever or a whole-second duration between 1s and 720h")
	}
	return duration, nil
}

func parseTTLs(value string) ([]time.Duration, []uint32, map[uint32]struct{}, error) {
	durations := make([]time.Duration, 0)
	seconds := make([]uint32, 0)
	allowed := make(map[uint32]struct{})
	for _, item := range strings.Split(value, ",") {
		duration, err := parseTTL(strings.TrimSpace(item))
		if err != nil {
			return nil, nil, nil, errors.New("TTLs must be forever or whole seconds between 1s and 720h")
		}
		value := uint32(duration / time.Second)
		if _, ok := allowed[value]; ok {
			continue
		}
		allowed[value] = struct{}{}
		durations = append(durations, duration)
		seconds = append(seconds, value)
	}
	if len(durations) == 0 {
		return nil, nil, nil, errors.New("at least one TTL is required")
	}
	return durations, seconds, allowed, nil
}

func parseCaptchaProvider(value string) (securlv1.CaptchaProvider, error) {
	switch value {
	case "none":
		return securlv1.CaptchaProvider_CAPTCHA_PROVIDER_NONE, nil
	case "turnstile":
		return securlv1.CaptchaProvider_CAPTCHA_PROVIDER_TURNSTILE, nil
	case "recaptcha":
		return securlv1.CaptchaProvider_CAPTCHA_PROVIDER_RECAPTCHA, nil
	default:
		return 0, errors.New("SECURL_CAPTCHA_PROVIDER must be none, turnstile, or recaptcha")
	}
}

func positiveDuration(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, errors.New("must be a positive duration")
	}
	return duration, nil
}

func positiveInt(value string) (int, error) {
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 0, errors.New("must be a positive integer")
	}
	return parsed, nil
}

func positiveInt32(value string) (int32, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed <= 0 {
		return 0, errors.New("must be a positive 32-bit integer")
	}
	return int32(parsed), nil
}

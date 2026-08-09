package config

import (
	"encoding/base64"
	"testing"
)

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestDefaultConfiguration(t *testing.T) {
	config, err := parseConfig(mapLookup(nil))
	if err != nil {
		t.Fatal(err)
	}
	if config.HTTPNetwork != "tcp" || config.HTTPAddr != ":8080" || config.StoreBackend != "memory" ||
		config.FrontendMode != "embedded" || config.DefaultTTL.String() != "168h0m0s" ||
		config.MaxEnvelopeBytes != 16384 || config.SafeBrowsingEnabled {
		t.Fatalf("config=%+v", config)
	}
	if _, ok := config.PublicOrigins["http://localhost:8080"]; !ok {
		t.Fatalf("public origins=%v", config.PublicOrigins)
	}
	if _, ok := config.AllowedTTLSet[0]; !ok {
		t.Fatalf("default TTLs do not allow forever: %v", config.AllowedTTLSeconds)
	}
}

func TestPaaSListenAddressDiscovery(t *testing.T) {
	tests := []struct {
		name     string
		values   map[string]string
		expected string
	}{
		{name: "default", values: nil, expected: ":8080"},
		{name: "explicit SecURL address", values: map[string]string{"SECURL_HTTP_ADDR": "127.0.0.1:9000"}, expected: "127.0.0.1:9000"},
		{name: "PORT overrides SecURL address", values: map[string]string{"SECURL_HTTP_ADDR": "127.0.0.1:9000", "PORT": "8081"}, expected: ":8081"},
		{name: "HOST and PORT", values: map[string]string{"HOST": "0.0.0.0", "PORT": "8082"}, expected: "0.0.0.0:8082"},
		{name: "IPv4 overrides HOST", values: map[string]string{"HOST": "localhost", "IP": "127.0.0.2", "PORT": "8083"}, expected: "127.0.0.2:8083"},
		{name: "IPv6 is bracketed", values: map[string]string{"IP": "2001:db8::1", "PORT": "8084"}, expected: "[2001:db8::1]:8084"},
		{name: "invalid IP keeps HOST", values: map[string]string{"HOST": "paas.internal", "IP": "invalid", "PORT": "8085"}, expected: "paas.internal:8085"},
		{name: "HOST without PORT is ignored", values: map[string]string{"SECURL_HTTP_ADDR": "127.0.0.1:9001", "HOST": "0.0.0.0"}, expected: "127.0.0.1:9001"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config, err := parseConfig(mapLookup(test.values))
			if err != nil {
				t.Fatal(err)
			}
			if config.HTTPNetwork != "tcp" || config.HTTPAddr != test.expected {
				t.Fatalf("HTTPNetwork=%q HTTPAddr=%q expected=%q", config.HTTPNetwork, config.HTTPAddr, test.expected)
			}
		})
	}
}

func TestUnixSocketListenAddressTakesPrecedenceOverPORT(t *testing.T) {
	config, err := parseConfig(mapLookup(map[string]string{
		"SECURL_HTTP_ADDR": "unix:/tmp/securl.sock",
		"HOST":             "0.0.0.0",
		"PORT":             "8080",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.HTTPNetwork != "unix" || config.HTTPAddr != "/tmp/securl.sock" {
		t.Fatalf("HTTPNetwork=%q HTTPAddr=%q", config.HTTPNetwork, config.HTTPAddr)
	}
}

func TestUnixSocketRequiresAbsolutePath(t *testing.T) {
	for _, address := range []string{"unix:", "unix:securl.sock"} {
		t.Run(address, func(t *testing.T) {
			if _, err := parseConfig(mapLookup(map[string]string{"SECURL_HTTP_ADDR": address})); err == nil {
				t.Fatal("relative Unix socket path accepted")
			}
		})
	}
}

func TestForeverTTLCanBeConfiguredAsDefault(t *testing.T) {
	config, err := parseConfig(mapLookup(map[string]string{
		"SECURL_ALLOWED_TTLS": "1h,forever",
		"SECURL_DEFAULT_TTL":  "forever",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if config.DefaultTTL != 0 || len(config.AllowedTTLSeconds) != 2 || config.AllowedTTLSeconds[1] != 0 {
		t.Fatalf("config=%+v", config)
	}
}

func TestMultiplePublicOriginsNormalizeUnicodeAndDefaultPorts(t *testing.T) {
	config, err := parseConfig(mapLookup(map[string]string{
		"SECURL_PUBLIC_ORIGINS": "https://BÜCHER.example., https://alt.example:443, http://[2001:db8::1]:80",
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"https://xn--bcher-kva.example",
		"https://alt.example",
		"http://[2001:db8::1]",
	} {
		if _, ok := config.PublicOrigins[expected]; !ok {
			t.Fatalf("missing %q in %v", expected, config.PublicOrigins)
		}
	}
}

func TestConfigurationRequiresEnabledDependencies(t *testing.T) {
	tests := []map[string]string{
		{"SECURL_SAFE_BROWSING_ENABLED": "true"},
		{"SECURL_STORE_BACKEND": "postgres"},
		{"SECURL_STORE_BACKEND": "mariadb"},
		{"SECURL_FRONTEND_MODE": "external"},
		{"SECURL_CAPTCHA_PROVIDER": "turnstile"},
		{"SECURL_CREATE_CAPTCHA_REQUIRED": "true"},
		{"SECURL_DEFAULT_TTL": "2h"},
	}
	for _, values := range tests {
		if _, err := parseConfig(mapLookup(values)); err == nil {
			t.Fatalf("configuration unexpectedly accepted: %v", values)
		}
	}
}

func TestDatabaseBackendConfiguration(t *testing.T) {
	postgres, err := parseConfig(mapLookup(map[string]string{
		"SECURL_STORE_BACKEND": "postgres",
		"SECURL_POSTGRES_URL":  "postgres://securl:secret@localhost/securl",
	}))
	if err != nil || postgres.PostgresURL == "" {
		t.Fatalf("postgres config=%+v err=%v", postgres, err)
	}
	maria, err := parseConfig(mapLookup(map[string]string{
		"SECURL_STORE_BACKEND": "mariadb",
		"SECURL_MARIADB_DSN":   "securl:secret@tcp(localhost:3306)/securl",
	}))
	if err != nil || maria.MariaDBDSN == "" {
		t.Fatalf("mariadb config=%+v err=%v", maria, err)
	}
}

func TestConfiguredCaptchaAndExternalFrontend(t *testing.T) {
	wrapKey := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	config, err := parseConfig(mapLookup(map[string]string{
		"SECURL_FRONTEND_MODE":             "external",
		"SECURL_CORS_ALLOWED_ORIGINS":      "https://app.example,https://앱.example",
		"SECURL_CAPTCHA_PROVIDER":          "turnstile",
		"SECURL_CAPTCHA_SITE_KEY":          "site",
		"SECURL_CAPTCHA_SECRET_KEY":        "secret",
		"SECURL_CAPTCHA_WRAP_KEY":          wrapKey,
		"SECURL_CAPTCHA_ALLOWED_HOSTNAMES": "BÜCHER.example.,localhost",
		"SECURL_CREATE_CAPTCHA_REQUIRED":   "true",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(config.CORSOrigins) != 2 || config.CaptchaAllowedHostnames[0] != "xn--bcher-kva.example" ||
		!config.CreateCaptchaRequired {
		t.Fatalf("config=%+v", config)
	}
}

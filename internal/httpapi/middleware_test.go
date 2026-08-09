package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/store/memory"
)

func middlewareRouter(frontend http.Handler, enableHSTS bool) http.Handler {
	return NewRouter(Dependencies{
		Repository: memory.New(),
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{3600}, DefaultTtlSeconds: 3600,
		},
		AllowedTTLs:        map[uint32]struct{}{3600: {}},
		Frontend:           frontend,
		PublicOrigins:      map[string]struct{}{"https://securl.example": {}, "https://securl-alt.example": {}},
		CORSAllowedOrigins: map[string]struct{}{"https://app.example": {}},
		EnableHSTS:         enableHSTS,
		Logger:             nopLogger(),
	})
}

func nopLogger() *zerolog.Logger {
	logger := zerolog.Nop()
	return &logger
}

func TestAllowedCORSPreflightUsesExactPolicyWithoutCredentials(t *testing.T) {
	request := httptest.NewRequest(http.MethodOptions, "/api/v1/envelopes", nil)
	request.Header.Set("Origin", "https://app.example")
	request.Header.Set("Access-Control-Request-Method", http.MethodPost)
	request.Header.Set("Access-Control-Request-Headers", "Content-Type, If-None-Match")
	response := httptest.NewRecorder()
	middlewareRouter(nil, false).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%x", response.Code, response.Body.Bytes())
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "https://app.example" ||
		response.Header().Get("Access-Control-Allow-Methods") != allowedMethods ||
		response.Header().Get("Access-Control-Allow-Headers") != allowedHeaders ||
		response.Header().Get("Access-Control-Expose-Headers") != exposedHeaders {
		t.Fatalf("CORS headers=%v", response.Header())
	}
	if response.Header().Get("Access-Control-Allow-Credentials") != "" ||
		response.Header().Get("Vary") != "Origin" {
		t.Fatalf("unsafe CORS headers=%v", response.Header())
	}
}

func TestCORSRejectsArbitraryOriginsAndHeaders(t *testing.T) {
	tests := []struct {
		name    string
		origin  string
		headers string
	}{
		{name: "arbitrary origin", origin: "https://evil.example", headers: "Content-Type"},
		{name: "origin prefix", origin: "https://app.example.evil", headers: "Content-Type"},
		{name: "unallowed header", origin: "https://app.example", headers: "Authorization"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodOptions, "/api/v1/envelopes", nil)
			request.Header.Set("Origin", test.origin)
			request.Header.Set("Access-Control-Request-Method", http.MethodPost)
			request.Header.Set("Access-Control-Request-Headers", test.headers)
			response := httptest.NewRecorder()
			middlewareRouter(nil, false).ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/config", nil)
	request.Header.Set("Origin", "https://evil.example")
	response := httptest.NewRecorder()
	middlewareRouter(nil, false).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("state-changing status=%d", response.Code)
	}
}

func TestSecurityHeadersRequestIDAndSameOrigin(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/config", nil)
	request.Header.Set("Origin", "https://securl-alt.example")
	response := httptest.NewRecorder()
	middlewareRouter(nil, true).ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", response.Code)
	}
	for header, expected := range map[string]string{
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Opener-Policy":   "same-origin",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Strict-Transport-Security":    "max-age=31536000",
	} {
		if response.Header().Get(header) != expected {
			t.Fatalf("%s=%q", header, response.Header().Get(header))
		}
	}
	if response.Header().Get("X-Request-ID") == "" ||
		response.Header().Get("Access-Control-Allow-Origin") != "https://securl-alt.example" {
		t.Fatalf("headers=%v", response.Header())
	}
}

func TestPanicRecoveryReturnsProtobufInternalError(t *testing.T) {
	frontend := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("secret panic") })
	response := httptest.NewRecorder()
	middlewareRouter(frontend, false).ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/panic", nil),
	)
	if response.Code != http.StatusInternalServerError ||
		response.Header().Get("Content-Type") != protobufContentType {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	var errorResponse securlv1.ErrorResponse
	if err := decodeCanonical(response.Body.Bytes(), &errorResponse); err != nil {
		t.Fatal(err)
	}
	if errorResponse.Code != "internal" || errorResponse.RequestId == "" {
		t.Fatalf("error=%+v", &errorResponse)
	}
}

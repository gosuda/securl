package httpapi

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/store/memory"
)

func testRouter() http.Handler {
	return NewRouter(Dependencies{
		Repository: memory.New(),
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{3600}, DefaultTtlSeconds: 3600, MaxUrlBytes: 4096,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
	})
}

func TestRouterRegistersOnlyDocumentedRoutes(t *testing.T) {
	router := testRouter()
	storageKey := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	tests := []struct {
		method string
		path   string
		status int
	}{
		{http.MethodGet, "/api/v1/config", http.StatusOK},
		{http.MethodPost, "/api/v1/envelopes", http.StatusUnsupportedMediaType},
		{http.MethodGet, "/api/v1/envelopes/" + storageKey + "/metadata", http.StatusNotFound},
		{http.MethodGet, "/api/v1/envelopes/" + storageKey, http.StatusNotFound},
		{http.MethodPost, "/api/v1/envelopes/" + storageKey + "/access", http.StatusUnsupportedMediaType},
		{http.MethodPost, "/api/v1/safe-browsing/lookup", http.StatusBadRequest},
		{http.MethodGet, "/healthz", http.StatusOK},
		{http.MethodGet, "/readyz", http.StatusOK},
		{http.MethodPost, "/api/v1/config", http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/unknown", http.StatusNotFound},
		{http.MethodGet, "/unknown", http.StatusNotFound},
	}
	for _, test := range tests {
		t.Run(test.method+" "+test.path, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

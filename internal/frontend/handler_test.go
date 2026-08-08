package frontend

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func testHandler(t testing.TB) *Handler {
	t.Helper()
	handler, err := newHandler(fstest.MapFS{
		"index.html":               &fstest.MapFile{Data: []byte(`<title>SecURL - Protected Link</title><meta http-equiv="content-security-policy" content="default-src 'self'">`)},
		"_app/immutable/app.js":    &fstest.MapFile{Data: []byte("javascript")},
		"_app/immutable/app.js.br": &fstest.MapFile{Data: []byte("brotli")},
		"_app/immutable/app.js.gz": &fstest.MapFile{Data: []byte("gzip")},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func TestHandlerServesRootWithNoCacheAndEnforcedCSP(t *testing.T) {
	handler := testHandler(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatalf("CSP=%q", response.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(response.Body.String(), "SecURL - Protected Link") {
		t.Fatal("static metadata missing")
	}
}

func TestHandlerDoesNotUseSPAFallback(t *testing.T) {
	handler := testHandler(t)
	for _, requestedPath := range []string{"/unknown", "/nested/path", "/../index.html"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, requestedPath, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("path=%s status=%d", requestedPath, response.Code)
		}
	}
}

func TestHandlerServesPrecompressedImmutableAssets(t *testing.T) {
	handler := testHandler(t)
	const asset = "_app/immutable/app.js"
	request := httptest.NewRequest(http.MethodGet, "/"+asset, nil)
	request.Header.Set("Accept-Encoding", "br, gzip")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Encoding") != "br" ||
		response.Header().Get("Cache-Control") != "public,max-age=31536000,immutable" ||
		response.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/"+asset, nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%d", head.Code, head.Body.Len())
	}
}

package frontend

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFrontendModes(t *testing.T) {
	embedded, err := forMode("embedded", func() (http.Handler, error) { return testHandler(t), nil })
	if err != nil || embedded == nil {
		t.Fatalf("embedded handler=%v err=%v", embedded, err)
	}
	response := httptest.NewRecorder()
	embedded.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("embedded status=%d", response.Code)
	}
	external, err := forMode("external", func() (http.Handler, error) { return testHandler(t), nil })
	if err != nil || external != nil {
		t.Fatalf("external handler=%v err=%v", external, err)
	}
	if _, err := forMode("invalid", func() (http.Handler, error) { return testHandler(t), nil }); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

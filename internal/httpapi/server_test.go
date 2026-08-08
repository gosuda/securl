package httpapi

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/store/memory"
)

func TestNewServerUsesDefensiveTimeoutsAndHeaderLimit(t *testing.T) {
	server := NewServer(":8080", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if server.ReadHeaderTimeout != 5*time.Second ||
		server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 15*time.Second ||
		server.IdleTimeout != 60*time.Second ||
		server.MaxHeaderBytes != 16<<10 {
		t.Fatalf("server=%+v", server)
	}
}

func TestRequestLoggingContainsOnlyTemplateStatusDurationAndRequestID(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	storageKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	router := NewRouter(Dependencies{
		Repository: memory.New(),
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{3600}, DefaultTtlSeconds: 3600,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
		Logger:      logger,
	})
	body, err := (&securlv1.AccessEnvelopeRequest{CaptchaToken: "secret-token"}).MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/envelopes/"+storageKey+"/access?value=query-secret",
		bytes.NewReader(body),
	)
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	output := logs.String()
	for _, forbidden := range []string{storageKey, "secret-token", "query-secret", "ciphertext"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("sensitive value %q in log: %s", forbidden, output)
		}
	}
	for _, required := range []string{
		`"route":"/api/v1/envelopes/:storageKey/access"`,
		`"status":400`,
		`"duration":`,
		`"request_id":`,
	} {
		if !strings.Contains(output, required) {
			t.Fatalf("missing %q in log: %s", required, output)
		}
	}
}

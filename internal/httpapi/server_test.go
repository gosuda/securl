package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/store/memory"
)

func TestNewServerUsesDefensiveTimeoutsAndHeaderLimit(t *testing.T) {
	logger := zerolog.Nop()
	server := NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), &logger)
	if server.ReadHeaderTimeout != 5*time.Second ||
		server.ReadTimeout != 15*time.Second ||
		server.WriteTimeout != 15*time.Second ||
		server.IdleTimeout != 60*time.Second ||
		server.MaxHeaderBytes != 16<<10 || server.ErrorLog == nil {
		t.Fatalf("server=%+v", server)
	}
}

func TestNewServerRoutesInternalErrorsThroughZerolog(t *testing.T) {
	var logs bytes.Buffer
	logger := zerolog.New(&logs)
	server := NewServer(http.NotFoundHandler(), &logger)
	server.ErrorLog.Print("internal HTTP server failure")

	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("invalid JSON log %q: %v", logs.String(), err)
	}
	if entry["level"] != "error" || entry["message"] != "internal HTTP server failure" {
		t.Fatalf("entry=%v", entry)
	}
}

func TestRequestLoggingContainsOnlyTemplateStatusDurationAndRequestID(t *testing.T) {
	var logs bytes.Buffer
	logger := zerolog.New(&logs)
	storageKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 16))
	router := NewRouter(Dependencies{
		Repository: memory.New(),
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{3600}, DefaultTtlSeconds: 3600,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
		Logger:      &logger,
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

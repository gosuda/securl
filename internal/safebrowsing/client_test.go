package safebrowsing

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func appendBytesField(message []byte, number protowire.Number, value []byte) []byte {
	message = protowire.AppendTag(message, number, protowire.BytesType)
	return protowire.AppendBytes(message, value)
}

func appendVarintField(message []byte, number protowire.Number, value uint64) []byte {
	message = protowire.AppendTag(message, number, protowire.VarintType)
	return protowire.AppendVarint(message, value)
}

func searchHashesResponse(fullHash [32]byte, seconds uint64, nanos uint64) []byte {
	detail := appendVarintField(nil, 1, 1)
	detail = appendBytesField(detail, 2, protowire.AppendVarint(nil, 2))
	hash := appendBytesField(nil, 1, fullHash[:])
	hash = appendBytesField(hash, 2, detail)
	duration := appendVarintField(nil, 1, seconds)
	duration = appendVarintField(duration, 2, nanos)
	response := appendBytesField(nil, 1, hash)
	return appendBytesField(response, 2, duration)
}

func invalidDurationResponse() []byte {
	duration := appendVarintField(nil, 1, ^uint64(0))
	return appendBytesField(nil, 2, duration)
}

func TestClientUsesPrivatePrefixOnlyGETAndParsesDetails(t *testing.T) {
	var fullHash [32]byte
	for index := range fullHash {
		fullHash[index] = byte(index)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Body != http.NoBody {
			t.Errorf("method=%s body=%v", request.Method, request.Body)
		}
		if request.URL.Query().Get("key") != "api-key" {
			t.Errorf("missing API key")
		}
		query := request.URL.Query()
		if _, ok := query["hashPrefixes[]"]; ok {
			t.Errorf("legacy bracketed hash prefix parameter was sent: %v", query)
		}
		prefixes := query["hashPrefixes"]
		if len(prefixes) != 1 || prefixes[0] != base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}) {
			t.Errorf("prefixes=%v", prefixes)
		}
		writer.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = writer.Write(searchHashesResponse(fullHash, 3, 500_000_000))
	}))
	defer server.Close()

	client, err := newClient(server.URL, "api-key", server.Client(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Lookup(context.Background(), [][4]byte{{1, 2, 3, 4}, {1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}
	if result.CacheSeconds != 3 || len(result.FullHashes) != 1 {
		t.Fatalf("result=%+v", result)
	}
	if result.FullHashes[0].Hash != fullHash || result.FullHashes[0].ThreatType != "MALWARE" {
		t.Fatalf("full hash=%+v", result.FullHashes[0])
	}
}

func TestClientFailsClosedOnProviderErrors(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		timeout time.Duration
	}{
		{
			name: "status",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(http.StatusServiceUnavailable)
			},
			timeout: time.Second,
		},
		{
			name: "invalid duration",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/x-protobuf")
				_, _ = writer.Write(invalidDurationResponse())
			},
			timeout: time.Second,
		},
		{
			name: "timeout",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				time.Sleep(50 * time.Millisecond)
				writer.Header().Set("Content-Type", "application/x-protobuf")
				_, _ = writer.Write(searchHashesResponse([32]byte{}, 60, 0))
			},
			timeout: 5 * time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			client, err := newClient(server.URL, "api-key", server.Client(), test.timeout)
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.Lookup(context.Background(), [][4]byte{{1, 2, 3, 4}})
			if !errors.Is(err, ErrDependencyUnavailable) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestClientValidatesLimitsAndConcurrency(t *testing.T) {
	client, err := newClient("https://example.invalid", "api-key", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Lookup(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty prefix error=%v", err)
	}
	if _, err := client.Lookup(context.Background(), make([][4]byte, MaxPrefixes+1)); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("prefix limit error=%v", err)
	}
	client.semaphore = make(chan struct{}, 1)
	client.semaphore <- struct{}{}
	if _, err := client.Lookup(context.Background(), [][4]byte{{1, 2, 3, 4}}); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("saturated client error=%v", err)
	}
}

func TestNewClientUsesFixedGoogleEndpoint(t *testing.T) {
	client, err := NewClient("api-key", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if client.endpoint != searchEndpoint {
		t.Fatalf("endpoint=%s", client.endpoint)
	}
}

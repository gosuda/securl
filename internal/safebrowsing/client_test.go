package safebrowsing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
		prefixes := request.URL.Query()["hashPrefixes[]"]
		if len(prefixes) != 1 || prefixes[0] != base64.StdEncoding.EncodeToString([]byte{1, 2, 3, 4}) {
			t.Errorf("prefixes=%v", prefixes)
		}
		fmt.Fprintf(
			writer,
			`{"fullHashes":[{"fullHash":%q,"fullHashDetails":[{"threatType":"MALWARE","attributes":["FRAME_ONLY"]}]}],"cacheDuration":"3.5s"}`,
			base64.StdEncoding.EncodeToString(fullHash[:]),
		)
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
				fmt.Fprint(writer, `{"fullHashes":[],"cacheDuration":"bad"}`)
			},
			timeout: time.Second,
		},
		{
			name: "timeout",
			handler: func(writer http.ResponseWriter, _ *http.Request) {
				time.Sleep(50 * time.Millisecond)
				fmt.Fprint(writer, `{"fullHashes":[],"cacheDuration":"60s"}`)
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

package safebrowsing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

const (
	searchEndpoint        = "https://safebrowsing.googleapis.com/v5/hashes:search"
	DefaultTimeout        = 3 * time.Second
	MaxPrefixes           = 30
	MaxConcurrentRequests = 32
)

var (
	ErrInvalidRequest        = errors.New("safe browsing: invalid request")
	ErrDependencyUnavailable = errors.New("safe browsing: dependency unavailable")
	ErrRateLimited           = errors.New("safe browsing: rate limited")
)

type FullHash struct {
	Hash         [32]byte
	ThreatType   string
	Attributes   []string
	CacheSeconds uint32
}

type LookupResult struct {
	FullHashes   []FullHash
	CacheSeconds uint32
}

type LookupClient interface {
	Lookup(context.Context, [][4]byte) (LookupResult, error)
}

type Client struct {
	endpoint  string
	apiKey    string
	client    *http.Client
	timeout   time.Duration
	semaphore chan struct{}
}

type apiResponse struct {
	FullHashes []struct {
		FullHash        string `json:"fullHash"`
		FullHashDetails []struct {
			ThreatType string   `json:"threatType"`
			Attributes []string `json:"attributes"`
		} `json:"fullHashDetails"`
	} `json:"fullHashes"`
	CacheDuration string `json:"cacheDuration"`
}

var googleDuration = regexp.MustCompile(`^(0|[1-9][0-9]*)(?:\.([0-9]{1,9}))?s$`)

func NewClient(apiKey string, client *http.Client, timeout time.Duration) (*Client, error) {
	return newClient(searchEndpoint, apiKey, client, timeout)
}

func newClient(
	endpoint string,
	apiKey string,
	client *http.Client,
	timeout time.Duration,
) (*Client, error) {
	if apiKey == "" {
		return nil, ErrInvalidRequest
	}
	if client == nil {
		client = &http.Client{}
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{
		endpoint:  endpoint,
		apiKey:    apiKey,
		client:    client,
		timeout:   timeout,
		semaphore: make(chan struct{}, MaxConcurrentRequests),
	}, nil
}

func parseCacheDuration(value string) (uint32, error) {
	matches := googleDuration.FindStringSubmatch(value)
	if matches == nil {
		return 0, ErrDependencyUnavailable
	}
	seconds, err := strconv.ParseUint(matches[1], 10, 32)
	if err != nil || seconds > math.MaxUint32 {
		return 0, ErrDependencyUnavailable
	}
	return uint32(seconds), nil
}

func deduplicatePrefixes(prefixes [][4]byte) ([][4]byte, error) {
	if len(prefixes) < 1 || len(prefixes) > MaxPrefixes {
		return nil, ErrInvalidRequest
	}
	seen := make(map[[4]byte]struct{}, len(prefixes))
	unique := make([][4]byte, 0, len(prefixes))
	for _, prefix := range prefixes {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		unique = append(unique, prefix)
	}
	return unique, nil
}

func (client *Client) Lookup(ctx context.Context, prefixes [][4]byte) (LookupResult, error) {
	unique, err := deduplicatePrefixes(prefixes)
	if err != nil {
		return LookupResult{}, err
	}
	select {
	case client.semaphore <- struct{}{}:
		defer func() { <-client.semaphore }()
	default:
		return LookupResult{}, ErrRateLimited
	}

	requestURL, err := url.Parse(client.endpoint)
	if err != nil {
		return LookupResult{}, ErrDependencyUnavailable
	}
	query := requestURL.Query()
	query.Set("key", client.apiKey)
	for _, prefix := range unique {
		query.Add("hashPrefixes[]", base64.StdEncoding.EncodeToString(prefix[:]))
	}
	requestURL.RawQuery = query.Encode()
	requestContext, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return LookupResult{}, ErrDependencyUnavailable
	}
	response, err := client.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return LookupResult{}, ctx.Err()
		}
		return LookupResult{}, ErrDependencyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return LookupResult{}, ErrDependencyUnavailable
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return LookupResult{}, ErrDependencyUnavailable
	}

	var decoded apiResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&decoded); err != nil {
		return LookupResult{}, ErrDependencyUnavailable
	}
	cacheSeconds, err := parseCacheDuration(decoded.CacheDuration)
	if err != nil {
		return LookupResult{}, err
	}
	result := LookupResult{CacheSeconds: cacheSeconds}
	for _, responseHash := range decoded.FullHashes {
		fullHashBytes, err := base64.StdEncoding.DecodeString(responseHash.FullHash)
		if err != nil || len(fullHashBytes) != 32 {
			return LookupResult{}, ErrDependencyUnavailable
		}
		var fullHash [32]byte
		copy(fullHash[:], fullHashBytes)
		for _, detail := range responseHash.FullHashDetails {
			if detail.ThreatType == "" {
				continue
			}
			result.FullHashes = append(result.FullHashes, FullHash{
				Hash:         fullHash,
				ThreatType:   detail.ThreatType,
				Attributes:   append([]string(nil), detail.Attributes...),
				CacheSeconds: cacheSeconds,
			})
		}
	}
	return result, nil
}

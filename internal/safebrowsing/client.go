package safebrowsing

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/known/durationpb"
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

type decodedHashDetail struct {
	threatType string
	attributes []string
}

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

func threatTypeName(value uint64) (string, bool) {
	switch value {
	case 1:
		return "MALWARE", true
	case 2:
		return "SOCIAL_ENGINEERING", true
	case 3:
		return "UNWANTED_SOFTWARE", true
	case 4:
		return "POTENTIALLY_HARMFUL_APPLICATION", true
	default:
		return "", false
	}
}

func threatAttributeName(value uint64) (string, bool) {
	switch value {
	case 1:
		return "CANARY", true
	case 2:
		return "FRAME_ONLY", true
	default:
		return "", false
	}
}

func skipWireField(number protowire.Number, wireType protowire.Type, data []byte) ([]byte, error) {
	consumed := protowire.ConsumeFieldValue(number, wireType, data)
	if consumed < 0 {
		return nil, ErrDependencyUnavailable
	}
	return data[consumed:], nil
}

func decodeHashDetail(data []byte) (decodedHashDetail, bool, error) {
	var detail decodedHashDetail
	valid := true
	hasThreatType := false
	for len(data) > 0 {
		number, wireType, consumed := protowire.ConsumeTag(data)
		if consumed < 0 {
			return decodedHashDetail{}, false, ErrDependencyUnavailable
		}
		data = data[consumed:]
		switch number {
		case 1:
			if wireType != protowire.VarintType {
				return decodedHashDetail{}, false, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeVarint(data)
			if valueBytes < 0 {
				return decodedHashDetail{}, false, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			hasThreatType = true
			var known bool
			detail.threatType, known = threatTypeName(value)
			valid = valid && known
		case 2:
			switch wireType {
			case protowire.VarintType:
				value, valueBytes := protowire.ConsumeVarint(data)
				if valueBytes < 0 {
					return decodedHashDetail{}, false, ErrDependencyUnavailable
				}
				data = data[valueBytes:]
				attribute, known := threatAttributeName(value)
				valid = valid && known
				if known {
					detail.attributes = append(detail.attributes, attribute)
				}
			case protowire.BytesType:
				packed, valueBytes := protowire.ConsumeBytes(data)
				if valueBytes < 0 {
					return decodedHashDetail{}, false, ErrDependencyUnavailable
				}
				data = data[valueBytes:]
				for len(packed) > 0 {
					value, packedBytes := protowire.ConsumeVarint(packed)
					if packedBytes < 0 {
						return decodedHashDetail{}, false, ErrDependencyUnavailable
					}
					packed = packed[packedBytes:]
					attribute, known := threatAttributeName(value)
					valid = valid && known
					if known {
						detail.attributes = append(detail.attributes, attribute)
					}
				}
			default:
				return decodedHashDetail{}, false, ErrDependencyUnavailable
			}
		default:
			var err error
			data, err = skipWireField(number, wireType, data)
			if err != nil {
				return decodedHashDetail{}, false, err
			}
		}
	}
	return detail, valid && hasThreatType, nil
}

func decodeFullHash(data []byte) ([32]byte, []decodedHashDetail, error) {
	var hash [32]byte
	var details []decodedHashDetail
	hasHash := false
	for len(data) > 0 {
		number, wireType, consumed := protowire.ConsumeTag(data)
		if consumed < 0 {
			return hash, nil, ErrDependencyUnavailable
		}
		data = data[consumed:]
		switch number {
		case 1:
			if wireType != protowire.BytesType {
				return hash, nil, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeBytes(data)
			if valueBytes < 0 || len(value) != len(hash) {
				return hash, nil, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			copy(hash[:], value)
			hasHash = true
		case 2:
			if wireType != protowire.BytesType {
				return hash, nil, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeBytes(data)
			if valueBytes < 0 {
				return hash, nil, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			detail, valid, err := decodeHashDetail(value)
			if err != nil {
				return hash, nil, err
			}
			if valid {
				details = append(details, detail)
			}
		default:
			var err error
			data, err = skipWireField(number, wireType, data)
			if err != nil {
				return hash, nil, err
			}
		}
	}
	if !hasHash {
		return hash, nil, ErrDependencyUnavailable
	}
	return hash, details, nil
}

func decodeCacheDuration(data []byte) (uint32, error) {
	var duration durationpb.Duration
	for len(data) > 0 {
		number, wireType, consumed := protowire.ConsumeTag(data)
		if consumed < 0 {
			return 0, ErrDependencyUnavailable
		}
		data = data[consumed:]
		switch number {
		case 1:
			if wireType != protowire.VarintType {
				return 0, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeVarint(data)
			if valueBytes < 0 {
				return 0, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			duration.Seconds = int64(value)
		case 2:
			if wireType != protowire.VarintType {
				return 0, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeVarint(data)
			if valueBytes < 0 {
				return 0, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			duration.Nanos = int32(value)
		default:
			var err error
			data, err = skipWireField(number, wireType, data)
			if err != nil {
				return 0, err
			}
		}
	}
	if duration.Seconds < 0 || duration.Seconds > math.MaxUint32 || duration.CheckValid() != nil {
		return 0, ErrDependencyUnavailable
	}
	return uint32(duration.Seconds), nil
}

func decodeSearchHashesResponse(data []byte) (LookupResult, error) {
	var result LookupResult
	hasCacheDuration := false
	for len(data) > 0 {
		number, wireType, consumed := protowire.ConsumeTag(data)
		if consumed < 0 {
			return LookupResult{}, ErrDependencyUnavailable
		}
		data = data[consumed:]
		switch number {
		case 1:
			if wireType != protowire.BytesType {
				return LookupResult{}, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeBytes(data)
			if valueBytes < 0 {
				return LookupResult{}, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			hash, details, err := decodeFullHash(value)
			if err != nil {
				return LookupResult{}, err
			}
			for _, detail := range details {
				result.FullHashes = append(result.FullHashes, FullHash{
					Hash: hash, ThreatType: detail.threatType, Attributes: detail.attributes,
				})
			}
		case 2:
			if wireType != protowire.BytesType {
				return LookupResult{}, ErrDependencyUnavailable
			}
			value, valueBytes := protowire.ConsumeBytes(data)
			if valueBytes < 0 {
				return LookupResult{}, ErrDependencyUnavailable
			}
			data = data[valueBytes:]
			cacheSeconds, err := decodeCacheDuration(value)
			if err != nil {
				return LookupResult{}, err
			}
			result.CacheSeconds = cacheSeconds
			hasCacheDuration = true
		default:
			var err error
			data, err = skipWireField(number, wireType, data)
			if err != nil {
				return LookupResult{}, err
			}
		}
	}
	if !hasCacheDuration {
		return LookupResult{}, ErrDependencyUnavailable
	}
	for index := range result.FullHashes {
		result.FullHashes[index].CacheSeconds = result.CacheSeconds
	}
	return result, nil
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
		query.Add("hashPrefixes", base64.StdEncoding.EncodeToString(prefix[:]))
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
	mediaType, _, contentTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if contentTypeErr != nil || mediaType != "application/x-protobuf" {
		return LookupResult{}, ErrDependencyUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return LookupResult{}, ErrDependencyUnavailable
	}
	return decodeSearchHashesResponse(body)
}

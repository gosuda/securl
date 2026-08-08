package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/memory"
)

func validCreateBody(t testing.TB) []byte {
	t.Helper()
	body, err := (&securlv1.CreateEnvelopeRequest{
		StorageKey: make([]byte, 32),
		Envelope: &securlv1.Envelope{
			Metadata: &securlv1.EnvelopeMetadata{
				ProtocolVersion: 1,
				TtlSeconds:      3600,
				PayloadNonce:    bytes.Repeat([]byte{1}, 24),
			},
			Ciphertext: []byte{2, 3, 4},
		},
	}).MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func validationRouter(repository store.Repository) http.Handler {
	return NewRouter(Dependencies{
		Repository: repository,
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{3600}, DefaultTtlSeconds: 3600, MaxUrlBytes: 4096,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
		Now:         func() time.Time { return time.Unix(10000, 0).UTC() },
	})
}

func postProtobuf(router http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", protobufContentType)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

type singleUseCreateVerifier struct {
	calls int
}

func (verifier *singleUseCreateVerifier) Verify(_ context.Context, token string) error {
	if token != "valid-create-token" {
		return captcha.ErrCaptchaFailed
	}
	verifier.calls++
	if verifier.calls > 1 {
		return captcha.ErrCaptchaFailed
	}
	return nil
}

func TestCreateRequiresVerifiedCaptchaAndReplaysWithoutReverification(t *testing.T) {
	repository := memory.New()
	verifier := &singleUseCreateVerifier{}
	router := NewRouter(Dependencies{
		Repository:      repository,
		CaptchaVerifier: verifier,
		RuntimeConfig: &securlv1.RuntimeConfig{
			CaptchaProvider:       securlv1.CaptchaProvider_CAPTCHA_PROVIDER_TURNSTILE,
			CreateCaptchaRequired: true,
			AllowedTtlSeconds:     []uint32{3600},
			DefaultTtlSeconds:     3600,
			MaxUrlBytes:           4096,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
		Now:         func() time.Time { return time.Unix(10000, 0).UTC() },
	})
	missing := postProtobuf(router, "/api/v1/envelopes", validCreateBody(t))
	if missing.Code != http.StatusForbidden {
		t.Fatalf("missing token status=%d body=%x", missing.Code, missing.Body.Bytes())
	}

	var createRequest securlv1.CreateEnvelopeRequest
	if err := decodeCanonical(validCreateBody(t), &createRequest); err != nil {
		t.Fatal(err)
	}
	createRequest.CaptchaToken = "invalid"
	invalidBody, err := createRequest.MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	invalid := postProtobuf(router, "/api/v1/envelopes", invalidBody)
	if invalid.Code != http.StatusForbidden {
		t.Fatalf("invalid token status=%d body=%x", invalid.Code, invalid.Body.Bytes())
	}
	var storageKey [32]byte
	if _, err := repository.Get(context.Background(), storageKey, time.Unix(0, 0)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unsolved create stored record: %v", err)
	}

	createRequest.CaptchaToken = "valid-create-token"
	validBody, err := createRequest.MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	created := postProtobuf(router, "/api/v1/envelopes", validBody)
	replayed := postProtobuf(router, "/api/v1/envelopes", validBody)
	if created.Code != http.StatusCreated || replayed.Code != http.StatusOK || verifier.calls != 1 {
		t.Fatalf("created=%d replayed=%d verifier calls=%d", created.Code, replayed.Code, verifier.calls)
	}
	if _, err := repository.Get(context.Background(), storageKey, time.Unix(10000, 0)); err != nil {
		t.Fatalf("solved create missing record: %v", err)
	}
}

func TestCreateRejectsMalformedUnknownDuplicateAndNonCanonicalWireData(t *testing.T) {
	valid := validCreateBody(t)
	tests := map[string][]byte{
		"malformed":       {0xff},
		"unknown field":   append(append([]byte(nil), valid...), 0x98, 0x06, 0x01),
		"duplicate field": append(append([]byte(nil), valid...), append([]byte{0x0a, 0x20}, make([]byte, 32)...)...),
		"trailing byte":   append(append([]byte(nil), valid...), 0x00),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			response := postProtobuf(validationRouter(memory.New()), "/api/v1/envelopes", body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%x", response.Code, response.Body.Bytes())
			}
		})
	}
}

func TestRequestContentTypeAndSizeBoundaries(t *testing.T) {
	router := validationRouter(memory.New())
	request := httptest.NewRequest(http.MethodPost, "/api/v1/envelopes", bytes.NewReader(validCreateBody(t)))
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type status=%d", response.Code)
	}

	response = postProtobuf(router, "/api/v1/envelopes", make([]byte, createRequestLimit))
	if response.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("exact boundary incorrectly rejected: %d", response.Code)
	}
	response = postProtobuf(router, "/api/v1/envelopes", make([]byte, createRequestLimit+1))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("over boundary status=%d", response.Code)
	}
}

func TestCreateAllowsUnlimitedTTLWithoutExpiration(t *testing.T) {
	repository := memory.New()
	router := NewRouter(Dependencies{
		Repository: repository,
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{0}, DefaultTtlSeconds: 0, MaxUrlBytes: 4096,
		},
		AllowedTTLs: map[uint32]struct{}{0: {}},
		Now:         func() time.Time { return time.Unix(10000, 0).UTC() },
	})
	body, err := (&securlv1.CreateEnvelopeRequest{
		StorageKey: make([]byte, 32),
		Envelope: &securlv1.Envelope{
			Metadata: &securlv1.EnvelopeMetadata{
				ProtocolVersion: 1, TtlSeconds: 0, PayloadNonce: bytes.Repeat([]byte{1}, 24),
			},
			Ciphertext: []byte{2, 3, 4},
		},
	}).MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	response := postProtobuf(router, "/api/v1/envelopes", body)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%x", response.Code, response.Body.Bytes())
	}
	var created securlv1.CreateEnvelopeResponse
	if err := decodeCanonical(response.Body.Bytes(), &created); err != nil || created.ExpiresAtUnix != 0 {
		t.Fatalf("created=%+v err=%v", &created, err)
	}
	var storageKey [32]byte
	if _, err := repository.Get(context.Background(), storageKey, time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("unlimited envelope missing: %v", err)
	}
}

func TestCreateValidatesFlagsTTLAndLayerMetadata(t *testing.T) {
	tests := []struct {
		name     string
		metadata *securlv1.EnvelopeMetadata
	}{
		{
			name: "unknown flag",
			metadata: &securlv1.EnvelopeMetadata{
				ProtocolVersion: 1, FeatureFlags: 8, TtlSeconds: 3600, PayloadNonce: make([]byte, 24),
			},
		},
		{
			name: "unallowed ttl",
			metadata: &securlv1.EnvelopeMetadata{
				ProtocolVersion: 1, TtlSeconds: 7200, PayloadNonce: make([]byte, 24),
			},
		},
		{
			name: "password mismatch",
			metadata: &securlv1.EnvelopeMetadata{
				ProtocolVersion: 1,
				FeatureFlags:    uint32(securlv1.FeatureFlag_FEATURE_FLAG_PASSWORD),
				TtlSeconds:      3600,
				PayloadNonce:    make([]byte, 24),
			},
		},
		{
			name: "captcha mismatch",
			metadata: &securlv1.EnvelopeMetadata{
				ProtocolVersion: 1,
				FeatureFlags:    uint32(securlv1.FeatureFlag_FEATURE_FLAG_CAPTCHA),
				TtlSeconds:      3600,
				PayloadNonce:    make([]byte, 24),
				Captcha:         &securlv1.CaptchaLayer{Nonce: make([]byte, 23)},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := (&securlv1.CreateEnvelopeRequest{
				StorageKey: make([]byte, 32),
				Envelope:   &securlv1.Envelope{Metadata: test.metadata, Ciphertext: []byte{1}},
			}).MarshalVTStrict()
			if err != nil {
				t.Fatal(err)
			}
			response := postProtobuf(validationRouter(memory.New()), "/api/v1/envelopes", body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d", response.Code)
			}
		})
	}
}

type countingRepository struct {
	store.Repository
	getCalls int
}

func (repository *countingRepository) Get(
	ctx context.Context,
	key [32]byte,
	now time.Time,
) (store.Record, error) {
	repository.getCalls++
	return repository.Repository.Get(ctx, key, now)
}

func TestInvalidStorageKeyNeverReachesRepository(t *testing.T) {
	repository := &countingRepository{Repository: memory.New()}
	router := validationRouter(repository)
	for _, key := range []string{"short", base64.RawURLEncoding.EncodeToString(make([]byte, 31)), strings.Repeat("z", 43)} {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/envelopes/"+key, nil)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusNotFound {
			t.Fatalf("key=%q status=%d", key, response.Code)
		}
	}
	if repository.getCalls != 0 {
		t.Fatalf("repository Get calls=%d", repository.getCalls)
	}
}

func FuzzCreateEnvelope(fuzz *testing.F) {
	fuzz.Add(validCreateBody(fuzz))
	fuzz.Add([]byte{0xff, 0x00})
	fuzz.Fuzz(func(t *testing.T, body []byte) {
		response := postProtobuf(validationRouter(memory.New()), "/api/v1/envelopes", body)
		switch response.Code {
		case http.StatusCreated, http.StatusBadRequest, http.StatusRequestEntityTooLarge:
		default:
			t.Fatalf("unexpected status=%d body=%x", response.Code, response.Body.Bytes())
		}
	})
}

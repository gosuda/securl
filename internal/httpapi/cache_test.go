package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	"securl.click/securl/internal/access"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/memory"
)

func storedEnvelope(t testing.TB, repository store.Repository, flags uint32) ([16]byte, string, []byte) {
	t.Helper()
	var storageKey [16]byte
	storageKey[0] = byte(flags + 1)
	metadata := &securlv1.EnvelopeMetadata{
		ProtocolVersion: 2,
		FeatureFlags:    flags,
		TtlSeconds:      3600,
		PayloadNonce:    bytes.Repeat([]byte{1}, 24),
	}
	if flags&access.CaptchaFlag != 0 {
		metadata.Captcha = &securlv1.CaptchaLayer{Nonce: bytes.Repeat([]byte{2}, 24)}
	}
	metadataBytes, err := metadata.MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	envelope := &securlv1.Envelope{Metadata: metadata, Ciphertext: []byte{9, 8, 7, 6}}
	envelopeBytes, err := envelope.MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(envelopeBytes)
	etag := `"` + base64.RawURLEncoding.EncodeToString(hash[:]) + `"`
	_, err = repository.Create(context.Background(), store.CreateInput{
		StorageKey:   storageKey,
		Metadata:     metadataBytes,
		Envelope:     envelopeBytes,
		ETag:         etag,
		FeatureFlags: flags,
		ExpiresAt:    time.Unix(12000, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return storageKey, etag, envelopeBytes
}

func cacheRouter(repository store.Repository) http.Handler {
	return NewRouter(Dependencies{
		Repository: repository,
		RuntimeConfig: &securlv1.RuntimeConfig{
			AllowedTtlSeconds: []uint32{3600}, DefaultTtlSeconds: 3600,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
		Now:         func() time.Time { return time.Unix(11000, 0).UTC() },
	})
}

func TestOrdinaryGetUsesETagAndPrivateRevalidation(t *testing.T) {
	repository := memory.New()
	storageKey, etag, envelopeBytes := storedEnvelope(t, repository, 0)
	path := "/api/v1/envelopes/" + base64.RawURLEncoding.EncodeToString(storageKey[:])
	router := cacheRouter(repository)

	request := httptest.NewRequest(http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), envelopeBytes) {
		t.Fatalf("status=%d body=%x", response.Code, response.Body.Bytes())
	}
	if response.Header().Get("ETag") != etag || response.Header().Get("Cache-Control") != "private, no-cache" {
		t.Fatalf("headers=%v", response.Header())
	}

	request = httptest.NewRequest(http.MethodGet, path, nil)
	request.Header.Set("If-None-Match", etag)
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatalf("304 response status=%d body=%x", response.Code, response.Body.Bytes())
	}
}

func TestMetadataNeverReturnsCiphertextAndUsesNoStore(t *testing.T) {
	repository := memory.New()
	storageKey, _, _ := storedEnvelope(t, repository, 0)
	path := "/api/v1/envelopes/" + base64.RawURLEncoding.EncodeToString(storageKey[:]) + "/metadata"
	response := httptest.NewRecorder()
	cacheRouter(repository).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
	if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatalf("status=%d headers=%v", response.Code, response.Header())
	}
	var metadataResponse securlv1.GetEnvelopeMetadataResponse
	if err := decodeCanonical(response.Body.Bytes(), &metadataResponse); err != nil {
		t.Fatal(err)
	}
	if metadataResponse.Metadata == nil || metadataResponse.Metadata.TtlSeconds != 3600 {
		t.Fatalf("metadata=%+v", metadataResponse.Metadata)
	}
}

func TestProtectedRecordsRejectOrdinaryGetWithoutETag(t *testing.T) {
	for _, flags := range []uint32{access.CaptchaFlag, access.BurnAfterReadFlag} {
		repository := memory.New()
		storageKey, _, _ := storedEnvelope(t, repository, flags)
		path := "/api/v1/envelopes/" + base64.RawURLEncoding.EncodeToString(storageKey[:])
		response := httptest.NewRecorder()
		cacheRouter(repository).ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusConflict || response.Header().Get("ETag") != "" {
			t.Fatalf("flags=%d status=%d headers=%v", flags, response.Code, response.Header())
		}
	}
}

func TestCreateReplayReturns200AndCollisionReturns409(t *testing.T) {
	repository := memory.New()
	router := validationRouter(repository)
	body := validCreateBody(t)
	first := postProtobuf(router, "/api/v1/envelopes", body)
	second := postProtobuf(router, "/api/v1/envelopes", body)
	if first.Code != http.StatusCreated || second.Code != http.StatusOK {
		t.Fatalf("first=%d second=%d", first.Code, second.Code)
	}
	var replay securlv1.CreateEnvelopeResponse
	if err := decodeCanonical(second.Body.Bytes(), &replay); err != nil || !replay.Replayed {
		t.Fatalf("replay=%+v err=%v", &replay, err)
	}

	var request securlv1.CreateEnvelopeRequest
	if err := decodeCanonical(body, &request); err != nil {
		t.Fatal(err)
	}
	request.Envelope.Ciphertext = []byte{5, 6, 7}
	collisionBody, err := request.MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	collision := postProtobuf(router, "/api/v1/envelopes", collisionBody)
	if collision.Code != http.StatusConflict {
		t.Fatalf("collision status=%d", collision.Code)
	}
}

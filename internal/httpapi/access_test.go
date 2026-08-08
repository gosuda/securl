package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	securlv1 "securl.click/securl/gen/go/securl/v1"
	accessservice "securl.click/securl/internal/access"
	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/memory"
)

type mutableVerifier struct {
	err error
}

func (verifier *mutableVerifier) Verify(context.Context, string) error {
	return verifier.err
}

func protectedRecord(
	t testing.TB,
	repository store.Repository,
	wrapper *captcha.KeyWrapper,
	flags uint32,
) ([32]byte, []byte) {
	t.Helper()
	var storageKey [32]byte
	storageKey[0] = byte(flags + 20)
	metadata := &securlv1.EnvelopeMetadata{
		ProtocolVersion: 1,
		FeatureFlags:    flags,
		TtlSeconds:      3600,
		PayloadNonce:    bytes.Repeat([]byte{1}, 24),
	}
	var captchaKey, nonce, ciphertext []byte
	var err error
	if flags&accessservice.CaptchaFlag != 0 {
		metadata.Captcha = &securlv1.CaptchaLayer{Nonce: bytes.Repeat([]byte{2}, 24)}
		captchaKey = bytes.Repeat([]byte{3}, 32)
		nonce, ciphertext, err = wrapper.Wrap(storageKey, 1, captchaKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	metadataBytes, err := metadata.MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	envelopeBytes, err := (&securlv1.Envelope{
		Metadata: metadata, Ciphertext: []byte{4, 5, 6},
	}).MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	_, err = repository.Create(context.Background(), store.CreateInput{
		StorageKey:           storageKey,
		Metadata:             metadataBytes,
		Envelope:             envelopeBytes,
		FeatureFlags:         flags,
		ExpiresAt:            time.Unix(14000, 0).UTC(),
		CaptchaKeyNonce:      nonce,
		CaptchaKeyCiphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}
	return storageKey, captchaKey
}

func protectedRouter(
	repository store.Repository,
	service *accessservice.Service,
	verifier captcha.Verifier,
	wrapper *captcha.KeyWrapper,
) http.Handler {
	return NewRouter(Dependencies{
		Repository:      repository,
		Access:          service,
		CaptchaVerifier: verifier,
		CaptchaWrapper:  wrapper,
		RuntimeConfig: &securlv1.RuntimeConfig{
			CaptchaProvider: securlv1.CaptchaProvider_CAPTCHA_PROVIDER_TURNSTILE,
		},
		AllowedTTLs: map[uint32]struct{}{3600: {}},
		Now:         func() time.Time { return time.Unix(11000, 0).UTC() },
	})
}

func TestBurnAccessConsumesOnlyAfterSuccessfulCaptcha(t *testing.T) {
	repository := memory.New()
	wrapper, err := captcha.NewKeyWrapper(
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &mutableVerifier{err: captcha.ErrCaptchaFailed}
	service := accessservice.NewService(repository, verifier, wrapper)
	storageKey, captchaKey := protectedRecord(
		t, repository, wrapper, accessservice.CaptchaFlag|accessservice.BurnAfterReadFlag,
	)
	encodedKey := base64.RawURLEncoding.EncodeToString(storageKey[:])
	router := protectedRouter(repository, service, verifier, wrapper)

	ordinary := httptest.NewRecorder()
	router.ServeHTTP(
		ordinary,
		httptest.NewRequest(http.MethodGet, "/api/v1/envelopes/"+encodedKey, nil),
	)
	if ordinary.Code != http.StatusConflict {
		t.Fatalf("ordinary GET status=%d", ordinary.Code)
	}

	requestBody, err := (&securlv1.AccessEnvelopeRequest{CaptchaToken: "token"}).MarshalVTStrict()
	if err != nil {
		t.Fatal(err)
	}
	failed := postProtobuf(router, "/api/v1/envelopes/"+encodedKey+"/access", requestBody)
	if failed.Code != http.StatusForbidden {
		t.Fatalf("failed CAPTCHA status=%d", failed.Code)
	}
	if _, err := repository.Get(context.Background(), storageKey, time.Unix(13000, 0)); err != nil {
		t.Fatalf("failed CAPTCHA consumed record: %v", err)
	}

	verifier.err = captcha.ErrDependencyUnavailable
	unavailable := postProtobuf(router, "/api/v1/envelopes/"+encodedKey+"/access", requestBody)
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("dependency status=%d", unavailable.Code)
	}
	if _, err := repository.Get(context.Background(), storageKey, time.Unix(13000, 0)); err != nil {
		t.Fatalf("dependency failure consumed record: %v", err)
	}

	verifier.err = nil
	success := postProtobuf(router, "/api/v1/envelopes/"+encodedKey+"/access", requestBody)
	if success.Code != http.StatusOK || success.Header().Get("Cache-Control") != "private, no-store" ||
		success.Header().Get("ETag") != "" {
		t.Fatalf("success status=%d headers=%v", success.Code, success.Header())
	}
	var response securlv1.AccessEnvelopeResponse
	if err := decodeCanonical(success.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response.CaptchaKey, captchaKey) {
		t.Fatalf("CAPTCHA key=%x", response.CaptchaKey)
	}
	second := postProtobuf(router, "/api/v1/envelopes/"+encodedKey+"/access", requestBody)
	if second.Code != http.StatusNotFound {
		t.Fatalf("second access status=%d", second.Code)
	}
}

func TestBurnWithoutCaptchaAcceptsCanonicalEmptyRequestOnce(t *testing.T) {
	repository := memory.New()
	service := accessservice.NewService(repository, nil, nil)
	storageKey, _ := protectedRecord(t, repository, nil, accessservice.BurnAfterReadFlag)
	encodedKey := base64.RawURLEncoding.EncodeToString(storageKey[:])
	router := protectedRouter(repository, service, nil, nil)

	first := postProtobuf(router, "/api/v1/envelopes/"+encodedKey+"/access", nil)
	if first.Code != http.StatusOK {
		t.Fatalf("first status=%d body=%x", first.Code, first.Body.Bytes())
	}
	second := postProtobuf(router, "/api/v1/envelopes/"+encodedKey+"/access", nil)
	if second.Code != http.StatusNotFound {
		t.Fatalf("second status=%d", second.Code)
	}
}

func TestAccessBodyLimitIsFourKiB(t *testing.T) {
	repository := memory.New()
	service := accessservice.NewService(repository, nil, nil)
	storageKey, _ := protectedRecord(t, repository, nil, accessservice.BurnAfterReadFlag)
	encodedKey := base64.RawURLEncoding.EncodeToString(storageKey[:])
	response := postProtobuf(
		protectedRouter(repository, service, nil, nil),
		"/api/v1/envelopes/"+encodedKey+"/access",
		make([]byte, accessRequestLimit+1),
	)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestPlainRecordCannotUseAccessEndpoint(t *testing.T) {
	repository := memory.New()
	service := accessservice.NewService(repository, nil, nil)
	storageKey, _, _ := storedEnvelope(t, repository, 0)
	encodedKey := base64.RawURLEncoding.EncodeToString(storageKey[:])
	response := postProtobuf(
		protectedRouter(repository, service, nil, nil),
		"/api/v1/envelopes/"+encodedKey+"/access",
		nil,
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", response.Code)
	}
	if _, err := repository.Get(context.Background(), storageKey, time.Unix(11000, 0)); errors.Is(err, store.ErrNotFound) {
		t.Fatal("plain record was consumed")
	}
}

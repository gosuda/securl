package access

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"securl.click/securl/internal/captcha"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/memory"
)

type verifierFunc func(context.Context, string) error

func (verify verifierFunc) Verify(ctx context.Context, token string) error {
	return verify(ctx, token)
}

func TestInvalidCaptchaDoesNotConsumeBurnRecord(t *testing.T) {
	repository := memory.New()
	wrapKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x21}, 32))
	wrapper, err := captcha.NewKeyWrapper(wrapKey)
	if err != nil {
		t.Fatal(err)
	}
	var storageKey [32]byte
	storageKey[0] = 7
	captchaKey := bytes.Repeat([]byte{0x31}, 32)
	nonce, ciphertext, err := wrapper.Wrap(storageKey, 2, captchaKey)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(6000, 0).UTC()
	_, err = repository.Create(context.Background(), store.CreateInput{
		StorageKey:           storageKey,
		Metadata:             []byte{1},
		Envelope:             []byte{2},
		FeatureFlags:         CaptchaFlag | BurnAfterReadFlag,
		ExpiresAt:            now.Add(time.Hour),
		CaptchaKeyNonce:      nonce,
		CaptchaKeyCiphertext: ciphertext,
	})
	if err != nil {
		t.Fatal(err)
	}

	failedService := NewService(
		repository,
		verifierFunc(func(context.Context, string) error { return captcha.ErrCaptchaFailed }),
		wrapper,
	)
	if _, err := failedService.Access(context.Background(), storageKey, now, "bad"); !errors.Is(err, captcha.ErrCaptchaFailed) {
		t.Fatalf("invalid CAPTCHA error = %v", err)
	}
	if _, err := repository.Get(context.Background(), storageKey, now); err != nil {
		t.Fatalf("invalid CAPTCHA consumed record: %v", err)
	}

	successService := NewService(
		repository,
		verifierFunc(func(context.Context, string) error { return nil }),
		wrapper,
	)
	result, err := successService.Access(context.Background(), storageKey, now, "valid")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.CaptchaKey, captchaKey) {
		t.Fatalf("released CAPTCHA key = %x", result.CaptchaKey)
	}
	for index := range result.CaptchaKey {
		result.CaptchaKey[index] = 0
	}
	if _, err := successService.Access(context.Background(), storageKey, now, "valid"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second burn access error = %v", err)
	}
}

func TestBurnWithoutCaptchaConsumesImmediately(t *testing.T) {
	repository := memory.New()
	var storageKey [32]byte
	storageKey[0] = 8
	now := time.Unix(7000, 0).UTC()
	_, err := repository.Create(context.Background(), store.CreateInput{
		StorageKey:   storageKey,
		Metadata:     []byte{1},
		Envelope:     []byte{2},
		FeatureFlags: BurnAfterReadFlag,
		ExpiresAt:    now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(repository, nil, nil)
	if _, err := service.Access(context.Background(), storageKey, now, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Get(context.Background(), storageKey, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("burn record remained: %v", err)
	}
}

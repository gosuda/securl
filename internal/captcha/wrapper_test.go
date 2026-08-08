package captcha

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func TestKeyWrapperRoundTripBindsStorageKeyAndVersion(t *testing.T) {
	wrappingKey := bytes.Repeat([]byte{0x31}, 32)
	wrapper, err := NewKeyWrapper(base64.RawURLEncoding.EncodeToString(wrappingKey))
	if err != nil {
		t.Fatal(err)
	}
	var storageKey [32]byte
	storageKey[0] = 1
	captchaKey := bytes.Repeat([]byte{0x42}, 32)
	nonce, ciphertext, err := wrapper.Wrap(storageKey, 1, captchaKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != 12 || len(ciphertext) != 48 {
		t.Fatalf("nonce=%d ciphertext=%d", len(nonce), len(ciphertext))
	}
	plaintext, err := wrapper.Unwrap(storageKey, 1, nonce, ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, captchaKey) {
		t.Fatalf("plaintext mismatch: %x", plaintext)
	}
	for index := range plaintext {
		plaintext[index] = 0
	}

	wrongStorageKey := storageKey
	wrongStorageKey[0] = 2
	if _, err := wrapper.Unwrap(wrongStorageKey, 1, nonce, ciphertext); !errors.Is(err, ErrInvalidWrappedKey) {
		t.Fatalf("wrong storage key error = %v", err)
	}
	if _, err := wrapper.Unwrap(storageKey, 2, nonce, ciphertext); !errors.Is(err, ErrInvalidWrappedKey) {
		t.Fatalf("wrong version error = %v", err)
	}
}

func TestKeyWrapperRequiresCanonicalBase64URLKey(t *testing.T) {
	canonical := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32))
	if _, err := NewKeyWrapper(canonical); err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeyWrapper(canonical + "="); !errors.Is(err, ErrInvalidWrappedKey) {
		t.Fatalf("padded key error = %v", err)
	}
	if _, err := NewKeyWrapper("short"); !errors.Is(err, ErrInvalidWrappedKey) {
		t.Fatalf("short key error = %v", err)
	}
}

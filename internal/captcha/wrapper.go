package captcha

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
)

var ErrInvalidWrappedKey = errors.New("captcha: invalid wrapped key")

type KeyWrapper struct {
	aead cipher.AEAD
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func NewKeyWrapper(encodedKey string) (*KeyWrapper, error) {
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != 32 || base64.RawURLEncoding.EncodeToString(key) != encodedKey {
		zeroBytes(key)
		return nil, ErrInvalidWrappedKey
	}
	block, err := aes.NewCipher(key)
	zeroBytes(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &KeyWrapper{aead: aead}, nil
}

func wrapAAD(storageKey [32]byte, protocolVersion uint32) []byte {
	aad := make([]byte, 36)
	copy(aad, storageKey[:])
	binary.BigEndian.PutUint32(aad[32:], protocolVersion)
	return aad
}

func (wrapper *KeyWrapper) Wrap(
	storageKey [32]byte,
	protocolVersion uint32,
	captchaKey []byte,
) ([]byte, []byte, error) {
	if wrapper == nil || wrapper.aead == nil || len(captchaKey) != 32 || protocolVersion != 2 {
		return nil, nil, ErrInvalidWrappedKey
	}
	nonce := make([]byte, wrapper.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext := wrapper.aead.Seal(nil, nonce, captchaKey, wrapAAD(storageKey, protocolVersion))
	return nonce, ciphertext, nil
}

func (wrapper *KeyWrapper) Unwrap(
	storageKey [32]byte,
	protocolVersion uint32,
	nonce []byte,
	ciphertext []byte,
) ([]byte, error) {
	if wrapper == nil || wrapper.aead == nil || len(nonce) != wrapper.aead.NonceSize() || protocolVersion != 2 {
		return nil, ErrInvalidWrappedKey
	}
	plaintext, err := wrapper.aead.Open(nil, nonce, ciphertext, wrapAAD(storageKey, protocolVersion))
	if err != nil || len(plaintext) != 32 {
		zeroBytes(plaintext)
		return nil, ErrInvalidWrappedKey
	}
	return plaintext, nil
}

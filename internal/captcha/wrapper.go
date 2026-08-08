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

func NewKeyWrapper(encodedKey string) (*KeyWrapper, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encodedKey {
		return nil, ErrInvalidWrappedKey
	}
	block, err := aes.NewCipher(decoded)
	for index := range decoded {
		decoded[index] = 0
	}
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
	if wrapper == nil || wrapper.aead == nil || len(captchaKey) != 32 || protocolVersion != 1 {
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
	if wrapper == nil || wrapper.aead == nil || len(nonce) != wrapper.aead.NonceSize() || protocolVersion != 1 {
		return nil, ErrInvalidWrappedKey
	}
	plaintext, err := wrapper.aead.Open(nil, nonce, ciphertext, wrapAAD(storageKey, protocolVersion))
	if err != nil || len(plaintext) != 32 {
		if plaintext != nil {
			for index := range plaintext {
				plaintext[index] = 0
			}
		}
		return nil, ErrInvalidWrappedKey
	}
	return plaintext, nil
}

package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: conflict")
	ErrInvalid  = errors.New("store: invalid input")
)

type CreateInput struct {
	StorageKey           [16]byte
	Metadata             []byte
	Envelope             []byte
	RequestHash          [32]byte
	ETag                 string
	FeatureFlags         uint32
	ExpiresAt            time.Time
	CaptchaKeyNonce      []byte
	CaptchaKeyCiphertext []byte
}

type CreateResult struct {
	ExpiresAt time.Time
	Replayed  bool
}

type MetadataRecord struct {
	Metadata     []byte
	FeatureFlags uint32
	ExpiresAt    time.Time
}

type Record struct {
	Metadata             []byte
	Envelope             []byte
	RequestHash          [32]byte
	ETag                 string
	FeatureFlags         uint32
	ExpiresAt            time.Time
	CaptchaKeyNonce      []byte
	CaptchaKeyCiphertext []byte
}

type Repository interface {
	Create(context.Context, CreateInput) (CreateResult, error)
	GetMetadata(context.Context, [16]byte, time.Time) (MetadataRecord, error)
	Get(context.Context, [16]byte, time.Time) (Record, error)
	Consume(context.Context, [16]byte, time.Time) (Record, error)
	DeleteExpired(context.Context, time.Time, int32) (int64, error)
	Ping(context.Context) error
	Close()
}

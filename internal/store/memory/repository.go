package memory

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"securl.click/securl/internal/store"
)

type Repository struct {
	mu      sync.Mutex
	records map[[32]byte]store.Record
}

var _ store.Repository = (*Repository)(nil)

func New() *Repository {
	return &Repository{records: make(map[[32]byte]store.Record)}
}

func cloneBytes(input []byte) []byte {
	if input == nil {
		return nil
	}
	return append([]byte(nil), input...)
}

func cloneRecord(record store.Record) store.Record {
	record.Metadata = cloneBytes(record.Metadata)
	record.Envelope = cloneBytes(record.Envelope)
	record.CaptchaKeyNonce = cloneBytes(record.CaptchaKeyNonce)
	record.CaptchaKeyCiphertext = cloneBytes(record.CaptchaKeyCiphertext)
	return record
}

func hasExpired(now, expiresAt time.Time) bool {
	return !expiresAt.IsZero() && !now.Before(expiresAt)
}

func (repository *Repository) Create(ctx context.Context, input store.CreateInput) (store.CreateResult, error) {
	if err := ctx.Err(); err != nil {
		return store.CreateResult{}, err
	}
	if len(input.Metadata) == 0 || len(input.Envelope) == 0 {
		return store.CreateResult{}, store.ErrInvalid
	}
	if len(input.CaptchaKeyNonce) != 0 || len(input.CaptchaKeyCiphertext) != 0 {
		if len(input.CaptchaKeyNonce) != 12 || len(input.CaptchaKeyCiphertext) == 0 {
			return store.CreateResult{}, store.ErrInvalid
		}
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, ok := repository.records[input.StorageKey]; ok {
		if bytes.Equal(existing.RequestHash[:], input.RequestHash[:]) {
			return store.CreateResult{ExpiresAt: existing.ExpiresAt, Replayed: true}, nil
		}
		return store.CreateResult{}, store.ErrConflict
	}

	repository.records[input.StorageKey] = cloneRecord(store.Record{
		Metadata:             input.Metadata,
		Envelope:             input.Envelope,
		RequestHash:          input.RequestHash,
		ETag:                 input.ETag,
		FeatureFlags:         input.FeatureFlags,
		ExpiresAt:            input.ExpiresAt.UTC(),
		CaptchaKeyNonce:      input.CaptchaKeyNonce,
		CaptchaKeyCiphertext: input.CaptchaKeyCiphertext,
	})
	return store.CreateResult{ExpiresAt: input.ExpiresAt.UTC()}, nil
}

func (repository *Repository) GetMetadata(
	ctx context.Context,
	storageKey [32]byte,
	now time.Time,
) (store.MetadataRecord, error) {
	if err := ctx.Err(); err != nil {
		return store.MetadataRecord{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, ok := repository.records[storageKey]
	if !ok || hasExpired(now, record.ExpiresAt) {
		return store.MetadataRecord{}, store.ErrNotFound
	}
	return store.MetadataRecord{
		Metadata:     cloneBytes(record.Metadata),
		FeatureFlags: record.FeatureFlags,
		ExpiresAt:    record.ExpiresAt,
	}, nil
}

func (repository *Repository) Get(
	ctx context.Context,
	storageKey [32]byte,
	now time.Time,
) (store.Record, error) {
	if err := ctx.Err(); err != nil {
		return store.Record{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, ok := repository.records[storageKey]
	if !ok || hasExpired(now, record.ExpiresAt) {
		return store.Record{}, store.ErrNotFound
	}
	return cloneRecord(record), nil
}

func (repository *Repository) Consume(
	ctx context.Context,
	storageKey [32]byte,
	now time.Time,
) (store.Record, error) {
	if err := ctx.Err(); err != nil {
		return store.Record{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, ok := repository.records[storageKey]
	if !ok || hasExpired(now, record.ExpiresAt) {
		return store.Record{}, store.ErrNotFound
	}
	delete(repository.records, storageKey)
	return cloneRecord(record), nil
}

func (repository *Repository) DeleteExpired(
	ctx context.Context,
	now time.Time,
	batch int32,
) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if batch <= 0 {
		return 0, store.ErrInvalid
	}
	type expiredRecord struct {
		key       [32]byte
		expiresAt time.Time
	}

	repository.mu.Lock()
	defer repository.mu.Unlock()
	expired := make([]expiredRecord, 0)
	for key, record := range repository.records {
		if hasExpired(now, record.ExpiresAt) {
			expired = append(expired, expiredRecord{key: key, expiresAt: record.ExpiresAt})
		}
	}
	sort.Slice(expired, func(left, right int) bool {
		return expired[left].expiresAt.Before(expired[right].expiresAt)
	})
	if len(expired) > int(batch) {
		expired = expired[:batch]
	}
	for _, record := range expired {
		delete(repository.records, record.key)
	}
	return int64(len(expired)), nil
}

func (repository *Repository) Ping(ctx context.Context) error {
	return ctx.Err()
}

func (repository *Repository) Close() {}

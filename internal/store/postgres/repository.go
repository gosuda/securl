package postgres

import (
	"bytes"
	"context"
	"errors"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"securl.click/securl/db/postgres/migrations"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/postgres/dbgen"
)

type Repository struct {
	pool    *pgxpool.Pool
	queries *dbgen.Queries
}

var _ store.Repository = (*Repository)(nil)

func Open(ctx context.Context, databaseURL string) (*Repository, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := migrations.Apply(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return New(pool), nil
}

func New(pool *pgxpool.Pool) *Repository {
	return &Repository{pool: pool, queries: dbgen.New(pool)}
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

func pgTime(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}

func timestamp(value pgtype.Timestamptz) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func recordFromDatabase(row dbgen.Envelope) (store.Record, error) {
	if len(row.RequestHash) != 32 || row.FeatureFlags < 0 {
		return store.Record{}, store.ErrInvalid
	}
	var requestHash [32]byte
	copy(requestHash[:], row.RequestHash)
	return cloneRecord(store.Record{
		Metadata:             row.Metadata,
		Envelope:             row.Envelope,
		RequestHash:          requestHash,
		ETag:                 row.Etag,
		FeatureFlags:         uint32(row.FeatureFlags),
		ExpiresAt:            timestamp(row.ExpiresAt),
		CaptchaKeyNonce:      row.CaptchaKeyNonce,
		CaptchaKeyCiphertext: row.CaptchaKeyCiphertext,
	}), nil
}

func validateCreateInput(input store.CreateInput) error {
	if len(input.Metadata) == 0 || len(input.Envelope) == 0 {
		return store.ErrInvalid
	}
	if input.FeatureFlags > math.MaxInt32 {
		return store.ErrInvalid
	}
	if len(input.CaptchaKeyNonce) != 0 || len(input.CaptchaKeyCiphertext) != 0 {
		if len(input.CaptchaKeyNonce) != 12 || len(input.CaptchaKeyCiphertext) == 0 {
			return store.ErrInvalid
		}
	}
	return nil
}

func (repository *Repository) Create(
	ctx context.Context,
	input store.CreateInput,
) (store.CreateResult, error) {
	if err := validateCreateInput(input); err != nil {
		return store.CreateResult{}, err
	}
	row, err := repository.queries.CreateEnvelope(ctx, dbgen.CreateEnvelopeParams{
		StorageKey:           cloneBytes(input.StorageKey[:]),
		Metadata:             cloneBytes(input.Metadata),
		Envelope:             cloneBytes(input.Envelope),
		RequestHash:          cloneBytes(input.RequestHash[:]),
		Etag:                 input.ETag,
		FeatureFlags:         int32(input.FeatureFlags),
		ExpiresAt:            pgTime(input.ExpiresAt),
		CaptchaKeyNonce:      cloneBytes(input.CaptchaKeyNonce),
		CaptchaKeyCiphertext: cloneBytes(input.CaptchaKeyCiphertext),
	})
	if err == nil {
		return store.CreateResult{ExpiresAt: timestamp(row.ExpiresAt)}, nil
	}

	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23505" {
		return store.CreateResult{}, err
	}
	existing, lookupErr := repository.queries.GetEnvelopeByKey(ctx, dbgen.GetEnvelopeByKeyParams{
		StorageKey: cloneBytes(input.StorageKey[:]),
		ExpiresAt:  pgTime(time.Unix(0, 0)),
	})
	if lookupErr != nil {
		if errors.Is(lookupErr, pgx.ErrNoRows) {
			return store.CreateResult{}, store.ErrConflict
		}
		return store.CreateResult{}, lookupErr
	}
	if !bytes.Equal(existing.RequestHash, input.RequestHash[:]) {
		return store.CreateResult{}, store.ErrConflict
	}
	return store.CreateResult{ExpiresAt: timestamp(existing.ExpiresAt), Replayed: true}, nil
}

func (repository *Repository) GetMetadata(
	ctx context.Context,
	storageKey [32]byte,
	now time.Time,
) (store.MetadataRecord, error) {
	row, err := repository.queries.GetEnvelopeMetadataByKey(ctx, dbgen.GetEnvelopeMetadataByKeyParams{
		StorageKey: cloneBytes(storageKey[:]),
		ExpiresAt:  pgTime(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.MetadataRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.MetadataRecord{}, err
	}
	if row.FeatureFlags < 0 {
		return store.MetadataRecord{}, store.ErrInvalid
	}
	return store.MetadataRecord{
		Metadata:     cloneBytes(row.Metadata),
		FeatureFlags: uint32(row.FeatureFlags),
		ExpiresAt:    timestamp(row.ExpiresAt),
	}, nil
}

func (repository *Repository) Get(
	ctx context.Context,
	storageKey [32]byte,
	now time.Time,
) (store.Record, error) {
	row, err := repository.queries.GetEnvelopeByKey(ctx, dbgen.GetEnvelopeByKeyParams{
		StorageKey: cloneBytes(storageKey[:]),
		ExpiresAt:  pgTime(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Record{}, store.ErrNotFound
	}
	if err != nil {
		return store.Record{}, err
	}
	return recordFromDatabase(row)
}

func (repository *Repository) Consume(
	ctx context.Context,
	storageKey [32]byte,
	now time.Time,
) (store.Record, error) {
	row, err := repository.queries.ConsumeEnvelope(ctx, dbgen.ConsumeEnvelopeParams{
		StorageKey: cloneBytes(storageKey[:]),
		ExpiresAt:  pgTime(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Record{}, store.ErrNotFound
	}
	if err != nil {
		return store.Record{}, err
	}
	return recordFromDatabase(row)
}

func (repository *Repository) DeleteExpired(
	ctx context.Context,
	now time.Time,
	batch int32,
) (int64, error) {
	if batch <= 0 {
		return 0, store.ErrInvalid
	}
	keys, err := repository.queries.DeleteExpiredEnvelopes(ctx, dbgen.DeleteExpiredEnvelopesParams{
		ExpiresAt: pgTime(now),
		BatchSize: batch,
	})
	return int64(len(keys)), err
}

func (repository *Repository) Ping(ctx context.Context) error {
	return repository.pool.Ping(ctx)
}

func (repository *Repository) Close() {
	repository.pool.Close()
}

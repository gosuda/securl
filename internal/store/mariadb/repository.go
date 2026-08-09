package mariadb

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	mysql "github.com/go-sql-driver/mysql"

	"securl.click/securl/db/mariadb/migrations"
	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/mariadb/dbgen"
)

type Repository struct {
	database *sql.DB
	queries  *dbgen.Queries
}

var _ store.Repository = (*Repository)(nil)

func connectionConfig(dsn string) (*mysql.Config, error) {
	configuration, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}
	configuration.ParseTime = true
	configuration.Loc = time.UTC
	configuration.Collation = "utf8mb4_bin"
	if configuration.Params == nil {
		configuration.Params = make(map[string]string)
	}
	configuration.Params["charset"] = "utf8mb4"
	return configuration, nil
}

func Open(ctx context.Context, dsn string) (*Repository, error) {
	configuration, err := connectionConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse MariaDB DSN: %w", err)
	}

	database, err := sql.Open("mysql", configuration.FormatDSN())
	if err != nil {
		return nil, fmt.Errorf("open MariaDB: %w", err)
	}
	if err := database.PingContext(ctx); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping MariaDB: %w", err)
	}
	if err := migrations.Apply(ctx, database); err != nil {
		database.Close()
		return nil, fmt.Errorf("migrate MariaDB: %w", err)
	}
	return New(database), nil
}

func New(database *sql.DB) *Repository {
	return &Repository{database: database, queries: dbgen.New(database)}
}

func cloneBytes(input []byte) []byte {
	if input == nil {
		return nil
	}
	return append([]byte(nil), input...)
}

func databaseBytes(input []byte) []byte {
	output := make([]byte, len(input))
	copy(output, input)
	return output
}

func optionalBytes(input []byte) []byte {
	if len(input) == 0 {
		return nil
	}
	return cloneBytes(input)
}

func nullTime(value time.Time) sql.NullTime {
	if value.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: value.UTC(), Valid: true}
}

func timestamp(value sql.NullTime) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return value.Time.UTC()
}

func recordFromDatabase(row dbgen.Envelope) (store.Record, error) {
	if len(row.RequestHash) != 32 {
		return store.Record{}, store.ErrInvalid
	}
	var requestHash [32]byte
	copy(requestHash[:], row.RequestHash)
	return store.Record{
		Metadata:             cloneBytes(row.Metadata),
		Envelope:             cloneBytes(row.Envelope),
		RequestHash:          requestHash,
		ETag:                 row.Etag,
		FeatureFlags:         row.FeatureFlags,
		ExpiresAt:            timestamp(row.ExpiresAt),
		CaptchaKeyNonce:      optionalBytes(row.CaptchaKeyNonce),
		CaptchaKeyCiphertext: optionalBytes(row.CaptchaKeyCiphertext),
	}, nil
}

func validateCreateInput(input store.CreateInput) error {
	if len(input.Metadata) == 0 || len(input.Envelope) == 0 {
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
	_, err := repository.queries.CreateEnvelope(ctx, dbgen.CreateEnvelopeParams{
		StorageKey:           cloneBytes(input.StorageKey[:]),
		Metadata:             cloneBytes(input.Metadata),
		Envelope:             cloneBytes(input.Envelope),
		RequestHash:          cloneBytes(input.RequestHash[:]),
		Etag:                 input.ETag,
		FeatureFlags:         input.FeatureFlags,
		ExpiresAt:            nullTime(input.ExpiresAt),
		CaptchaKeyNonce:      databaseBytes(input.CaptchaKeyNonce),
		CaptchaKeyCiphertext: databaseBytes(input.CaptchaKeyCiphertext),
	})
	if err == nil {
		return store.CreateResult{ExpiresAt: input.ExpiresAt.UTC()}, nil
	}
	var mariaError *mysql.MySQLError
	if !errors.As(err, &mariaError) || mariaError.Number != 1062 {
		return store.CreateResult{}, err
	}
	existing, lookupErr := repository.queries.GetEnvelopeForReplay(ctx, cloneBytes(input.StorageKey[:]))
	if errors.Is(lookupErr, sql.ErrNoRows) {
		return store.CreateResult{}, store.ErrConflict
	}
	if lookupErr != nil {
		return store.CreateResult{}, lookupErr
	}
	if !bytes.Equal(existing.RequestHash, input.RequestHash[:]) {
		return store.CreateResult{}, store.ErrConflict
	}
	return store.CreateResult{ExpiresAt: timestamp(existing.ExpiresAt), Replayed: true}, nil
}

func (repository *Repository) GetMetadata(
	ctx context.Context,
	storageKey [16]byte,
	now time.Time,
) (store.MetadataRecord, error) {
	row, err := repository.queries.GetEnvelopeMetadataByKey(ctx, dbgen.GetEnvelopeMetadataByKeyParams{
		StorageKey: cloneBytes(storageKey[:]),
		ExpiresAt:  nullTime(now),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return store.MetadataRecord{}, store.ErrNotFound
	}
	if err != nil {
		return store.MetadataRecord{}, err
	}
	return store.MetadataRecord{
		Metadata:     cloneBytes(row.Metadata),
		FeatureFlags: row.FeatureFlags,
		ExpiresAt:    timestamp(row.ExpiresAt),
	}, nil
}

func (repository *Repository) Get(
	ctx context.Context,
	storageKey [16]byte,
	now time.Time,
) (store.Record, error) {
	row, err := repository.queries.GetEnvelopeByKey(ctx, dbgen.GetEnvelopeByKeyParams{
		StorageKey: cloneBytes(storageKey[:]),
		ExpiresAt:  nullTime(now),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return store.Record{}, store.ErrNotFound
	}
	if err != nil {
		return store.Record{}, err
	}
	return recordFromDatabase(row)
}

func (repository *Repository) Consume(
	ctx context.Context,
	storageKey [16]byte,
	now time.Time,
) (store.Record, error) {
	transaction, err := repository.database.BeginTx(ctx, nil)
	if err != nil {
		return store.Record{}, err
	}
	defer transaction.Rollback()
	queries := repository.queries.WithTx(transaction)
	row, err := queries.LockEnvelopeByKey(ctx, dbgen.LockEnvelopeByKeyParams{
		StorageKey: cloneBytes(storageKey[:]),
		ExpiresAt:  nullTime(now),
	})
	if errors.Is(err, sql.ErrNoRows) {
		return store.Record{}, store.ErrNotFound
	}
	if err != nil {
		return store.Record{}, err
	}
	record, err := recordFromDatabase(row)
	if err != nil {
		return store.Record{}, err
	}
	deleted, err := queries.DeleteEnvelopeByKey(ctx, cloneBytes(storageKey[:]))
	if err != nil {
		return store.Record{}, err
	}
	if deleted != 1 {
		return store.Record{}, store.ErrInvalid
	}
	if err := transaction.Commit(); err != nil {
		return store.Record{}, err
	}
	return record, nil
}

func (repository *Repository) DeleteExpired(
	ctx context.Context,
	now time.Time,
	batch int32,
) (int64, error) {
	if batch <= 0 {
		return 0, store.ErrInvalid
	}
	return repository.queries.DeleteExpiredEnvelopes(ctx, dbgen.DeleteExpiredEnvelopesParams{
		ExpiresAt: nullTime(now),
		Limit:     batch,
	})
}

func (repository *Repository) Ping(ctx context.Context) error {
	return repository.database.PingContext(ctx)
}

func (repository *Repository) Close() {
	repository.database.Close()
}

package mariadb

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"securl.click/securl/db/mariadb/migrations"
	"securl.click/securl/internal/store"
)

func TestConnectionConfigForcesUTF8MB4AndUTC(t *testing.T) {
	configuration, err := connectionConfig("securl:secret@tcp(localhost:3306)/securl?charset=latin1&parseTime=false")
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.ParseTime || configuration.Loc != time.UTC || configuration.Collation != "utf8mb4_bin" ||
		configuration.Params["charset"] != "utf8mb4" {
		t.Fatalf("configuration=%+v", configuration)
	}
}

func testRepository(t testing.TB) *Repository {
	t.Helper()
	dsn := os.Getenv("TEST_MARIADB_DSN")
	if dsn == "" {
		t.Skip("TEST_MARIADB_DSN is not configured")
	}
	repository, err := Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := migrations.Apply(context.Background(), repository.database); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	if _, err := repository.database.ExecContext(context.Background(), "TRUNCATE envelopes"); err != nil {
		repository.Close()
		t.Fatal(err)
	}
	t.Cleanup(repository.Close)
	return repository
}

func createInput(keyByte, hashByte byte, expiresAt time.Time) store.CreateInput {
	var storageKey [16]byte
	storageKey[0] = keyByte
	var requestHash [32]byte
	requestHash[0] = hashByte
	return store.CreateInput{
		StorageKey:   storageKey,
		Metadata:     []byte{1, 2, 3},
		Envelope:     []byte{4, 5, 6},
		RequestHash:  requestHash,
		ETag:         `"etag"`,
		FeatureFlags: 0,
		ExpiresAt:    expiresAt,
	}
}

func TestRepositoryContract(t *testing.T) {
	repository := testRepository(t)
	if err := migrations.Apply(context.Background(), repository.database); err != nil {
		t.Fatal(err)
	}
	var migrationCount int
	if err := repository.database.QueryRowContext(context.Background(), "SELECT count(*) FROM securl_schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 1 {
		t.Fatalf("migration count=%d", migrationCount)
	}
	var connectionCharset, connectionCollation string
	if err := repository.database.QueryRowContext(
		context.Background(),
		"SELECT @@character_set_connection, @@collation_connection",
	).Scan(&connectionCharset, &connectionCollation); err != nil {
		t.Fatal(err)
	}
	if connectionCharset != "utf8mb4" || connectionCollation != "utf8mb4_bin" {
		t.Fatalf("connection charset=%s collation=%s", connectionCharset, connectionCollation)
	}
	rows, err := repository.database.QueryContext(context.Background(), `
SELECT table_name, table_collation
FROM information_schema.tables
WHERE table_schema = DATABASE() AND table_name IN ('envelopes', 'securl_schema_migrations')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	collations := make(map[string]string)
	for rows.Next() {
		var tableName, collation string
		if err := rows.Scan(&tableName, &collation); err != nil {
			t.Fatal(err)
		}
		collations[tableName] = collation
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, tableName := range []string{"envelopes", "securl_schema_migrations"} {
		if collations[tableName] != "utf8mb4_bin" {
			t.Fatalf("table %s collation=%q", tableName, collations[tableName])
		}
	}

	now := time.Unix(16000, 0).UTC()
	input := createInput(1, 1, now.Add(time.Hour))
	created, err := repository.Create(context.Background(), input)
	if err != nil || created.Replayed {
		t.Fatalf("create=%+v err=%v", created, err)
	}
	replayed, err := repository.Create(context.Background(), input)
	if err != nil || !replayed.Replayed || !replayed.ExpiresAt.Equal(created.ExpiresAt) {
		t.Fatalf("replay=%+v err=%v", replayed, err)
	}
	collision := input
	collision.RequestHash[0] = 2
	if _, err := repository.Create(context.Background(), collision); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("collision error=%v", err)
	}
	if _, err := repository.Get(context.Background(), input.StorageKey, input.ExpiresAt); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expiry boundary error=%v", err)
	}

	expired := createInput(2, 2, now.Add(-time.Minute))
	if _, err := repository.Create(context.Background(), expired); err != nil {
		t.Fatal(err)
	}
	deleted, err := repository.DeleteExpired(context.Background(), now, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup deleted=%d err=%v", deleted, err)
	}

	unlimited := createInput(4, 4, time.Time{})
	createdUnlimited, err := repository.Create(context.Background(), unlimited)
	if err != nil || !createdUnlimited.ExpiresAt.IsZero() {
		t.Fatalf("unlimited create=%+v err=%v", createdUnlimited, err)
	}
	if _, err := repository.Get(context.Background(), unlimited.StorageKey, time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("unlimited get: %v", err)
	}
	deleted, err = repository.DeleteExpired(context.Background(), time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), 10)
	if err != nil || deleted != 1 {
		t.Fatalf("future cleanup deleted=%d err=%v", deleted, err)
	}
	if _, err := repository.Get(context.Background(), unlimited.StorageKey, time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("unlimited record was cleaned up: %v", err)
	}
}

func TestBurnRace(t *testing.T) {
	repository := testRepository(t)
	now := time.Unix(17000, 0).UTC()
	input := createInput(3, 3, now.Add(time.Hour))
	if _, err := repository.Create(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var notFound atomic.Int32
	var wait sync.WaitGroup
	wait.Add(64)
	for range 64 {
		go func() {
			defer wait.Done()
			_, err := repository.Consume(context.Background(), input.StorageKey, now)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, store.ErrNotFound):
				notFound.Add(1)
			default:
				t.Errorf("consume error=%v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || notFound.Load() != 63 {
		t.Fatalf("successes=%d not_found=%d", successes.Load(), notFound.Load())
	}
}

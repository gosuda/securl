package memory

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"securl.click/securl/internal/store"
)

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
		ETag:         "etag",
		FeatureFlags: 4,
		ExpiresAt:    expiresAt,
	}
}

func TestCopiesStoredAndReturnedBytes(t *testing.T) {
	repository := New()
	now := time.Unix(1000, 0).UTC()
	input := createInput(1, 2, now.Add(time.Hour))
	if _, err := repository.Create(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.Metadata[0] = 99
	input.Envelope[0] = 99

	record, err := repository.Get(context.Background(), input.StorageKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if record.Metadata[0] != 1 || record.Envelope[0] != 4 {
		t.Fatalf("stored bytes were mutated: %+v", record)
	}
	record.Metadata[0] = 88
	record.Envelope[0] = 88
	again, err := repository.Get(context.Background(), input.StorageKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if again.Metadata[0] != 1 || again.Envelope[0] != 4 {
		t.Fatalf("returned bytes alias storage: %+v", again)
	}
}

func TestConsumeAllowsExactlyOneConcurrentReader(t *testing.T) {
	repository := New()
	now := time.Unix(2000, 0).UTC()
	input := createInput(3, 4, now.Add(time.Hour))
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
				t.Errorf("unexpected consume error: %v", err)
			}
		}()
	}
	wait.Wait()
	if successes.Load() != 1 || notFound.Load() != 63 {
		t.Fatalf("successes=%d not_found=%d", successes.Load(), notFound.Load())
	}
}

func TestExpiryBoundaryAndCleanupBatch(t *testing.T) {
	repository := New()
	now := time.Unix(3000, 0).UTC()
	first := createInput(5, 5, now.Add(-time.Minute))
	second := createInput(6, 6, now)
	third := createInput(7, 7, now.Add(time.Minute))
	for _, input := range []store.CreateInput{first, second, third} {
		if _, err := repository.Create(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := repository.Get(context.Background(), second.StorageKey, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expiry boundary error = %v", err)
	}
	deleted, err := repository.DeleteExpired(context.Background(), now, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("first cleanup: deleted=%d err=%v", deleted, err)
	}
	deleted, err = repository.DeleteExpired(context.Background(), now, 10)
	if err != nil || deleted != 1 {
		t.Fatalf("second cleanup: deleted=%d err=%v", deleted, err)
	}
	if _, err := repository.Get(context.Background(), third.StorageKey, now); err != nil {
		t.Fatalf("unexpired record missing: %v", err)
	}
}

func TestUnlimitedRecordNeverExpiresOrGetsCleanedUp(t *testing.T) {
	repository := New()
	input := createInput(10, 10, time.Time{})
	if result, err := repository.Create(context.Background(), input); err != nil || !result.ExpiresAt.IsZero() {
		t.Fatalf("create result=%+v err=%v", result, err)
	}
	farFuture := time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	if _, err := repository.Get(context.Background(), input.StorageKey, farFuture); err != nil {
		t.Fatalf("unlimited record missing: %v", err)
	}
	if deleted, err := repository.DeleteExpired(context.Background(), farFuture, 10); err != nil || deleted != 0 {
		t.Fatalf("cleanup deleted=%d err=%v", deleted, err)
	}
}

func TestCreateReplayAndConflict(t *testing.T) {
	repository := New()
	now := time.Unix(4000, 0).UTC()
	input := createInput(8, 8, now.Add(time.Hour))
	if result, err := repository.Create(context.Background(), input); err != nil || result.Replayed {
		t.Fatalf("initial create: result=%+v err=%v", result, err)
	}
	if result, err := repository.Create(context.Background(), input); err != nil || !result.Replayed {
		t.Fatalf("replay: result=%+v err=%v", result, err)
	}
	collision := input
	collision.RequestHash[0] = 9
	if _, err := repository.Create(context.Background(), collision); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("collision error = %v", err)
	}
}

package cleanup

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"securl.click/securl/internal/store"
	"securl.click/securl/internal/store/memory"
)

func TestWorkerDeletesOnlyExpiredBatch(t *testing.T) {
	repository := memory.New()
	now := time.Unix(5000, 0).UTC()
	for index, expiresAt := range []time.Time{now.Add(-time.Hour), now, now.Add(time.Hour)} {
		var storageKey [32]byte
		storageKey[0] = byte(index + 1)
		var requestHash [32]byte
		requestHash[0] = byte(index + 1)
		_, err := repository.Create(context.Background(), store.CreateInput{
			StorageKey:  storageKey,
			Metadata:    []byte{1},
			Envelope:    []byte{2},
			RequestHash: requestHash,
			ExpiresAt:   expiresAt,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	logger := zerolog.Nop()
	worker := NewWorker(repository, time.Minute, 1, &logger)
	if deleted, err := worker.RunOnce(context.Background(), now); err != nil || deleted != 1 {
		t.Fatalf("first sweep: deleted=%d err=%v", deleted, err)
	}
	if deleted, err := worker.RunOnce(context.Background(), now); err != nil || deleted != 1 {
		t.Fatalf("second sweep: deleted=%d err=%v", deleted, err)
	}

	var liveKey [32]byte
	liveKey[0] = 3
	if _, err := repository.Get(context.Background(), liveKey, now); err != nil {
		t.Fatalf("live record removed: %v", err)
	}
	var expiredKey [32]byte
	expiredKey[0] = 2
	if _, err := repository.Get(context.Background(), expiredKey, now); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired record remained readable: %v", err)
	}
}

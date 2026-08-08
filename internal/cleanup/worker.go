package cleanup

import (
	"context"
	"log/slog"
	"time"

	"securl.click/securl/internal/store"
)

const (
	DefaultInterval = time.Minute
	DefaultBatch    = int32(500)
)

type Worker struct {
	repository store.Repository
	interval   time.Duration
	batch      int32
	logger     *slog.Logger
	now        func() time.Time
}

func NewWorker(
	repository store.Repository,
	interval time.Duration,
	batch int32,
	logger *slog.Logger,
) *Worker {
	if interval <= 0 {
		interval = DefaultInterval
	}
	if batch <= 0 {
		batch = DefaultBatch
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		repository: repository,
		interval:   interval,
		batch:      batch,
		logger:     logger,
		now:        time.Now,
	}
}

func (worker *Worker) RunOnce(ctx context.Context, now time.Time) (int64, error) {
	return worker.repository.DeleteExpired(ctx, now.UTC(), worker.batch)
}

func (worker *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(worker.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := worker.RunOnce(ctx, worker.now())
			if err != nil {
				if ctx.Err() == nil {
					worker.logger.Warn("expired envelope cleanup failed", "error", err)
				}
				continue
			}
			if deleted > 0 {
				worker.logger.Debug("expired envelopes deleted", "count", deleted)
			}
		}
	}
}

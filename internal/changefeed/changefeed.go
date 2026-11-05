package changefeed

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"vsf/internal/bloom"
	"vsf/internal/model"
)

type Source interface {
	Head(ctx context.Context) (xid string, seq int64, err error)
	ChangesSince(ctx context.Context, afterXID string, afterSeq int64, limit int) ([]model.Change, error)
	AllHashes(ctx context.Context, emit func(uint64)) error
	EstimatedCount(ctx context.Context) (int64, error)
	PurgeChanges(ctx context.Context, olderThan time.Duration) (int64, error)
}

const batchSize = 10000

type Feed struct {
	src   Source
	bloom *bloom.Manager
	log   *slog.Logger

	mu  sync.Mutex
	xid string
	seq int64

	epoch    atomic.Value
	lastPoll atomic.Int64
}

func New(src Source, b *bloom.Manager, log *slog.Logger) *Feed {
	f := &Feed{src: src, bloom: b, log: log, xid: "0"}
	f.epoch.Store("0.0")
	return f
}

func (f *Feed) Epoch() string { return f.epoch.Load().(string) }

func (f *Feed) Lag() time.Duration {
	t := f.lastPoll.Load()
	if t == 0 {
		return time.Duration(1<<62 - 1)
	}

	return time.Since(time.Unix(0, t))
}

func (f *Feed) setCursor(xid string, seq int64) {
	f.xid, f.seq = xid, seq
	f.epoch.Store(fmt.Sprintf("%s.%d", xid, seq))
}

func (f *Feed) Init(ctx context.Context, expectedItems uint64) error {
	xid, seq, err := f.src.Head(ctx)
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}

	f.mu.Lock()
	f.setCursor(xid, seq)
	f.mu.Unlock()

	if err := f.Rebuild(ctx, expectedItems); err != nil {
		return err
	}

	f.lastPoll.Store(time.Now().UnixNano())
	return nil
}

func (f *Feed) Rebuild(ctx context.Context, expectedItems uint64) error {
	start := time.Now()
	size := expectedItems

	if est, err := f.src.EstimatedCount(ctx); err == nil && est > 0 {
		if want := uint64(est) * 13 / 10; want > size {
			size = want
		}
	}

	err := f.bloom.Rebuild(ctx, size, func(ctx context.Context, emit func(uint64)) error {
		return f.src.AllHashes(ctx, emit)
	})
	if err != nil {
		return err
	}

	f.log.Info("bloom rebuilt", "items", f.bloom.Items(), "bytes", f.bloom.SizeBytes(), "took", time.Since(start).String())
	return nil
}

func (f *Feed) SyncNow(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for {
		changes, err := f.src.ChangesSince(ctx, f.xid, f.seq, batchSize)
		if err != nil {
			return err
		}

		for _, c := range changes {
			f.bloom.Add(uint64(c.Hash))
		}

		if n := len(changes); n > 0 {
			last := changes[n-1]
			f.setCursor(last.XID, last.Seq)
		}

		f.lastPoll.Store(time.Now().UnixNano())

		if len(changes) < batchSize {
			return nil
		}
	}
}

func (f *Feed) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-t.C:
			if err := f.SyncNow(ctx); err != nil && ctx.Err() == nil {
				f.log.Error("changefeed poll failed", "err", err)
			}
		}
	}
}

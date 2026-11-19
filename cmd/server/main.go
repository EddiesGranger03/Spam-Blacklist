package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"vsf/internal/apikey"
	"vsf/internal/auth"
	"vsf/internal/cache"
	"vsf/internal/changefeed"
	"vsf/internal/checker"
	"vsf/internal/config"
	"vsf/internal/filter"
	"vsf/internal/handler"
	"vsf/internal/inspector"
	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/seal"
	"vsf/internal/snapshot"
	"vsf/internal/store"
	"vsf/internal/verify"
)

// main là điểm vào của server: chạy run và thoát với mã lỗi nếu có lỗi.
func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// run khởi tạo toàn bộ hệ thống (cấu hình, DB, Redis, Bloom, changefeed, HTTP server) và chạy đến khi nhận tín hiệu dừng.
func run(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return serve(ctx, stop, log)
}

// serve chạy server cho tới khi ctx bị hủy (tín hiệu dừng, hoặc test hủy trực tiếp) hoặc có lỗi nghiêm trọng.
func serve(ctx context.Context, stop context.CancelFunc, log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if cfg.AuthDisabled {
		log.Warn("!!! AUTH_DISABLED=true: Check API KHÔNG yêu cầu API key (chỉ dùng khi phát triển trên localhost) !!!")
	}

	st, err := store.New(ctx, cfg.DatabaseURL, cfg.ReadDatabaseURL, cfg.PGMaxConns)
	if err != nil {
		return err
	}

	defer st.Close()

	sl, err := seal.New(cfg.DataKey, cfg.DataPepper, int16(cfg.DataKeyVersion), seal.WithRetiredKeys(cfg.DataKeysRetired)) // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
	if err != nil {
		return err
	}

	// Phải cài khóa trước Migrate: lần khởi động đầu sau khi nâng cấp
	// sẽ chuyển bảng plaintext sang bố cục mã hóa.
	st.SetSealer(sl)
	st.SetAuditKey(store.AuditKeyFrom(cfg.AuditKey, cfg.SessionSecret))
	log.Info("encryption at rest enabled", "key_version", cfg.DataKeyVersion, "versions_readable", sl.Versions())
	// Vân tay khóa (không lộ khóa) để đối chiếu với nơi lưu khóa: mất khóa thì dữ liệu không thể giải mã lại.
	log.Info("data key fingerprints: hãy sao lưu DATA_KEY, DATA_PEPPER và DATA_KEY_V<n> ở nơi tách biệt với bản sao lưu DB",
		"data_key", config.KeyFingerprint(cfg.DataKey), "pepper", config.KeyFingerprint(cfg.DataPepper))

	for _, w := range cfg.Warnings() {
		log.Warn(w)
	}

	// Migrate còn kiểm tra khóa với một mẫu dữ liệu đã lưu và từ chối chạy tiếp nếu khóa không đọc được.
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	if chk := st.LastKeyCheck(); chk.Sampled > 0 {
		log.Info("data keys verified against stored data", "sampled_rows", chk.Sampled, "rows_by_key_version", chk.Versions)

		for v := range chk.Versions {
			if v != int16(cfg.DataKeyVersion) { // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
				log.Warn("some rows are still sealed under an older key: run `rekey` to move them, then the old key can be retired",
					"key_version", v)
			}
		}
	}

	if err := bootstrapAdmin(ctx, st, cfg, log); err != nil {
		return err
	}

	var rdb, subRdb *redis.Client
	var rc cache.Cache = cache.Noop{}

	if cfg.RedisAddr != "" {
		// F9: client đường request có timeout ngắn + circuit breaker; Pub/Sub dùng client riêng (cmd/server/redis.go).
		rdb = newRequestRedis(cfg.RedisAddr, cfg.RedisPassword, redisTuningFromEnv())
		defer rdb.Close()
		subRdb = newPubSubRedis(cfg.RedisAddr, cfg.RedisPassword)
		defer subRdb.Close()
		rc = cache.NewRedis(rdb, cfg.CacheTTL)
	}

	bm := filter.NewManager()
	feed := changefeed.New(st, bm, log)

	if rdb != nil {
		st.SetChangeNotifier(changefeed.NewPublisher(rdb, cfg.SyncChannel, log))
	}
	chk := checker.New(cfg.DefaultRegion, bm, rc, st, feed)
	chk.SetCacheSealer(sl)
	keys := apikey.NewService(st, rdb, cfg.RateLimitRPS)

	metrics.RegisterGauges(
		func() float64 { return float64(bm.Items()) },
		func() float64 { return float64(bm.SizeBytes()) },
		func() float64 { return feed.Lag().Seconds() },
		func() float64 { n, _ := st.PoolStats(); return float64(n) },
		func() float64 { return float64(feed.TailLen()) },
		func() float64 { return feed.StalledFor().Seconds() },
	)

	store.SetScanOptions(store.ScanOptions{Batch: cfg.FilterScanBatch, Pause: cfg.FilterScanPause})
	// Leader giữ một connection riêng cho advisory lock; phải trả nó trước st.Close (defer chạy LIFO),
	// nếu không pool.Close chờ connection đó mãi khi Bootstrap chưa xong.
	leader := st.Leader(store.SnapshotLeaderLockID)
	defer leader.Release()

	syncer := snapshot.NewSyncer(st.Snapshots(), feed, leader, log, snapshot.Config{
		Interval:    cfg.FilterSnapshotInterval,
		PollEvery:   cfg.FilterSnapshotPoll,
		MaxAge:      changeLogRetention - time.Hour, // cursor cũ hơn retention thì change_log sau nó có thể đã bị xóa
		WaitTimeout: cfg.FilterBootstrapTimeout,
		Keep:        cfg.FilterSnapshotKeep,
		Expected:    cfg.BloomExpectedItems,
		RetryBase:   cfg.FilterRetryBase,
		RetryMax:    cfg.FilterRetryMax,
		// F10: dựng snapshot sớm khi delta/removed phình
		DeltaRebuildRatio: cfg.FilterDeltaRebuildRatio, RemovedRebuildMax: cfg.FilterRemovedRebuildMax, MinRebuildGap: cfg.FilterMinRebuildGap,
	})

	st2 := syncer
	metrics.RegisterFuncs([]metrics.FuncMetric{
		{Name: "vsf_filter_leader", Help: "1 if this pod holds the snapshot leader lock.", F: func() float64 { return b2f(st2.Status().Leader) }},
		{Name: "vsf_filter_snapshot_age_seconds", Help: "Age of the snapshot the served filter was built from (0 = unknown).", F: func() float64 {
			if t := st2.Status().SnapshotAt; !t.IsZero() {
				return time.Since(t).Seconds()
			}

			return 0
		}},
		{Name: "vsf_filter_snapshot_id", Help: "Id of the snapshot the served filter was built from (0 = none).", F: func() float64 { return float64(st2.Status().SnapshotID) }},
		{Name: "vsf_filter_snapshot_consecutive_failures", Help: "Snapshot build/save failures since the last success (drives the backoff).", F: func() float64 { return float64(st2.Status().Consecutive) }},
		{Name: "vsf_filter_snapshot_pending_save", Help: "1 while a built filter is held in RAM waiting for Save to succeed.", F: func() float64 { return b2f(st2.Status().PendingSave) }},
		{Name: "vsf_filter_snapshot_build_failures_total", Help: "Table scan/build errors on this pod.", Counter: true, F: func() float64 { return float64(st2.Status().BuildFailures) }},
		{Name: "vsf_filter_snapshot_save_failures_total", Help: "Snapshot save errors on this pod.", Counter: true, F: func() float64 { return float64(st2.Status().SaveFailures) }},
		{Name: "vsf_filter_snapshot_fallbacks_total", Help: "Times an older snapshot was used because newer ones were unusable.", Counter: true, F: func() float64 { return float64(st2.Status().Fallbacks) }},
		{Name: "vsf_filter_snapshot_corrupt_flagged_total", Help: "Snapshots this pod flagged corrupt.", Counter: true, F: func() float64 { return float64(st2.Status().CorruptMarked) }},
		{Name: "vsf_filter_rebuild_requests_total", Help: "Rebuild requests recorded by this pod (no usable snapshot).", Counter: true, F: func() float64 { return float64(st2.Status().RebuildRequests) }},
		{Name: "vsf_filter_delta_fill_ratio", Help: "Delta layer items / its design capacity; the leader rebuilds early past FILTER_DELTA_REBUILD_RATIO.", F: func() float64 { r, _ := bm.DeltaPressure(); return r }},
		{Name: "vsf_filter_removed_items", Help: "Hashes in the exact removed-set layer (removed after the snapshot cursor).", F: func() float64 { _, n := bm.DeltaPressure(); return float64(n) }},
		{Name: "vsf_filter_pressure_rebuilds_total", Help: "Early snapshot builds because the delta/removed layer was too full.", Counter: true, F: func() float64 { return float64(st2.Status().PressureBuilds) }},
	})

	ver := verify.New(bm, feed, st, verify.Config{
		Interval: cfg.FilterVerifyInterval,
		Sample:   cfg.FilterVerifySample,
		Heal: func(h uint64) {
			if l := bm.Current(); l != nil {
				l.Add(h) // vá ngay hash thiếu (chỉ có thể gây dương tính giả, vô hại)
			}
		},
		// Filter pod này đã lệch khỏi DB: yêu cầu leader dựng lại snapshot từ bảng; các pod nạp snapshot mới sẽ sạch.
		OnFalseNegative: func(c context.Context, _ int) {
			if _, err := st.Snapshots().RequestRebuild(c); err != nil {
				log.Error("filter verify: request rebuild failed", "err", err)
			}
		},
	}, log)

	ins := inspector.New(200)
	h, err := handler.New(handler.Deps{Cfg: cfg, Log: log, Store: st, Checker: chk, Feed: feed, Bloom: bm, Snapshots: syncer, Verify: ver, APIKeys: keys, Inspector: ins})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           h.Router(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second, // chống slowloris; route upload/export tự nới bằng ResponseController
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr, "env", cfg.AppEnv)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	go func() {
		// Khởi động từ snapshot: nạp snapshot mới nhất -> replay change_log sau cursor -> ready.
		// Không có snapshot hợp lệ thì chỉ leader (pg_try_advisory_lock) quét bảng; pod khác chờ (vẫn không ready).
		if err := syncer.Bootstrap(ctx); err != nil {
			if ctx.Err() == nil {
				log.Error("filter bootstrap failed", "err", err)
				errCh <- err
			}

			return
		}

		log.Info("ready")
		go supervise(ctx, log, "changefeed", loopRestartDelay, func(c context.Context) {
			feed.RunSync(c, cfg.SafetyPollInterval, cfg.PollInterval)
		})

		if rdb != nil {
			// Nhận tín hiệu thay đổi từ pod khác; mất Redis thì feed tự về poll nhanh (PollInterval).
			go supervise(ctx, log, "changefeed-subscribe", loopRestartDelay, func(c context.Context) {
				feed.Subscribe(c, subRdb, cfg.SyncChannel)
			})
		} else {
			metrics.SyncFallback.Inc()
			log.Warn("REDIS_ADDR not set: changefeed polls change_log every POLL_INTERVAL (no pub/sub)",
				"interval", cfg.PollInterval.String())
		}
		go supervise(ctx, log, "filter-snapshot", loopRestartDelay, syncer.Run)
		go supervise(ctx, log, "filter-verify", loopRestartDelay, func(c context.Context) { ver.Run(c) })
		go supervise(ctx, log, "background-jobs", loopRestartDelay, func(c context.Context) {
			backgroundJobs(c, log, st, feed, keys, cfg)
		})
	}()

	select {
	case <-ctx.Done():
		log.Info("shutting down")

	case err := <-errCh:
		stop()
		return err
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = keys.FlushLastUsed(shutCtx)
	return srv.Shutdown(shutCtx)
}

// Chu kỳ của các vòng nền. Là biến (không phải hằng) để test rút ngắn được.
var (
	flushEvery = time.Minute // ghi lượt dùng API key xuống DB
	purgeEvery = time.Hour   // dọn change_log và phiên hết hạn
)

// changeLogRetention là thời gian giữ change_log. Snapshot filter cũ hơn mức này (trừ biên an toàn) bị từ chối.
const changeLogRetention = 24 * time.Hour

// backgroundJobs chạy các vòng nền (flush lượt dùng API key, dọn phiên và changelog; filter làm mới qua snapshot.Syncer, không rebuild mỗi pod), mỗi vòng được giám sát và khởi động lại khi panic.
func backgroundJobs(ctx context.Context, log *slog.Logger, st *store.Store, feed *changefeed.Feed,
	keys *apikey.Service, cfg config.Config) {

	minute := time.NewTicker(flushEvery)
	defer minute.Stop()
	hourly := time.NewTicker(purgeEvery)
	defer hourly.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-minute.C:
			if err := keys.FlushLastUsed(ctx); err != nil {
				log.Error("flush api key usage", "err", err)
			}

		case <-hourly.C:
			if _, err := st.PurgeChanges(ctx, changeLogRetention); err != nil {
				log.Error("purge change_log", "err", err)
			}

			if _, err := st.PurgeSessions(ctx, 30*time.Minute); err != nil {
				log.Error("purge sessions", "err", err)
			}
		}
	}
}

// bootstrapAdmin tạo tài khoản admin đầu tiên từ BOOTSTRAP_ADMIN_* khi bảng admin còn trống.
func bootstrapAdmin(ctx context.Context, st *store.Store, cfg config.Config, log *slog.Logger) error {
	n, err := st.CountAdmins(ctx)
	if err != nil || n > 0 {
		return err
	}

	if cfg.BootstrapEmail == "" || cfg.BootstrapPass == "" {
		log.Warn("chưa có tài khoản nào. Đặt BOOTSTRAP_ADMIN_EMAIL và BOOTSTRAP_ADMIN_PASSWORD rồi khởi động lại để tạo admin đầu tiên")
		return nil
	}

	if len(cfg.BootstrapPass) < auth.MinPasswordLen {
		return errors.New("BOOTSTRAP_ADMIN_PASSWORD quá ngắn (tối thiểu 10 ký tự)")
	}

	hash, err := auth.HashPassword(cfg.BootstrapPass)
	if err != nil {
		return err
	}

	if _, err := st.CreateAdmin(ctx, cfg.BootstrapEmail, hash, model.RoleAdmin, model.Actor{Email: "bootstrap"}); err != nil {
		// Nhiều pod khởi động cùng lúc trên DB rỗng: CountAdmins ở trên không nguyên tử với INSERT. Pod thua cuộc nhận
		// unique violation trên email, nghĩa là pod khác đã tạo đúng admin này: coi là thành công (F7).
		if errors.Is(err, store.ErrDuplicate) {
			log.Info("admin đầu tiên đã được pod khác tạo", "email", cfg.BootstrapEmail)
			return nil
		}

		return err
	}

	log.Info("đã tạo admin đầu tiên", "email", cfg.BootstrapEmail)
	return nil
}

func b2f(b bool) float64 {
	if b {
		return 1
	}

	return 0
}

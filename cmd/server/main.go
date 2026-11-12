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
	"vsf/internal/bloom"
	"vsf/internal/cache"
	"vsf/internal/changefeed"
	"vsf/internal/checker"
	"vsf/internal/config"
	"vsf/internal/handler"
	"vsf/internal/inspector"
	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/seal"
	"vsf/internal/store"
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

	sl, err := seal.New(cfg.DataKey, cfg.DataPepper, int16(cfg.DataKeyVersion), seal.WithRetiredKeys(cfg.DataKeysRetired))  // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
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
			if v != int16(cfg.DataKeyVersion) {  // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
				log.Warn("some rows are still sealed under an older key: run `rekey` to move them, then the old key can be retired",
					"key_version", v)
			}
		}
	}

	if err := bootstrapAdmin(ctx, st, cfg, log); err != nil {
		return err
	}

	var rdb *redis.Client
	var rc cache.Cache = cache.Noop{}

	if cfg.RedisAddr != "" {
		rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPassword})
		defer rdb.Close()
		rc = cache.NewRedis(rdb, cfg.CacheTTL)
	}

	bm := bloom.NewManager()
	feed := changefeed.New(st, bm, log)
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

	ins := inspector.New(200)
	h, err := handler.New(handler.Deps{Cfg: cfg, Log: log, Store: st, Checker: chk, Feed: feed, Bloom: bm, APIKeys: keys, Inspector: ins})
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
		if err := feed.Init(ctx, cfg.BloomExpectedItems); err != nil {
			if ctx.Err() == nil {
				log.Error("bloom init failed", "err", err)
				errCh <- err
			}

			return
		}

		log.Info("ready")
		go supervise(ctx, log, "changefeed", loopRestartDelay, func(c context.Context) { feed.Run(c, cfg.PollInterval) })
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

// backgroundJobs chạy các vòng nền (changefeed, dựng lại Bloom, dọn phiên và changelog), mỗi vòng được giám sát và khởi động lại khi panic.
func backgroundJobs(ctx context.Context, log *slog.Logger, st *store.Store, feed *changefeed.Feed,
	keys *apikey.Service, cfg config.Config) {

	minute := time.NewTicker(flushEvery)
	defer minute.Stop()
	hourly := time.NewTicker(purgeEvery)
	defer hourly.Stop()
	rebuild := time.NewTicker(cfg.BloomRebuildInterval)
	defer rebuild.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-minute.C:
			if err := keys.FlushLastUsed(ctx); err != nil {
				log.Error("flush api key usage", "err", err)
			}

		case <-hourly.C:
			if _, err := st.PurgeChanges(ctx, 24*time.Hour); err != nil {
				log.Error("purge change_log", "err", err)
			}

			if _, err := st.PurgeSessions(ctx, 30*time.Minute); err != nil {
				log.Error("purge sessions", "err", err)
			}

		case <-rebuild.C:
			if err := feed.Rebuild(ctx, cfg.BloomExpectedItems); err != nil {
				log.Error("bloom rebuild", "err", err)
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
		return err
	}

	log.Info("đã tạo admin đầu tiên", "email", cfg.BootstrapEmail)
	return nil
}

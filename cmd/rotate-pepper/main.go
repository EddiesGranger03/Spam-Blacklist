// Lệnh rotate-pepper chuyển mọi dòng blacklist từ một DATA_PEPPER cũ sang một pepper mới (chỉ mục blind và value_hash).
// Xem README, "Xoay DATA_PEPPER".
//
// ĐÂY LÀ THAO TÁC OFFLINE. Dừng mọi instance server trước, chạy lệnh, rồi khởi động server với DATA_PEPPER MỚI.
// Server vẫn chạy với pepper cũ sẽ không tìm được các dòng đã chuyển và sẽ báo các giá trị đang bị chặn là an toàn.
//
// Môi trường: giống server (DATABASE_URL, DATA_KEY, DATA_KEY_VERSION, DATA_KEY_V<n>, SESSION_SECRET /
// AUDIT_HMAC_KEY), với DATA_PEPPER = pepper MỚI và DATA_PEPPER_OLD = pepper mà dữ liệu đang được lưu dưới đó.
//
//	rotate-pepper -dry-run                          giải mã và kiểm tra mọi dòng, không ghi gì
//	rotate-pepper -servers-stopped                  chuyển đổi (chạy tiếp được: chạy lại nếu bị gián đoạn)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"vsf/internal/config"
	"vsf/internal/model"
	"vsf/internal/seal"
	"vsf/internal/store"
)

// main là điểm vào của công cụ rotate-pepper: chạy run và thoát với mã lỗi nếu có lỗi.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rotate-pepper:", err)
		os.Exit(1)
	}
}

// run đọc cấu hình cả pepper cũ và mới, rồi chuyển các dòng (hoặc chỉ kiểm tra khi -dry-run).
func run(args []string) error {
	fs := flag.NewFlagSet("rotate-pepper", flag.ContinueOnError)

	dryRun := fs.Bool("dry-run", false, "decrypt and check every row, write nothing")
	stopped := fs.Bool("servers-stopped", false, "confirm that EVERY server instance is stopped (required for a real run)")
	batch := fs.Int("batch", 5000, "rows per statement")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if !*dryRun && !*stopped {
		return errors.New("refusing to run: stop every server instance and pass -servers-stopped " +
			"(a running server cannot find rotated rows). Use -dry-run to only check")
	}

	oldPepper := os.Getenv("DATA_PEPPER_OLD")
	if oldPepper == "" {
		return errors.New("DATA_PEPPER_OLD is required: set it to the pepper the data is stored under now, " +
			"and DATA_PEPPER to the new one")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if oldPepper == cfg.DataPepper {
		return errors.New("DATA_PEPPER_OLD and DATA_PEPPER are the same: nothing to rotate")
	}

	retired := cfg.DataKeysRetired

	newSealer, err := seal.New(cfg.DataKey, cfg.DataPepper, int16(cfg.DataKeyVersion), seal.WithRetiredKeys(retired))  // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
	if err != nil {
		return err
	}

	oldSealer, err := seal.New(cfg.DataKey, oldPepper, int16(cfg.DataKeyVersion), seal.WithRetiredKeys(retired))  // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
	if err != nil {
		return fmt.Errorf("DATA_PEPPER_OLD: %w", err)
	}

	st, err := store.New(ctx, cfg.DatabaseURL, "", 4)
	if err != nil {
		return err
	}

	defer st.Close()

	st.SetSealer(newSealer)
	st.SetAuditKey(store.AuditKeyFrom(cfg.AuditKey, cfg.SessionSecret))

	start := time.Now()

	res, err := st.RotatePepper(ctx, model.Actor{Email: "rotate-pepper"}, store.PepperRotateOptions{
		OldBlind: oldSealer.Blind,
		Batch:    *batch,
		DryRun:   *dryRun,
		Progress: func(r store.PepperRotateResult) {
			if r.Batches%20 == 0 {
				fmt.Printf("  ... %d rows read, %d rotated, %d already new (%s)\n", r.Scanned, r.Rewritten, r.AlreadyNew,
					time.Since(start).Round(time.Second))
			}
		},
	})

	verb := "rotated"
	if *dryRun {
		verb = "would be rotated (dry run: nothing was written)"
	}

	fmt.Printf("%d rows read, %d %s, %d already under the new pepper, %d skipped because they were edited meanwhile, %s\n",
		res.Scanned, res.Rewritten, verb, res.AlreadyNew, res.Skipped, time.Since(start).Round(time.Millisecond))

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("interrupted: what was already rotated stays; run it again to continue")
		}

		return err
	}

	if !*dryRun {
		fmt.Println("done. Start the servers with the NEW DATA_PEPPER (this rebuilds the Bloom filter), and keep the old")
		fmt.Println("pepper only for restoring backups made before the rotation: they are stored under it.")
	}

	return nil
}

// Lệnh rekey mã hóa lại các dòng blacklist vẫn đang được mã hóa bằng một khóa dữ liệu cũ, để có thể gỡ khóa đó sau khi DATA_KEY đã được xoay.
// Xem README, "Xoay khóa mã hóa".
//
// Chạy nó với CÙNG môi trường như server (DATABASE_URL, DATA_KEY, DATA_KEY_VERSION, DATA_PEPPER, các biến DATA_KEY_V<n> của khóa cũ,
// SESSION_SECRET / AUDIT_HMAC_KEY). An toàn khi chạy lúc server đang chạy, và có thể chạy lại sau khi bị gián đoạn.
//
//	rekey -status     đếm số dòng theo từng phiên bản khóa (quét toàn bảng) và cho biết mọi phiên bản có đọc được không
//	rekey -dry-run    đọc và giải mã mọi dòng sẽ bị ghi lại, không ghi gì
//	rekey             mã hóa lại mọi dòng không còn ở khóa hiện tại
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"vsf/internal/config"
	"vsf/internal/model"
	"vsf/internal/seal"
	"vsf/internal/store"
)

// main là điểm vào của công cụ rekey: chạy run và thoát với mã lỗi nếu có lỗi.
func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "rekey:", err)
		os.Exit(1)
	}
}

// run đọc cấu hình, nối database và thực hiện theo cờ đã chọn (-status, -dry-run hoặc chạy thật).
func run(args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runContext(ctx, args)
}

// runContext là phần thân của run với context do người gọi cấp: Ctrl+C (hoặc test) hủy context này để dừng giữa chừng.
func runContext(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("rekey", flag.ContinueOnError)

	status := fs.Bool("status", false, "only report how many rows are sealed under each key version")
	dryRun := fs.Bool("dry-run", false, "decrypt everything that would be rewritten but write nothing")
	batch := fs.Int("batch", 5000, "rows per statement")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	sl, err := seal.New(cfg.DataKey, cfg.DataPepper, int16(cfg.DataKeyVersion), seal.WithRetiredKeys(cfg.DataKeysRetired))  // #nosec G115 -- DATA_KEY_VERSION đã được config.validate giới hạn 1..32767
	if err != nil {
		return err
	}

	st, err := store.New(ctx, cfg.DatabaseURL, "", 4)
	if err != nil {
		return err
	}

	defer st.Close()

	st.SetSealer(sl)
	st.SetAuditKey(store.AuditKeyFrom(cfg.AuditKey, cfg.SessionSecret))

	fmt.Printf("current key version: %d   readable key versions: %v\n", sl.Version(), sl.Versions())

	if *status {
		return printStatus(ctx, st, sl)
	}

	// Cùng kiểm tra mà server làm lúc khởi động: khóa hoặc pepper sai phải dừng ở đây, trước mọi lần ghi.
	chk, err := st.VerifyKeys(ctx)
	if err != nil {
		return fmt.Errorf("the configured keys cannot read the stored data:\n%w", err)
	}

	fmt.Printf("keys verified against %d sampled rows\n", chk.Sampled)

	start := time.Now()

	res, err := st.Rekey(ctx, model.Actor{Email: "rekey"}, store.RekeyOptions{
		Batch:  *batch,
		DryRun: *dryRun,
		Progress: func(r store.RekeyResult) {
			if r.Batches%20 == 0 {
				fmt.Printf("  ... %d rows read, %d rewritten, %d skipped (%s)\n", r.Scanned, r.Rewritten, r.Skipped,
					time.Since(start).Round(time.Second))
			}
		},
	})

	verb := "rewritten"
	if *dryRun {
		verb = "would be rewritten (dry run: nothing was written)"
	}

	fmt.Printf("%d rows read, %d %s, %d skipped because they were edited meanwhile, %d batches, %s\n",
		res.Scanned, res.Rewritten, verb, res.Skipped, res.Batches, time.Since(start).Round(time.Millisecond))

	if len(res.From) > 0 {
		fmt.Printf("rows found per old key version: %v\n", res.From)
	}

	if err != nil {
		if errors.Is(err, context.Canceled) {
			return errors.New("interrupted: what was already rewritten stays; run it again to continue")
		}

		return err
	}

	if !*dryRun {
		fmt.Println("done. Check with `rekey -status`: once no row is left on an old version, that key can be retired.")
		fmt.Println("Keep the old key as long as you may need to restore a backup made before the rotation: it is still sealed under it.")
	}

	return nil
}

// printStatus in số dòng theo từng phiên bản khóa và cho biết các phiên bản có đọc được không.
func printStatus(ctx context.Context, st *store.Store, sl *seal.Sealer) error {
	counts, err := st.KeyVersionCounts(ctx)
	if err != nil {
		return err
	}

	versions := make([]int16, 0, len(counts))
	for v := range counts {
		versions = append(versions, v)
	}

	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	unreadable := false

	for _, v := range versions {
		note := ""
		switch {
		case v == sl.Version():
			note = "  (current key)"
		case !sl.HasVersion(v):
			note = fmt.Sprintf("  UNREADABLE: set DATA_KEY_V%d", v)
			unreadable = true
		default:
			note = "  (old key: run rekey to move these rows)"
		}

		fmt.Printf("key version %d: %d rows%s\n", v, counts[v], note)
	}

	if len(versions) == 0 {
		fmt.Println("the table is empty")
	}

	if unreadable {
		return errors.New("some rows are sealed under a key version that is not configured")
	}

	return nil
}

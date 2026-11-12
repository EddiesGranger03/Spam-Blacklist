package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
	"vsf/internal/store"
)

// seedManyOldKey tạo n entry phone dưới khóa cũ (phiên bản 1).
func seedManyOldKey(t *testing.T, dsn string, n int) {
	t.Helper()

	ctx := context.Background()

	sl, err := seal.New(testKeyOld, testPepper, 1)
	if err != nil {
		t.Fatal(err)
	}

	st, err := store.New(ctx, dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	defer st.Close()

	st.SetSealer(sl)

	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < n; i++ {
		key, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, fmt.Sprintf("09010%05d", i), "VN")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := st.CreateEntry(ctx, key, model.EntryInput{Category: "scam", RiskScore: 50, Source: "s", Note: "n"}, model.Actor{Email: "seed"}); err != nil {
			t.Fatal(err)
		}
	}
}

// stdoutPipe chuyển stdout vào một pipe và gom mọi thứ được in ra; trả hàm lấy nội dung hiện có và hàm khôi phục.
func stdoutPipe(t *testing.T) (snapshot func() string, restore func()) {
	t.Helper()

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}

	os.Stdout = w

	var (
		mu  sync.Mutex
		buf strings.Builder
	)

	done := make(chan struct{})

	go func() {
		b := make([]byte, 4096)

		for {
			n, err := r.Read(b)
			mu.Lock()
			buf.Write(b[:n])
			mu.Unlock()

			if err != nil {
				close(done)
				return
			}
		}
	}()

	return func() string { mu.Lock(); defer mu.Unlock(); return buf.String() },
		func() { _ = w.Close(); <-done; os.Stdout = old; _ = r.Close() }
}

// Tiến độ được in sau mỗi 20 lô (trước đây nhánh này chưa từng chạy trong test).
func TestRekeyPrintsProgressEveryTwentyBatches(t *testing.T) {
	dsn := tempDB(t)
	seedManyOldKey(t, dsn, 45)
	setRekeyEnv(t, dsn, true)

	snap, restore := stdoutPipe(t)
	err := run([]string{"-batch", "1"}) // 45 dòng, mỗi lô 1 dòng: 45 lô, tiến độ ở lô 20 và 40
	restore()

	out := snap()
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}

	if got := strings.Count(out, "  ... "); got != 2 {
		t.Fatalf("want 2 progress lines (batches 20 and 40), got %d:\n%s", got, out)
	}

	if !strings.Contains(out, "45 rewritten") {
		t.Fatalf("all rows must be rewritten:\n%s", out)
	}
}

// Ctrl+C giữa chừng: lệnh dừng với thông báo rõ ràng, những gì đã mã hóa lại được giữ, chạy lại thì làm nốt phần còn lại.
func TestRekeyCanBeInterruptedAndResumed(t *testing.T) {
	dsn := tempDB(t)
	const rows = 300

	seedManyOldKey(t, dsn, rows)
	setRekeyEnv(t, dsn, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	snap, restore := stdoutPipe(t)
	errc := make(chan error, 1)

	go func() { errc <- runContext(ctx, []string{"-batch", "1"}) }()

	// Chờ tới khi lệnh đã qua bước kiểm tra khóa (đang mã hóa lại) rồi mới "bấm Ctrl+C".
	deadline := time.Now().Add(30 * time.Second)
	for !strings.Contains(snap(), "keys verified") {
		if time.Now().After(deadline) {
			cancel()
			restore()
			t.Fatal("rekey never reached the re-encryption step")
		}

		time.Sleep(5 * time.Millisecond)
	}

	time.Sleep(60 * time.Millisecond)
	cancel()

	err := <-errc
	restore()

	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("an interrupted run must say so: %v", err)
	}

	done := countVersion(t, dsn, 2)
	left := countVersion(t, dsn, 1)

	if done+left != rows {
		t.Fatalf("no row may be lost or duplicated: v2=%d v1=%d", done, left)
	}

	if left == 0 {
		t.Skip("máy quá nhanh: lệnh đã chạy xong trước khi bị ngắt, không kiểm tra được đường ngắt")
	}

	// chạy lại: làm nốt phần còn lại
	_, restore2 := stdoutPipe(t)
	err = run([]string{"-batch", "50"})

	restore2()

	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	if v1, v2 := countVersion(t, dsn, 1), countVersion(t, dsn, 2); v1 != 0 || v2 != rows {
		t.Fatalf("after resuming every row must be on the current key: v1=%d v2=%d", v1, v2)
	}

}

package pgfault

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func dsn(t *testing.T) string {
	t.Helper()

	d := os.Getenv("TEST_DATABASE_URL")
	if d == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	return d
}

func connect(t *testing.T, p *Proxy, base string) *pgx.Conn {
	t.Helper()

	c, err := pgx.Connect(context.Background(), p.DSN(t, base))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = c.Close(context.Background()) })

	return c
}

// Proxy đang rảnh thì trong suốt: truy vấn chạy bình thường.
func TestProxyIsTransparentUntilToldToFail(t *testing.T) {
	base := dsn(t)
	p := Start(t, TargetOf(t, base))
	c := connect(t, p, base)
	ctx := context.Background()

	var n int
	if err := c.QueryRow(ctx, `SELECT 41 + 1`).Scan(&n); err != nil || n != 42 {
		t.Fatalf("%d %v", n, err)
	}

	if p.Cuts() != 0 {
		t.Fatal("an idle proxy must not cut anything")
	}
}

// FailAtRoundTrip(n): n-1 câu lệnh chạy được, câu thứ n gặp lỗi mạng; Heal rồi kết nối lại thì dùng được.
func TestFailAtRoundTripCutsExactlyThere(t *testing.T) {
	base := dsn(t)
	p := Start(t, TargetOf(t, base))
	ctx := context.Background()

	// Giao thức đơn giản: mỗi câu lệnh đúng một vòng. (Giao thức mở rộng lần đầu dùng một câu lệnh còn tốn thêm một vòng để
	// chuẩn bị câu lệnh; các test quét của dự án không phụ thuộc điều đó vì chúng quét mọi n.)
	cfg, err := pgx.ParseConfig(p.DSN(t, base))
	if err != nil {
		t.Fatal(err)
	}

	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = c.Close(context.Background()) })

	p.FailAtRoundTrip(3)

	for i := 1; i <= 2; i++ {
		var n int
		if err := c.QueryRow(ctx, `SELECT $1::int`, i).Scan(&n); err != nil || n != i {
			t.Fatalf("statement %d must still run: %d %v", i, n, err)
		}
	}

	var n int
	if err := c.QueryRow(ctx, `SELECT 3`).Scan(&n); err == nil {
		t.Fatal("the 3rd statement must fail with a network error")
	}

	if p.Cuts() != 1 {
		t.Fatalf("cuts = %d", p.Cuts())
	}

	p.Heal()

	c2 := connect(t, p, base)
	if err := c2.QueryRow(ctx, `SELECT 1`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("a new connection after Heal must work: %v", err)
	}
}

// Giao dịch đang mở khi mất kết nối thì bị server hủy: phần đã chạy KHÔNG được lưu.
func TestCutInsideATransactionRollsItBack(t *testing.T) {
	base := dsn(t)
	p := Start(t, TargetOf(t, base))
	direct, err := pgx.Connect(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}

	defer direct.Close(context.Background())

	ctx := context.Background()

	if _, err := direct.Exec(ctx, `CREATE TEMP TABLE IF NOT EXISTS x (a int)`); err != nil {
		t.Skip("cần quyền tạo bảng tạm")
	}

	// bảng thật (không tạm) để hai kết nối cùng thấy
	name := "pgfault_probe_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	if _, err := direct.Exec(ctx, `CREATE TABLE `+name+` (a int)`); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _, _ = direct.Exec(context.Background(), `DROP TABLE IF EXISTS `+name) })

	c := connect(t, p, base)

	tx, err := c.Begin(ctx) // vòng 1: BEGIN
	if err != nil {
		t.Fatal(err)
	}

	p.FailAtRoundTrip(3) // vòng 1 INSERT, vòng 2 INSERT thứ hai: đứt TRƯỚC vòng 3 (COMMIT)

	for i := 0; i < 2; i++ {
		if _, err := tx.Exec(ctx, `INSERT INTO `+name+` VALUES (1)`); err != nil {
			t.Fatal(err)
		}
	}

	if err := tx.Commit(ctx); err == nil {
		t.Fatal("the commit must fail when the connection is cut before it")
	}

	var n int
	if err := direct.QueryRow(ctx, `SELECT count(*) FROM `+name).Scan(&n); err != nil || n != 0 {
		t.Fatalf("an uncommitted transaction must leave nothing behind: %d %v", n, err)
	}
}

// Mất kết nối GIỮA LÚC nhận một kết quả lớn: phía client nhận lỗi, không treo.
func TestFailAfterServerBytesCutsAStreamingResult(t *testing.T) {
	base := dsn(t)
	p := Start(t, TargetOf(t, base))
	c := connect(t, p, base)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)

	defer cancel()

	p.FailAfterServerBytes(20_000)

	rows, err := c.Query(ctx, `SELECT g, repeat('x', 100) FROM generate_series(1, 100000) g`)
	if err != nil {
		t.Fatal(err)
	}

	read := 0

	for rows.Next() {
		read++
	}

	rows.Close()

	if rows.Err() == nil || read == 0 || read >= 100000 {
		t.Fatalf("the stream must be cut part-way with an error: read=%d err=%v", read, rows.Err())
	}
}

// Đứt SAU khi server nhận COMMIT: client báo lỗi nhưng dữ liệu đã được lưu (tình huống "mất phản hồi của commit").
func TestFailAfterRoundTripLosesTheCommitAcknowledgement(t *testing.T) {
	base := dsn(t)
	p := Start(t, TargetOf(t, base))

	direct, err := pgx.Connect(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}

	defer direct.Close(context.Background())

	ctx := context.Background()
	name := "pgfault_ack_" + strconv.FormatInt(time.Now().UnixNano(), 10)

	if _, err := direct.Exec(ctx, `CREATE TABLE `+name+` (a int)`); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _, _ = direct.Exec(context.Background(), `DROP TABLE IF EXISTS `+name) })

	c := connect(t, p, base)

	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO `+name+` VALUES (1)`); err != nil {
		t.Fatal(err)
	}

	p.FailAfterRoundTrip(1) // vòng kế tiếp là COMMIT

	if err := tx.Commit(ctx); err == nil {
		t.Fatal("the client must not receive the commit acknowledgement")
	}

	// server xử lý COMMIT bất đồng bộ với phía client: chờ ngắn cho tới khi thấy dữ liệu
	deadline := time.Now().Add(3 * time.Second)

	var n int

	for {
		if err := direct.QueryRow(ctx, `SELECT count(*) FROM `+name).Scan(&n); err != nil {
			t.Fatal(err)
		}

		if n == 1 || time.Now().After(deadline) {
			break
		}

		time.Sleep(20 * time.Millisecond)
	}

	if n != 1 {
		t.Fatalf("the server received COMMIT, so the row must be stored even though the client saw an error: %d", n)
	}
}


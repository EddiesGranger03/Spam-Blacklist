package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/seal"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
)

type Store struct {
	write *pgxpool.Pool
	read  *pgxpool.Pool

	auditKey []byte
	sealer   *seal.Sealer
	keyCheck KeyCheck
}

// New mở kết nối tới primary (và replica nếu có), trả về Store đã sẵn sàng.
func New(ctx context.Context, writeDSN, readDSN string, maxConns int) (*Store, error) {
	w, err := openPool(ctx, writeDSN, maxConns)
	if err != nil {
		return nil, fmt.Errorf("open primary: %w", err)
	}

	s := &Store{write: w, read: w}

	if readDSN != "" {
		r, err := openPool(ctx, readDSN, maxConns)
		if err != nil {
			w.Close()
			return nil, fmt.Errorf("open replica: %w", err)
		}

		s.read = r
	}

	return s, nil
}

// openPool mở một pool kết nối pgx với số kết nối tối đa đã cho.
func openPool(ctx context.Context, dsn string, maxConns int) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	if maxConns > 1000 {
		return nil, fmt.Errorf("số kết nối tối đa %d vượt quá giới hạn 1000", maxConns)
	}

	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)  // #nosec G115 -- maxConns đã được giới hạn 1..1000 ở trên
	}

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}

	return pool, nil
}

// Close đóng các pool kết nối của Store.
func (s *Store) Close() {
	if s.read != s.write {
		s.read.Close()
	}

	s.write.Close()
}

// Ping kiểm tra kết nối tới database còn sống hay không.
func (s *Store) Ping(ctx context.Context) error { return s.read.Ping(ctx) }

// PoolStats trả về số kết nối đang dùng và tổng số kết nối của pool ghi.
func (s *Store) PoolStats() (inUse, total int32) {
	st := s.write.Stat()
	return st.AcquiredConns(), st.TotalConns()
}

// Migrate chạy các bước khởi động theo thứ tự: chuyển bảng sang dạng mã hóa, kiểm tra khóa, rồi chuẩn hóa URL.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.write.Acquire(ctx)
	if err != nil {
		return err
	}

	defer conn.Release()

	const lockID = 727274
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", lockID); err != nil {
		return err
	}

	defer conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", lockID)

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}

	files, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}

	names := make([]string, 0, len(files))

	for _, f := range files {
		names = append(names, f.Name())
	}

	sort.Strings(names)

	for _, name := range names {
		var done bool
		if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)", name).Scan(&done); err != nil {
			return err
		}

		if done {
			continue
		}

		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return err
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", name, err)
		}

		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES ($1)", name); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}

		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}

	if err := s.convertToSealed(ctx); err != nil {
		return err
	}

	// Kiểm tra các khóa đã cấu hình với dữ liệu đã lưu TRƯỚC mọi bước đọc giá trị mã hóa, để khóa sai hoặc thiếu
	// hiện một thông báo rõ ràng, thay vì "decryption failed" giữa chừng migration.
	// (Không có sealer thì không có gì để kiểm tra; các bước bên dưới cũng không làm gì.)
	if s.sealer != nil {
		chk, err := s.VerifyKeys(ctx)
		if err != nil {
			return fmt.Errorf("the configured data keys cannot read the stored data; fix the configuration, nothing was changed: %w", err)
		}

		s.keyCheck = chk
	}

	// Chạy sau khi bố cục mã hóa đã tồn tại, vì bước này cần đọc các giá trị đã mã hóa.
	return s.runURLPathMigration(ctx)
}

// LastKeyCheck là kết quả kiểm tra khóa mà Migrate tìm được (zero nếu chưa chạy).
func (s *Store) LastKeyCheck() KeyCheck { return s.keyCheck }

// isUniqueViolation cho biết lỗi có phải là vi phạm ràng buộc unique (SQLSTATE 23505) hay không.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// mapNotFound đổi lỗi không có dòng của pgx thành ErrNotFound của gói.
func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	return err
}

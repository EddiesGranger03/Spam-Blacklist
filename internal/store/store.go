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
}

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

func openPool(ctx context.Context, dsn string, maxConns int) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}

	if maxConns > 0 {
		cfg.MaxConns = int32(maxConns)
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

func (s *Store) Close() {
	if s.read != s.write {
		s.read.Close()
	}

	s.write.Close()
}

func (s *Store) Ping(ctx context.Context) error { return s.read.Ping(ctx) }

func (s *Store) PoolStats() (inUse, total int32) {
	st := s.write.Stat()
	return st.AcquiredConns(), st.TotalConns()
}

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

	return nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}

	return err
}

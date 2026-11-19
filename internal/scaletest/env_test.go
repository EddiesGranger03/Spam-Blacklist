//go:build scale

package scaletest

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"vsf/internal/changefeed"
	"vsf/internal/filter"
	"vsf/internal/seal"
	"vsf/internal/snapshot"
	"vsf/internal/store"
)

// Environment:
//
//	SCALE_DATABASE_URL  postgres DSN whose database name ends in "_test" (created and migrated if missing)
//	SCALE_REDIS_ADDR    host:port of a throw-away Redis (required for the pub/sub tests)
//	SCALE_ROWS          rows seeded in blacklist_entries for startup/chaos tests (default 10_000_000)
//	SCALE_FILTER_N      comma separated N values for the filter benchmark (default 1000000,10000000)
func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}

	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(strings.ReplaceAll(v, "_", "")); err == nil {
			return n
		}
	}

	return def
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// ---------------- memory sampling ----------------

// memProbe samples the Go runtime's total mapped memory every few ms and keeps the peak.
type memProbe struct {
	stop chan struct{}
	done chan struct{}
	peak uint64
	base uint64
}

func totalMem() uint64 {
	// Resident-ish Go memory: everything mapped minus what was already handed back to the OS.
	s := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(s)

	return s[0].Value.Uint64() - s[1].Value.Uint64()
}

func startMemProbe() *memProbe {
	runtime.GC()
	debug.FreeOSMemory() // hand freed spans back so a previous phase's high-water mark does not hide this one's peak

	p := &memProbe{stop: make(chan struct{}), done: make(chan struct{}), base: totalMem()}
	p.peak = p.base

	go func() {
		defer close(p.done)

		t := time.NewTicker(5 * time.Millisecond)
		defer t.Stop()

		for {
			select {
			case <-p.stop:
				return
			case <-t.C:
				if m := totalMem(); m > p.peak {
					p.peak = m
				}
			}
		}
	}()

	return p
}

// Stop returns the peak mapped memory seen minus the baseline when the probe started.
func (p *memProbe) Stop() (peakDelta uint64) {
	close(p.stop)
	<-p.done

	if m := totalMem(); m > p.peak {
		p.peak = m
	}

	return p.peak - p.base
}

func heapNow() uint64 {
	runtime.GC()
	runtime.GC()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	return ms.HeapAlloc
}

func mb(b uint64) string { return fmt.Sprintf("%.1f MB", float64(b)/(1<<20)) }

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}

	i := min(int(float64(len(sorted))*p), len(sorted)-1)

	return sorted[i]
}

func summarize(d []time.Duration) (p50, p90, p99, maxv time.Duration) {
	s := slices.Clone(d)
	slices.Sort(s)

	return pct(s, 0.5), pct(s, 0.9), pct(s, 0.99), s[len(s)-1]
}

// ---------------- database ----------------

var (
	dbOnce sync.Once
	dbDSN  string
	dbErr  error
)

// scaleDSN creates (once) and migrates the scale database, then returns its DSN.
func scaleDSN(t *testing.T) string {
	t.Helper()

	base := os.Getenv("SCALE_DATABASE_URL")
	if base == "" {
		t.Skip("SCALE_DATABASE_URL is not set")
	}

	dbOnce.Do(func() {
		u, err := url.Parse(base)
		if err != nil {
			dbErr = err
			return
		}

		name := strings.TrimPrefix(u.Path, "/")
		if !strings.HasSuffix(name, "_test") {
			dbErr = fmt.Errorf("refusing: database %q must end in _test", name)
			return
		}

		ctx := context.Background()
		adm := *u
		adm.Path = "/postgres"

		ap, err := pgxpool.New(ctx, adm.String())
		if err != nil {
			dbErr = err
			return
		}
		defer ap.Close()

		var exists bool
		if err := ap.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil {
			dbErr = err
			return
		}

		if !exists {
			if _, err := ap.Exec(ctx, `CREATE DATABASE `+name); err != nil {
				dbErr = err
				return
			}
		}

		dbPool, err := pgxpool.New(ctx, base)
		if err != nil {
			dbErr = err
			return
		}
		defer dbPool.Close()

		st, err := store.New(ctx, base, "", 4)
		if err != nil {
			dbErr = err
			return
		}
		defer st.Close()

		st.SetSealer(testSealer(t))

		// Migrate only a fresh database: once seeded, the table holds synthetic plaintext rows that the seal
		// migration would try to convert (and that conversion is not what we are measuring).
		var migrated bool
		if err := dbPool.QueryRow(ctx, `SELECT to_regclass('filter_snapshots') IS NOT NULL`).Scan(&migrated); err != nil {
			dbErr = err
			return
		}

		if !migrated {
			dbErr = st.Migrate(ctx)
		} else {
			// Already seeded (Migrate would try to verify the synthetic sealed columns): apply only migrations added
			// after the seeding, by hand. Currently 007 (snapshot corrupt flag, rebuild requests).
			var has007 bool
			if err := dbPool.QueryRow(ctx, `SELECT to_regclass('filter_rebuild_requests') IS NOT NULL`).Scan(&has007); err != nil {
				dbErr = err
				return
			}

			if !has007 {
				body, err := os.ReadFile("../store/migrations/007_snapshot_corrupt_and_rebuild_requests.sql")
				if err != nil {
					dbErr = err
					return
				}

				if _, err := dbPool.Exec(ctx, string(body)); err != nil {
					dbErr = err
					return
				}

				_, dbErr = dbPool.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ('007_snapshot_corrupt_and_rebuild_requests.sql') ON CONFLICT DO NOTHING`)
			}
		}
		dbDSN = base
	})

	if dbErr != nil {
		t.Fatal(dbErr)
	}

	return dbDSN
}

func testSealer(t testing.TB) *seal.Sealer {
	t.Helper()

	sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}

	return sl
}

func openStore(t testing.TB, dsn string) *store.Store {
	t.Helper()

	st, err := store.New(context.Background(), dsn, "", 6)
	if err != nil {
		t.Fatal(err)
	}

	st.SetSealer(testSealer(t))
	t.Cleanup(st.Close)

	return st
}

func rawPool(t testing.TB, dsn string) *pgxpool.Pool {
	t.Helper()

	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(p.Close)

	return p
}

func newRedis(t testing.TB, addr string) *redis.Client {
	t.Helper()

	rdb := redis.NewClient(&redis.Options{Addr: addr, MaxRetries: -1, DialTimeout: 500 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	return rdb
}

func redisAddr(t *testing.T) string {
	t.Helper()

	a := os.Getenv("SCALE_REDIS_ADDR")
	if a == "" {
		t.Skip("SCALE_REDIS_ADDR is not set")
	}

	return a
}

// ensureSeed makes sure blacklist_entries holds at least `rows` rows (every 50th is WHITELIST) and returns the number
// of BLACKLIST rows. Seeding is SQL-side (generate_series) so 10M rows take minutes, not hours; it is idempotent.
func ensureSeed(t *testing.T, dsn string, rows int) (blacklist int64) {
	t.Helper()

	ctx := context.Background()
	p := rawPool(t, dsn)

	var have int64
	if err := p.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries`).Scan(&have); err != nil {
		t.Fatal(err)
	}

	if have < int64(rows) {
		t.Logf("seeding blacklist_entries: have %d, want %d", have, rows)

		step := 1_000_000

		start := time.Now()

		lean := os.Getenv("SCALE_LEAN") != ""
		if lean {
			// Lean seeding for very large N: drop the unique (value_hash, type, match_type, value_blind) index first. The
			// filter scan walks the id index and reads value_hash/status only, so it is not involved; it is rebuilt by
			// no one, i.e. a lean database cannot be used for the write-path tests.
			var idx string
			if err := p.QueryRow(ctx, `SELECT indexname FROM pg_indexes WHERE tablename='blacklist_entries' AND indexdef LIKE '%UNIQUE%'`).Scan(&idx); err == nil {
				if _, err := p.Exec(ctx, `DROP INDEX `+idx); err != nil {
					t.Fatal(err)
				}
			}

			step = 2_000_000
		}

		for lo := int(have); lo < rows; lo += step {
			hi := min(lo+step, rows)

			q := `INSERT INTO blacklist_entries
					(type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version, status, category)
				SELECT 'phone', 'exact', hashtextextended('seed' || i::text, 7),
				       sha256(('b' || i::text)::bytea),
				       substr(sha256(('e' || i::text)::bytea) || sha256(('f' || i::text)::bytea), 1, 48),
				       substr(sha256(('n' || i::text)::bytea), 1, 28), substr(sha256(('s' || i::text)::bytea), 1, 28), 1,
				       CASE WHEN i % 50 = 0 THEN 'WHITELIST' ELSE 'BLACKLIST' END, 'spam'
				FROM generate_series($1::bigint, $2::bigint) AS i`
			if lean {
				q = `INSERT INTO blacklist_entries
					(type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version, status, category)
				SELECT 'phone', 'exact', hashtextextended('seed' || i::text, 7), '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, '\x00'::bytea, 1,
				       CASE WHEN i % 50 = 0 THEN 'WHITELIST' ELSE 'BLACKLIST' END, 'spam'
				FROM generate_series($1::bigint, $2::bigint) AS i`
			}

			if _, err := p.Exec(ctx, q, lo, hi-1); err != nil {
				t.Fatal(err)
			}

			t.Logf("  seeded %d / %d (%s)", hi, rows, time.Since(start).Truncate(time.Second))
		}

		if _, err := p.Exec(ctx, `ANALYZE blacklist_entries`); err != nil {
			t.Fatal(err)
		}
	}

	if err := p.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries WHERE status='BLACKLIST'`).Scan(&blacklist); err != nil {
		t.Fatal(err)
	}

	return blacklist
}

// tableReads returns (scans, rows) read from the blacklist_entries partitions so far, from pg_stat_user_tables.
// Postgres flushes backend stats lazily, so this waits ~1.6s first.
func tableReads(t testing.TB, p *pgxpool.Pool) (scans, rows int64) {
	t.Helper()

	time.Sleep(1600 * time.Millisecond)

	err := p.QueryRow(context.Background(), `SELECT COALESCE(sum(seq_scan + idx_scan),0)::bigint,
			COALESCE(sum(seq_tup_read + idx_tup_fetch),0)::bigint
		FROM pg_stat_user_tables WHERE relname LIKE 'blacklist\_entries\_p%'`).Scan(&scans, &rows)
	if err != nil {
		t.Fatal(err)
	}

	return scans, rows
}

func resetSnapshots(t testing.TB, p *pgxpool.Pool) {
	t.Helper()

	if _, err := p.Exec(context.Background(), `DELETE FROM filter_snapshots`); err != nil {
		t.Fatal(err)
	}
}

// ---------------- pods ----------------

// pod is one "server process": its own pool, filter, feed, leader-lock connection and syncer.
type pod struct {
	name   string
	st     *store.Store
	feed   *changefeed.Feed
	m      *filter.Manager
	sync   *snapshot.Syncer
	leader *store.AdvisoryLeader
	rdb    *redis.Client

	readyAfter time.Duration // Bootstrap duration
	readyErr   error
	stop       context.CancelFunc
}

type podOpts struct {
	redisAddr string
	channel   string
	safety    time.Duration
	fallback  time.Duration
	snapPoll  time.Duration
	snapEvery time.Duration
	expected  uint64
	publish   bool // attach a Redis Publisher to the store
	// F10 early rebuild knobs passed to snapshot.Config (zero = package defaults).
	rebuildRatio float64
	rebuildGap   time.Duration
}

func (o *podOpts) defaults() {
	if o.safety == 0 {
		o.safety = time.Hour
	}

	if o.fallback == 0 {
		o.fallback = time.Second
	}

	if o.snapPoll == 0 {
		o.snapPoll = 250 * time.Millisecond
	}

	if o.snapEvery == 0 {
		o.snapEvery = 24 * time.Hour
	}
}

func newPod(t *testing.T, dsn, name string, o podOpts) *pod {
	t.Helper()
	o.defaults()

	st := openStore(t, dsn)
	m := filter.NewManager()
	feed := changefeed.New(st, m, quiet())
	leader := st.Leader(store.SnapshotLeaderLockID)

	p := &pod{name: name, st: st, feed: feed, m: m, leader: leader}
	p.sync = snapshot.NewSyncer(st.Snapshots(), feed, leader, quiet(), snapshot.Config{
		Interval: o.snapEvery, PollEvery: o.snapPoll, Expected: o.expected,
		DeltaRebuildRatio: o.rebuildRatio, MinRebuildGap: o.rebuildGap,
	})

	if o.redisAddr != "" {
		p.rdb = newRedis(t, o.redisAddr)
		if o.publish {
			st.SetChangeNotifier(changefeed.NewPublisher(p.rdb, o.channel, quiet()))
		}
	}

	t.Cleanup(func() {
		if p.stop != nil {
			p.stop()
		}

		leader.Release()
	})

	return p
}

// bootstrap runs Syncer.Bootstrap and, on success, starts the background loops the real server starts.
func (p *pod) bootstrap(ctx context.Context, o podOpts) {
	o.defaults()

	start := time.Now()
	p.readyErr = p.sync.Bootstrap(ctx)
	p.readyAfter = time.Since(start)

	if p.readyErr != nil {
		return
	}

	bg, cancel := context.WithCancel(context.Background())
	p.stop = cancel

	go p.feed.RunSync(bg, o.safety, o.fallback)
	go p.sync.Run(bg)

	if p.rdb != nil {
		go p.feed.Subscribe(bg, p.rdb, o.channel)
	}
}

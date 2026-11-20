package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/snapshot"
)

// BlacklistPartitions is the number of hash partitions of blacklist_entries (001_init.sql).
const BlacklistPartitions = 32

// ScanOptions throttles the full scan used to build a filter snapshot.
type ScanOptions struct {
	Batch int           // rows per keyset page (default and maximum: MaxScanBatch)
	Pause time.Duration // sleep between pages, to bound load on the database
}

// MaxScanBatch caps the rows read per page during a full scan: larger pages make each query heavier on the database.
const MaxScanBatch = 5000

var scanOpts = ScanOptions{Batch: MaxScanBatch, Pause: 2 * time.Millisecond}

// SetScanOptions configures ScanBlacklistHashes (call at startup).
func SetScanOptions(o ScanOptions) {
	if o.Batch <= 0 || o.Batch > MaxScanBatch {
		o.Batch = MaxScanBatch
	}

	scanOpts = o
}

// ScanBlacklistHashes emits the value_hash of every row with status BLACKLIST. It walks the 32 partitions one at a
// time with keyset pagination on id (short queries, no long-running snapshot, no big sort), pausing between pages, on
// the read pool (replica if configured). Only the snapshot leader (or a dev/test full build) calls this.
func (s *Store) ScanBlacklistHashes(ctx context.Context, emit func(uint64)) error {
	o := scanOpts

	for p := 0; p < BlacklistPartitions; p++ {
		// Partition name is built from an integer, never from input.
		q := fmt.Sprintf(`SELECT id, value_hash FROM blacklist_entries_p%d
			WHERE id > $1 AND status = 'BLACKLIST' ORDER BY id LIMIT $2`, p)

		var after int64

		for {
			rows, err := s.read.Query(ctx, q, after, o.Batch)
			if err != nil {
				return fmt.Errorf("scan partition %d: %w", p, err)
			}

			n := 0
			for rows.Next() {
				var h int64
				if err := rows.Scan(&after, &h); err != nil {
					rows.Close()
					return err
				}

				emit(uint64(h)) // #nosec G115 -- chủ ý: cùng bit pattern với hash đã lưu trong BIGINT
				n++
			}

			rows.Close()
			if err := rows.Err(); err != nil {
				return fmt.Errorf("scan partition %d: %w", p, err)
			}

			if n < o.Batch {
				break
			}

			if o.Pause > 0 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(o.Pause):
				}
			}
		}
	}

	return nil
}

// SnapshotChunkSize is the size of each bytea chunk.
const SnapshotChunkSize = 4 << 20

// PGSnapshots stores filter snapshots in Postgres (migration 006). It implements snapshot.Store.
type PGSnapshots struct{ s *Store }

var _ snapshot.Store = PGSnapshots{}

// Domain is the hash domain of this store's value_hash (G1): derived from DATA_PEPPER via the sealer, or
// snapshot.PlainDomain without one. Only snapshots of this domain are listed or loaded.
func (p PGSnapshots) Domain() uint64 {
	if p.s.sealer == nil {
		return snapshot.PlainDomain
	}

	return p.s.sealer.FilterDomain()
}

// domainArg is Domain() as the stored BIGINT bit pattern.
func (p PGSnapshots) domainArg() int64 { return int64(p.Domain()) } // #nosec G115 -- stored bit pattern

// Snapshots returns the Postgres snapshot store.
func (s *Store) Snapshots() PGSnapshots { return PGSnapshots{s: s} }

// Save writes the snapshot in a single transaction, chunk by chunk, and sets complete only after the last chunk;
// a crash or error rolls everything back. The last 8 bytes of the stream (the file's own checksum) are recorded
// in the checksum column.
func (p PGSnapshots) Save(ctx context.Context, meta snapshot.Meta, r io.Reader) (int64, error) {
	tx, err := p.s.write.Begin(ctx)
	if err != nil {
		return 0, err
	}

	// The caller encodes the same domain into the file header; 0 means "this store's domain".
	domain := int64(meta.Domain) // #nosec G115 -- stored bit pattern
	if meta.Domain == 0 {
		domain = p.domainArg()
	}

	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	var id int64
	if err := tx.QueryRow(ctx, `INSERT INTO filter_snapshots (kind, items, cursor_xid, cursor_seq, domain_id)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		int16(meta.Kind), int64(meta.Items), meta.CursorXID, meta.CursorSeq, domain).Scan(&id); err != nil { // #nosec G115 -- item count fits int64
		return 0, err
	}

	buf := make([]byte, SnapshotChunkSize)
	var (
		size  int64
		idx   int
		tail8 []byte
	)

	for {
		n, rerr := io.ReadFull(r, buf)
		if n > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO filter_snapshot_chunks (snapshot_id, idx, data) VALUES ($1, $2, $3)`,
				id, idx, buf[:n]); err != nil {
				return 0, err
			}

			idx++
			size += int64(n)
			tail8 = append(tail8, buf[max(0, n-8):n]...)
			if len(tail8) > 8 {
				tail8 = append(tail8[:0], tail8[len(tail8)-8:]...)
			}
		}

		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}

		if rerr != nil {
			return 0, rerr
		}
	}

	if len(tail8) != 8 {
		return 0, errors.New("snapshot: stream too short")
	}

	sum := int64(binary.LittleEndian.Uint64(tail8)) // #nosec G115 -- stored bit pattern

	tag, err := tx.Exec(ctx, `UPDATE filter_snapshots SET size_bytes=$2, chunks=$3, checksum=$4, complete=true
		WHERE id=$1 AND (SELECT count(*) FROM filter_snapshot_chunks WHERE snapshot_id=$1) = $3`, id, size, idx, sum)
	if err != nil {
		return 0, err
	}

	if tag.RowsAffected() != 1 {
		return 0, errors.New("snapshot: chunk count mismatch")
	}

	return id, tx.Commit(ctx)
}

// LatestID returns the id of the newest complete snapshot.
func (p PGSnapshots) LatestID(ctx context.Context) (int64, error) {
	var id int64
	err := p.s.read.QueryRow(ctx, `SELECT id FROM filter_snapshots WHERE complete AND NOT corrupt AND domain_id=$1 ORDER BY id DESC LIMIT 1`, p.domainArg()).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, snapshot.ErrNoSnapshot
	}

	return id, err
}

// LoadLatest opens the newest usable (complete, not corrupt) snapshot.
func (p PGSnapshots) LoadLatest(ctx context.Context) (snapshot.Meta, io.ReadCloser, error) {
	ids, err := p.ListUsable(ctx)
	if err != nil {
		return snapshot.Meta{}, nil, err
	}

	if len(ids) == 0 {
		return snapshot.Meta{}, nil, snapshot.ErrNoSnapshot
	}

	return p.Load(ctx, ids[0])
}

// ListUsable returns the ids of complete, non-corrupt snapshots, newest first (cheap: index only).
func (p PGSnapshots) ListUsable(ctx context.Context) ([]int64, error) {
	rows, err := p.s.read.Query(ctx, `SELECT id FROM filter_snapshots WHERE complete AND NOT corrupt AND domain_id=$1 ORDER BY id DESC`, p.domainArg())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []int64

	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}

		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// Load opens one snapshot by id; chunks are fetched one at a time as the reader is consumed. Reads go to the primary:
// a replica may not yet have the rows of a just-committed snapshot.
func (p PGSnapshots) Load(ctx context.Context, id int64) (snapshot.Meta, io.ReadCloser, error) {
	var (
		m        snapshot.Meta
		kind     int16
		items    int64
		chunks   int
		checksum int64
		domain   int64
	)

	err := p.s.write.QueryRow(ctx, `SELECT id, kind, items, cursor_xid, cursor_seq, size_bytes, chunks, checksum, created_at, domain_id
		FROM filter_snapshots WHERE id=$1 AND complete AND NOT corrupt`, id).
		Scan(&m.ID, &kind, &items, &m.CursorXID, &m.CursorSeq, &m.SizeBytes, &chunks, &checksum, &m.CreatedAt, &domain)
	if errors.Is(err, pgx.ErrNoRows) {
		return m, nil, snapshot.ErrNoSnapshot
	}

	if err != nil {
		return m, nil, err
	}

	m.Kind = snapshot.Kind(kind)  // #nosec G115 -- small enum
	m.Items = uint64(items)       // #nosec G115 -- non-negative
	m.Checksum = uint64(checksum) // #nosec G115 -- stored bit pattern
	m.Domain = uint64(domain)     // #nosec G115 -- stored bit pattern; the Syncer refuses a foreign domain

	return m, &chunkReader{ctx: ctx, pool: p.s.write, id: m.ID, total: chunks}, nil
}

// MarkCorrupt flags a snapshot so that no pod tries it again.
func (p PGSnapshots) MarkCorrupt(ctx context.Context, id int64, reason string) error {
	_, err := p.s.write.Exec(ctx, `UPDATE filter_snapshots SET corrupt=true, corrupt_reason=left($2, 500) WHERE id=$1`, id, reason)
	return err
}

// RebuildState returns the rebuild-request counters.
func (p PGSnapshots) RebuildState(ctx context.Context) (requests, handled int64, err error) {
	err = p.s.read.QueryRow(ctx, `SELECT requests, handled FROM filter_rebuild_requests WHERE id=1`).Scan(&requests, &handled)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, nil
	}

	return requests, handled, err
}

// RequestRebuild records "please build a snapshot" unless a request is already pending. It reports whether a new
// request was recorded. Atomic, so any number of pods asking at once results in a single pending request.
func (p PGSnapshots) RequestRebuild(ctx context.Context) (bool, error) {
	tag, err := p.s.write.Exec(ctx, `UPDATE filter_rebuild_requests SET requests = requests + 1, updated_at = now()
		WHERE id=1 AND requests <= handled`)

	return tag.RowsAffected() == 1, err
}

// MarkRebuildHandled sets handled to upTo (never lowers it): the leader passes the `requests` it saw before building.
func (p PGSnapshots) MarkRebuildHandled(ctx context.Context, upTo int64) error {
	_, err := p.s.write.Exec(ctx, `UPDATE filter_rebuild_requests SET handled = GREATEST(handled, $1), updated_at = now() WHERE id=1`, upTo)
	return err
}

type chunkReader struct {
	ctx   context.Context
	pool  *pgxpool.Pool
	id    int64
	next  int
	total int
	cur   []byte
}

func (c *chunkReader) Read(b []byte) (int, error) {
	for len(c.cur) == 0 {
		if c.next >= c.total {
			return 0, io.EOF
		}

		if err := c.pool.QueryRow(c.ctx, `SELECT data FROM filter_snapshot_chunks WHERE snapshot_id=$1 AND idx=$2`,
			c.id, c.next).Scan(&c.cur); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return 0, fmt.Errorf("%w: snapshot %d chunk %d missing (truncated, or pruned while loading)", snapshot.ErrCorrupt, c.id, c.next)
			}

			return 0, err
		}

		c.next++
	}

	n := copy(b, c.cur)
	c.cur = c.cur[n:]

	return n, nil
}

func (c *chunkReader) Close() error { c.cur = nil; c.next = c.total; return nil }

// Prune keeps the newest keep usable snapshots of this domain and deletes older ones, snapshots of another hash
// domain (G1) older than a day, plus incomplete rows older than an hour
// (left by a writer that died; normally impossible since Save is one transaction).
func (p PGSnapshots) Prune(ctx context.Context, keep int) (int64, error) {
	if keep < 1 {
		keep = 1
	}

	tag, err := p.s.write.Exec(ctx, `DELETE FROM filter_snapshots
		WHERE (complete AND NOT corrupt AND id < (SELECT COALESCE(min(id), 0) FROM
				(SELECT id FROM filter_snapshots WHERE complete AND NOT corrupt AND domain_id=$2 ORDER BY id DESC LIMIT $1) k)
				AND domain_id=$2)
		   OR (domain_id <> $2 AND created_at < now() - interval '1 day')
		   OR (NOT complete AND created_at < now() - interval '1 hour')
		   OR (corrupt AND created_at < now() - interval '1 day')`, keep, p.domainArg())

	return tag.RowsAffected(), err
}

// SnapshotLeaderLockID is the advisory lock key held by the pod that builds snapshots. It must differ from every other
// advisory key in the store (727274 = Migrate, 727275 = audit chain): the leader holds its lock for its whole lifetime,
// so sharing a key would block every audit write (login, entry edits) while a leader exists (finding F5).
// TestAdvisoryLockKeysAreDistinct guards this.
const SnapshotLeaderLockID int64 = 727276

// AdvisoryLeader elects one pod with pg_try_advisory_lock on a dedicated session. The lock is released when the
// session ends (pod dies / connection drops), so another pod can take over. It implements snapshot.Leader.
type AdvisoryLeader struct {
	pool *pgxpool.Pool
	key  int64

	mu   sync.Mutex
	conn *pgxpool.Conn
}

// Leader returns an elector bound to the primary pool.
func (s *Store) Leader(key int64) *AdvisoryLeader { return &AdvisoryLeader{pool: s.write, key: key} }

// TryAcquire returns true if this process holds the lock (taking it if free). It also verifies an already-held
// session is still alive; if not, leadership is dropped and re-attempted.
func (l *AdvisoryLeader) TryAcquire(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.conn != nil {
		if err := l.conn.Ping(ctx); err == nil {
			return true, nil
		}

		// Session lost: the server already released the lock with it.
		l.conn.Release()
		l.conn = nil
	}

	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return false, err
	}

	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, l.key).Scan(&ok); err != nil {
		conn.Release()
		return false, err
	}

	if !ok {
		conn.Release()
		return false, nil
	}

	l.conn = conn

	return true, nil
}

// Release gives up leadership.
func (l *AdvisoryLeader) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.conn == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := l.conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, l.key); err != nil {
		// Could not unlock cleanly: close the session so the server drops the lock.
		_ = l.conn.Conn().Close(ctx)
	}

	l.conn.Release()
	l.conn = nil
}

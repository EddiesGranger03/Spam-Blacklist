package snapshot

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"vsf/internal/filter"
)

// Leader elects the single pod allowed to build snapshots (full table scan).
type Leader interface {
	// TryAcquire returns true while this process holds leadership (non-blocking).
	TryAcquire(ctx context.Context) (bool, error)
	Release()
}

// Installer is the changefeed side (implemented by *changefeed.Feed).
type Installer interface {
	BuildStatic(ctx context.Context, expectedItems uint64) (*filter.BinaryFuse8, string, int64, error)
	Install(ctx context.Context, l *filter.Layered, src filter.Source) error
	Filter() *filter.Manager
}

// Config tunes the Syncer.
type Config struct {
	Interval    time.Duration // leader builds a new snapshot this often (FILTER_SNAPSHOT_INTERVAL, default 1h)
	PollEvery   time.Duration // how often pods look for a newer snapshot / try to become leader
	MaxAge      time.Duration // snapshots older than this are refused: change_log after their cursor may be purged
	WaitTimeout time.Duration // a non-leader waiting at startup logs an error after this long (and keeps waiting)
	Keep        int           // snapshots kept by Prune
	Expected    uint64        // capacity hint for the full scan
	RetryBase   time.Duration // first retry delay after a failed build/save (doubles each failure), default 5s
	RetryMax    time.Duration // cap of that delay, default 10m

	// F10: early rebuild when the delta/removed layers grow between scheduled snapshots (e.g. a bulk import).
	DeltaRebuildRatio float64       // leader rebuilds once delta fill >= this (FILTER_DELTA_REBUILD_RATIO, default 0.7; <0 disables)
	RemovedRebuildMax int64         // ... or once the removed-set holds this many hashes (FILTER_REMOVED_REBUILD_MAX, default 1M; <0 disables)
	MinRebuildGap     time.Duration // minimum time between two snapshots for those reasons (FILTER_MIN_REBUILD_GAP, default 5m)
}

func (c *Config) defaults() {
	if c.Interval <= 0 {
		c.Interval = time.Hour
	}

	if c.PollEvery <= 0 {
		c.PollEvery = 30 * time.Second
	}

	if c.MaxAge <= 0 {
		c.MaxAge = 23 * time.Hour
	}

	if c.WaitTimeout <= 0 {
		c.WaitTimeout = 10 * time.Minute
	}

	if c.Keep <= 0 {
		c.Keep = 3
	}

	if c.RetryBase <= 0 {
		c.RetryBase = 5 * time.Second
	}

	if c.RetryMax <= 0 {
		c.RetryMax = 10 * time.Minute
	}

	if c.RetryMax < c.RetryBase {
		c.RetryMax = c.RetryBase
	}

	if c.DeltaRebuildRatio == 0 {
		c.DeltaRebuildRatio = DefaultDeltaRebuildRatio
	}

	if c.RemovedRebuildMax == 0 {
		c.RemovedRebuildMax = DefaultRemovedRebuildMax
	}

	if c.MinRebuildGap <= 0 {
		c.MinRebuildGap = 5 * time.Minute
	}
}

const (
	// DefaultDeltaRebuildRatio: rebuild at 70% of the delta's design capacity, while its FPR is still below the design
	// value (~1%), leaving headroom for the writes that land during the scan itself.
	DefaultDeltaRebuildRatio = 0.7
	// DefaultRemovedRebuildMax: the removed-set is an exact Go map (~48 B/entry), so 1M entries ≈ 48 MB per pod, and
	// every Test takes its read lock while it is non-empty. A mass delete (e.g. disabling an import) beyond that is
	// cheaper to fold into a new snapshot than to keep in RAM on every pod.
	DefaultRemovedRebuildMax = 1_000_000
)

// Status is a point-in-time view of the syncer for metrics and /readyz.
type Status struct {
	Leader bool // this pod currently holds the leader lock (as of the last election attempt)

	SnapshotID  int64     // snapshot the served filter was built from (0 = built locally, none loaded)
	CursorXID   string    // change_log cursor of that snapshot
	CursorSeq   int64     //
	SnapshotAt  time.Time // creation time of that snapshot (zero if unknown)
	Interval    time.Duration
	LastBuildOK time.Time // last successful table scan + static build by this pod
	LastSaveOK  time.Time // last successful snapshot save by this pod

	BuildFailures   int64 // cumulative scan/build errors
	SaveFailures    int64 // cumulative save errors
	InstallFailures int64 // cumulative install (replay) errors after a good save
	Consecutive     int   // failures since the last success (drives the backoff)
	NextAttempt     time.Time
	PendingSave     bool // a built filter is held in RAM waiting for Save to succeed (no rescan needed)

	Fallbacks       int64 // times an older snapshot was used because newer ones were unusable
	CorruptMarked   int64 // snapshots this pod flagged corrupt
	RebuildRequests int64 // rebuild requests this pod recorded
	RebuildServed   int64 // builds this pod ran because of a request
	PressureBuilds  int64 // early builds this pod ran because the delta/removed layer was too full (F10)
}

// pendingSave is a freshly built static layer whose Save failed; it is retried without scanning the table again.
type pendingSave struct {
	static  *filter.BinaryFuse8
	xid     string
	seq     int64
	builtAt time.Time
}

// Syncer loads, builds and refreshes the static filter layer from a Store.
type Syncer struct {
	store  Store
	feed   Installer
	leader Leader
	log    *slog.Logger
	cfg    Config
	now    func() time.Time
	rnd    func() float64 // [0,1), replaceable in tests

	mu         sync.Mutex
	lastBuild  time.Time // newest snapshot creation time known to this pod (leader uses it to schedule builds)
	pending    *pendingSave
	failures   int
	nextTry    time.Time
	isLeader   bool
	installed  time.Time
	scanOK     time.Time
	saveOK     time.Time
	buildFail  int64
	saveFail   int64
	instFail   int64
	fallbacks  int64
	corrupt    int64
	reqs       int64
	reqServed  int64
	pressureN  int64
	lastReqLog time.Time
}

// NewSyncer creates a Syncer.
func NewSyncer(st Store, feed Installer, leader Leader, log *slog.Logger, cfg Config) *Syncer {
	cfg.defaults()
	return &Syncer{store: st, feed: feed, leader: leader, log: log, cfg: cfg, now: time.Now, rnd: rand.Float64}
}

// ErrStale means the newest snapshot is older than the change_log retention and cannot be caught up.
var ErrStale = errors.New("snapshot: older than change_log retention")

// Status returns the current status (safe for concurrent use).
func (s *Syncer) Status() Status {
	src := s.feed.Filter().Source()

	s.mu.Lock()
	defer s.mu.Unlock()

	return Status{
		Leader: s.isLeader, SnapshotID: src.SnapshotID, CursorXID: src.CursorXID, CursorSeq: src.CursorSeq,
		SnapshotAt: s.installed, Interval: s.cfg.Interval, LastBuildOK: s.scanOK, LastSaveOK: s.saveOK,
		BuildFailures: s.buildFail, SaveFailures: s.saveFail, InstallFailures: s.instFail,
		Consecutive: s.failures, NextAttempt: s.nextTry, PendingSave: s.pending != nil,
		Fallbacks: s.fallbacks, CorruptMarked: s.corrupt, RebuildRequests: s.reqs, RebuildServed: s.reqServed,
		PressureBuilds: s.pressureN,
	}
}

func (s *Syncer) setLeader(v bool) {
	s.mu.Lock()
	s.isLeader = v
	s.mu.Unlock()
}

func isCorrupt(err error) bool { return errors.Is(err, ErrChecksum) || errors.Is(err, ErrCorrupt) }

// LoadNewer installs the newest usable stored snapshot if it is newer than the one being served. Snapshots are tried
// newest to oldest: one that fails its checksum (or cannot be decoded) is flagged corrupt in the store — so nobody
// tries it again — and the next older one is used; one older than MaxAge ends the search (all older ones are older
// still). Transient errors (database, network) stop the attempt without flagging anything.
// Returns (true, nil) if a snapshot was installed, ErrNoSnapshot if there is no usable one.
func (s *Syncer) LoadNewer(ctx context.Context) (bool, error) {
	ids, err := s.store.ListUsable(ctx)
	if err != nil {
		return false, err
	}

	if len(ids) == 0 {
		return false, ErrNoSnapshot
	}

	cur := s.feed.Filter().Source().SnapshotID
	if ids[0] <= cur {
		return false, nil
	}

	var first error

	for i, id := range ids {
		if id <= cur {
			break
		}

		err := s.tryLoad(ctx, id)
		if err == nil {
			if i > 0 {
				s.mu.Lock()
				s.fallbacks++
				s.mu.Unlock()
				s.log.Warn("newest filter snapshot(s) unusable; installed an older one", "id", id, "skipped", i)
			}

			return true, nil
		}

		if first == nil {
			first = err
		}

		switch {
		case errors.Is(err, ErrDomainMismatch):
			// A valid snapshot of another hash domain (from before a pepper rotation): skip it, never flag it corrupt.
			s.log.Warn("filter snapshot built under another DATA_PEPPER; skipping it", "id", id, "err", err)
		case errors.Is(err, ErrStale):
			return false, err
		case isCorrupt(err):
			s.log.Error("filter snapshot is corrupt; flagging it and trying an older one", "id", id, "err", err)

			if merr := s.store.MarkCorrupt(ctx, id, err.Error()); merr != nil {
				s.log.Warn("could not flag corrupt snapshot", "id", id, "err", merr)
			} else {
				s.mu.Lock()
				s.corrupt++
				s.mu.Unlock()
			}
		case errors.Is(err, ErrNoSnapshot):
			// pruned or flagged by another pod between list and load: try the next one
		default:
			return false, err
		}
	}

	if first == nil || errors.Is(first, ErrDomainMismatch) {
		// Nothing of our hash domain is the same as no snapshot: the leader builds one, other pods ask it to (F3).
		first = ErrNoSnapshot
	}

	return false, first
}

// tryLoad decodes, verifies and installs one snapshot.
func (s *Syncer) tryLoad(ctx context.Context, id int64) error {
	meta, rc, err := s.store.Load(ctx, id)
	if err != nil {
		return err
	}
	defer rc.Close()

	// G1: value_hash depends on DATA_PEPPER. A snapshot of another domain decodes and checksums fine but describes
	// different hashes; installing it would make every blacklisted value read as safe.
	domain := s.store.Domain()
	if meta.Domain != domain {
		return fmt.Errorf("%w: snapshot %d (domain %x, ours %x)", ErrDomainMismatch, meta.ID, meta.Domain, domain)
	}

	if age := s.now().Sub(meta.CreatedAt); age > s.cfg.MaxAge {
		return fmt.Errorf("%w: snapshot %d is %s old (max %s)", ErrStale, meta.ID, age.Truncate(time.Second), s.cfg.MaxAge)
	}

	start := s.now()

	d, err := Decode(rc)
	if err != nil {
		return fmt.Errorf("snapshot %d: %w", meta.ID, err)
	}

	if meta.Checksum != 0 && d.Checksum != meta.Checksum {
		return fmt.Errorf("snapshot %d: %w (meta)", meta.ID, ErrChecksum)
	}

	// Checked after the checksum, so damaged bytes are flagged corrupt rather than mistaken for another domain.
	if d.Domain != domain {
		return fmt.Errorf("%w: snapshot %d file domain %x, ours %x", ErrDomainMismatch, meta.ID, d.Domain, domain)
	}

	if d.CursorXID != meta.CursorXID || d.CursorSeq != meta.CursorSeq {
		return fmt.Errorf("%w: snapshot %d cursor in file does not match metadata", ErrCorrupt, meta.ID)
	}

	l := filter.NewLayered(d.Filter, filter.DefaultDeltaCapacity(d.Filter.Items))
	if err := s.feed.Install(ctx, l, filter.Source{SnapshotID: meta.ID, CursorXID: d.CursorXID, CursorSeq: d.CursorSeq}); err != nil {
		return err
	}

	s.noteBuilt(meta.CreatedAt)

	s.mu.Lock()
	s.installed = meta.CreatedAt
	s.mu.Unlock()

	s.log.Info("filter snapshot installed", "id", meta.ID, "items", d.Filter.Items, "bytes", meta.SizeBytes,
		"cursor", fmt.Sprintf("%s.%d", d.CursorXID, d.CursorSeq), "took", s.now().Sub(start).String())

	return nil
}

// backoff returns the delay after n consecutive failures: RetryBase * 2^(n-1) capped at RetryMax, with "equal jitter"
// (uniform in [d/2, d]) so that several pods that failed together do not retry together, and never above the cap.
func (s *Syncer) backoff(n int) time.Duration {
	d := s.cfg.RetryBase

	for i := 1; i < n && d < s.cfg.RetryMax; i++ {
		d *= 2
	}

	d = min(d, s.cfg.RetryMax)

	return d/2 + time.Duration(s.rnd()*float64(d/2))
}

func (s *Syncer) fail(kind string, err error) {
	s.mu.Lock()
	s.failures++

	switch kind {
	case "build":
		s.buildFail++
	case "save":
		s.saveFail++
	default:
		s.instFail++
	}

	delay := s.backoff(s.failures)
	s.nextTry = s.now().Add(delay)
	n := s.failures
	s.mu.Unlock()

	s.log.Error("filter snapshot "+kind+" failed; will retry after backoff", "err", err, "consecutive", n, "retry_in", delay.Truncate(time.Millisecond).String())
}

// canBuild reports whether the backoff after the last failure has elapsed.
func (s *Syncer) canBuild() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return !s.now().Before(s.nextTry)
}

func (s *Syncer) hasPending() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.pending != nil
}

// BuildAndPublish (leader only) scans the table, builds the static layer — which folds in every delta/removed change
// up to the cursor — saves it, installs it locally and prunes old snapshots. Build and Save are separate steps: when
// Save fails the built layer is kept in RAM and the next call only retries Save (it never rescans the table for that),
// unless the held layer has become too old to be a good snapshot. Every failure arms the exponential backoff checked
// by Bootstrap and Tick.
func (s *Syncer) BuildAndPublish(ctx context.Context) error {
	start := s.now()

	// Requests seen so far are satisfied by this build; see the handled counter below.
	s.mu.Lock()
	pb := s.pending
	s.mu.Unlock()

	if pb != nil && s.now().Sub(pb.builtAt) > s.cfg.MaxAge/2 {
		s.log.Warn("dropping held filter build: too old to publish, rebuilding from the table")

		pb = nil
	}

	if pb == nil {
		static, xid, seq, err := s.feed.BuildStatic(ctx, s.cfg.Expected)
		if err != nil {
			if ctx.Err() == nil {
				s.fail("build", err)
			}

			return fmt.Errorf("build: %w", err)
		}

		pb = &pendingSave{static: static, xid: xid, seq: seq, builtAt: s.now()}

		s.mu.Lock()
		s.pending = pb
		s.scanOK = s.now()
		s.mu.Unlock()
	}

	pr, pw := io.Pipe()
	encErr := make(chan error, 1)

	go func() {
		_, _, err := Encode(pw, pb.static, s.store.Domain(), pb.xid, pb.seq)
		_ = pw.CloseWithError(err)
		encErr <- err
	}()

	id, err := s.store.Save(ctx, Meta{Kind: KindBinaryFuse8, Domain: s.store.Domain(), Items: pb.static.Items, CursorXID: pb.xid, CursorSeq: pb.seq}, pr)
	_ = pr.CloseWithError(errors.New("save finished"))

	if eerr := <-encErr; eerr != nil && err == nil {
		err = eerr
	}

	if err != nil {
		if ctx.Err() == nil {
			s.fail("save", err)
		}

		return fmt.Errorf("save: %w", err) // pb stays in s.pending: the next attempt only retries Save
	}

	s.mu.Lock()
	s.pending = nil
	s.saveOK = s.now()
	s.mu.Unlock()

	// A pod waiting for a snapshot (or asking for a rebuild) at any point before now is served by this one.
	if req, _, rerr := s.store.RebuildState(ctx); rerr == nil {
		if merr := s.store.MarkRebuildHandled(ctx, req); merr != nil {
			s.log.Warn("could not mark rebuild requests handled", "err", merr)
		}
	}

	l := filter.NewLayered(pb.static, filter.DefaultDeltaCapacity(pb.static.Items))
	if err := s.feed.Install(ctx, l, filter.Source{SnapshotID: id, CursorXID: pb.xid, CursorSeq: pb.seq}); err != nil {
		s.fail("install", err)

		return err
	}

	s.noteBuilt(s.now())

	s.mu.Lock()
	s.installed = s.now()
	s.failures = 0
	s.nextTry = time.Time{}
	s.mu.Unlock()

	if n, err := s.store.Prune(ctx, s.cfg.Keep); err != nil {
		s.log.Warn("filter snapshot prune", "err", err)
	} else if n > 0 {
		s.log.Info("filter snapshots pruned", "deleted", n)
	}

	s.log.Info("filter snapshot built", "id", id, "items", pb.static.Items, "bytes", pb.static.SizeBytes(),
		"cursor", fmt.Sprintf("%s.%d", pb.xid, pb.seq), "took", s.now().Sub(start).String())

	return nil
}

func (s *Syncer) noteBuilt(t time.Time) {
	s.mu.Lock()
	if t.After(s.lastBuild) {
		s.lastBuild = t
	}
	s.mu.Unlock()
}

func (s *Syncer) lastBuilt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.lastBuild
}

// requestRebuild asks the leader for a snapshot. At most one request is pending cluster-wide (see migration 007).
func (s *Syncer) requestRebuild(ctx context.Context) {
	ok, err := s.store.RequestRebuild(ctx)
	if err != nil {
		if ctx.Err() == nil {
			s.log.Warn("could not request a filter rebuild", "err", err)
		}

		return
	}

	if ok {
		s.mu.Lock()
		s.reqs++
		s.mu.Unlock()
		s.log.Warn("no usable filter snapshot: asked the leader to build one")
	}
}

// rebuildRequested reports whether a request is pending (requests > handled).
func (s *Syncer) rebuildRequested(ctx context.Context) bool {
	req, handled, err := s.store.RebuildState(ctx)

	return err == nil && req > handled
}

// Bootstrap makes the pod ready: newest valid snapshot → replay change_log after its cursor. Without a usable
// snapshot only the leader does a full build (honouring the failure backoff); other pods record a rebuild request and
// wait for it (logging an error every WaitTimeout), so N pods starting together never scan the table N times.
func (s *Syncer) Bootstrap(ctx context.Context) error {
	start := s.now()
	nextWarn := start.Add(s.cfg.WaitTimeout)
	retry := min(s.cfg.PollEvery, 5*time.Second)

	for {
		ok, err := s.LoadNewer(ctx)
		if ok {
			return nil
		}

		if err != nil && !errors.Is(err, ErrNoSnapshot) {
			s.log.Warn("filter snapshot not usable", "err", err)
		}

		leader, lerr := s.leader.TryAcquire(ctx)
		if lerr != nil {
			s.log.Warn("filter leader election", "err", lerr)
		}

		s.setLeader(leader)

		switch {
		case leader && s.canBuild():
			s.log.Info("no usable filter snapshot: this pod is leader, building one")

			if err := s.BuildAndPublish(ctx); err != nil {
				if ctx.Err() == nil {
					s.log.Error("filter full build failed", "err", err)
				}
			} else {
				return nil
			}

		case !leader:
			s.requestRebuild(ctx)
		}

		if now := s.now(); now.After(nextWarn) {
			s.log.Error("still waiting for a filter snapshot from the leader; pod stays not ready",
				"waited", now.Sub(start).Truncate(time.Second).String())
			nextWarn = now.Add(s.cfg.WaitTimeout)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(retry):
		}
	}
}

// underPressure reports whether the served filter's delta or removed layer has grown past its limit and the last
// snapshot is at least MinRebuildGap old (so a long import rebuilds every few minutes, not on every tick).
func (s *Syncer) underPressure() (bool, float64, int64) {
	fill, removed := s.feed.Filter().DeltaPressure()
	full := (s.cfg.DeltaRebuildRatio > 0 && fill >= s.cfg.DeltaRebuildRatio) ||
		(s.cfg.RemovedRebuildMax > 0 && removed >= s.cfg.RemovedRebuildMax)

	return full && s.now().Sub(s.lastBuilt()) >= s.cfg.MinRebuildGap, fill, removed
}

// Tick runs one maintenance step. The leader builds when the interval has passed, when a held build still has to be
// saved, when the delta/removed layer is too full (F10, rate-limited by MinRebuildGap), or when some pod asked for a
// rebuild — in each case only after the failure backoff has elapsed. Every pod then
// installs a newer usable snapshot if there is one.
func (s *Syncer) Tick(ctx context.Context) {
	leader, err := s.leader.TryAcquire(ctx)
	if err != nil {
		s.log.Warn("filter leader election", "err", err)
	}

	s.setLeader(leader)

	if leader {
		requested := s.rebuildRequested(ctx)
		scheduled := s.now().Sub(s.lastBuilt()) >= s.cfg.Interval || s.hasPending() || requested
		pressure, fill, removed := s.underPressure()

		if scheduled || pressure {
			if !s.canBuild() {
				return // backing off after a failure
			}

			if pressure && !scheduled {
				s.mu.Lock()
				s.pressureN++
				s.mu.Unlock()
				s.log.Warn("filter delta layer is filling up; building a snapshot early",
					"delta_fill", fmt.Sprintf("%.2f", fill), "removed", removed,
					"ratio_limit", s.cfg.DeltaRebuildRatio, "removed_limit", s.cfg.RemovedRebuildMax)
			}

			if requested {
				s.mu.Lock()
				s.reqServed++
				s.mu.Unlock()
			}

			if err := s.BuildAndPublish(ctx); err != nil && ctx.Err() == nil {
				s.log.Error("filter snapshot build failed", "err", err)
			}

			return
		}
	}

	if _, err := s.LoadNewer(ctx); err != nil && !errors.Is(err, ErrNoSnapshot) && ctx.Err() == nil {
		s.log.Warn("filter snapshot refresh", "err", err)
	}
}

// Run calls Tick every PollEvery until ctx is done, then releases leadership.
func (s *Syncer) Run(ctx context.Context) {
	defer s.leader.Release()

	t := time.NewTicker(s.cfg.PollEvery)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

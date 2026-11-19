package filter

import (
	"sync"
	"sync/atomic"

	"vsf/internal/bloom"
)

// Layered is the three-layer filter:
//
//		Test(h) = !removed[h] && (static.Contains(h) || delta.Test(h))
//
//	  - static: immutable binary fuse filter built from a snapshot of all BLACKLIST hashes.
//	  - delta: small Bloom filter for hashes added after the snapshot cursor (approximate is fine: only false positives).
//	  - removed: EXACT set of hashes removed after the snapshot cursor. It must be exact — a Bloom filter here would
//	    hide hashes that merely collide with a removed one, i.e. false negatives.
//
// Re-adding a removed hash deletes it from removed (and adds it to delta). All methods are safe for concurrent use.
type Layered struct {
	static *BinaryFuse8
	delta  *bloom.Filter

	deltaItems atomic.Uint64
	deltaCap   uint64

	mu         sync.RWMutex
	removed    map[uint64]struct{}
	removedLen atomic.Int64 // lets Test skip the lock in the common case of an empty removed-set
}

// MinDeltaCapacity is the smallest delta Bloom size (in items).
const MinDeltaCapacity = 1 << 20

// NewLayered wraps a static filter with empty delta/removed layers. deltaCap is the number of items the delta Bloom is
// sized for (FPR grows past it, but it never produces false negatives).
func NewLayered(static *BinaryFuse8, deltaCap uint64) *Layered {
	if static == nil {
		static = &BinaryFuse8{}
	}

	if deltaCap < MinDeltaCapacity {
		deltaCap = MinDeltaCapacity
	}

	return &Layered{static: static, delta: bloom.New(deltaCap), deltaCap: deltaCap, removed: map[uint64]struct{}{}}
}

// DefaultDeltaCapacity sizes the delta layer at 5% of the static set (at least MinDeltaCapacity).
func DefaultDeltaCapacity(staticItems uint64) uint64 { return max(staticItems/20, MinDeltaCapacity) }

// Test reports whether h may be blacklisted (false = definitely not).
func (l *Layered) Test(h uint64) bool {
	if l.removedLen.Load() > 0 {
		l.mu.RLock()
		_, gone := l.removed[h]
		l.mu.RUnlock()

		if gone {
			return false
		}
	}

	return l.static.Contains(h) || l.delta.Test(h)
}

// Add records a hash added after the snapshot.
func (l *Layered) Add(h uint64) {
	l.deltaItems.Add(1)
	l.Readd(h)
}

// Readd is Add without counting the item: used when the same change-log row is applied again (a pending row
// re-read on the next poll), so it is re-applied in order after any removal without inflating the item count.
func (l *Layered) Readd(h uint64) {
	// Order matters for concurrent readers: put it in delta BEFORE un-removing it, so there is no window where
	// the hash is neither removed nor present.
	l.delta.Add(h)

	if l.removedLen.Load() > 0 {
		l.mu.Lock()
		if _, ok := l.removed[h]; ok {
			delete(l.removed, h)
			l.removedLen.Add(-1)
		}
		l.mu.Unlock()
	}
}

// Remove records a hash removed after the snapshot.
func (l *Layered) Remove(h uint64) {
	l.mu.Lock()
	if _, ok := l.removed[h]; !ok {
		l.removed[h] = struct{}{}
		l.removedLen.Add(1)
	}
	l.mu.Unlock()
}

// Static returns the immutable layer.
func (l *Layered) Static() *BinaryFuse8 { return l.static }

// Stats is a point-in-time view used for metrics/logs.
type Stats struct {
	StaticItems, DeltaItems, DeltaCap uint64
	Removed                           int64
	Bytes                             uint64
}

// Stats returns sizes of the three layers. Bytes counts the static array, the delta bits and ~48 bytes per
// removed-map entry (Go map overhead estimate).
func (l *Layered) Stats() Stats {
	r := l.removedLen.Load()
	return Stats{
		StaticItems: l.static.Items,
		DeltaItems:  l.deltaItems.Load(),
		DeltaCap:    l.deltaCap,
		Removed:     r,
		Bytes:       l.static.SizeBytes() + l.delta.SizeBytes() + uint64(r)*48, // #nosec G115 -- r >= 0
	}
}

// DeltaFillRatio is items added to the delta layer divided by the capacity it was sized for. Past 1.0 its
// false-positive rate climbs fast (4x capacity measured ~68% FPR in docs/SCALE_TEST.md 11.3), so the snapshot leader
// rebuilds before that (see snapshot.Config.DeltaRebuildRatio).
func (l *Layered) DeltaFillRatio() float64 {
	if l.deltaCap == 0 {
		return 0
	}

	return float64(l.deltaItems.Load()) / float64(l.deltaCap)
}

// Manager holds the active Layered filter and swaps it atomically. It satisfies checker.Filter.
type Manager struct {
	cur  atomic.Pointer[Layered]
	meta atomic.Pointer[Source]
}

// Source describes where the active filter came from.
type Source struct {
	SnapshotID int64 // 0 = built locally, not from a stored snapshot
	CursorXID  string
	CursorSeq  int64
}

// NewManager returns a Manager with no filter (not ready).
func NewManager() *Manager { return &Manager{} }

// Ready reports whether a filter is installed. A pod must not receive traffic before this.
func (m *Manager) Ready() bool { return m.cur.Load() != nil }

// Test is conservative while not ready (returns true so callers fall through to the DB). This is only an internal
// safety net: /readyz keeps the pod out of the load balancer until a filter is installed.
func (m *Manager) Test(h uint64) bool {
	l := m.cur.Load()
	if l == nil {
		return true
	}

	return l.Test(h)
}

// Current returns the active filter (nil if not ready).
func (m *Manager) Current() *Layered { return m.cur.Load() }

// Swap installs l as the active filter.
func (m *Manager) Swap(l *Layered, src Source) {
	m.meta.Store(&src)
	m.cur.Store(l)
}

// Source returns where the active filter came from (zero if none).
func (m *Manager) Source() Source {
	if s := m.meta.Load(); s != nil {
		return *s
	}

	return Source{}
}

// Items is the number of items in the static layer plus delta adds.
func (m *Manager) Items() uint64 {
	if l := m.cur.Load(); l != nil {
		s := l.Stats()
		return s.StaticItems + s.DeltaItems
	}

	return 0
}

// DeltaPressure returns the active filter's delta fill ratio and removed-set size (0, 0 when not ready).
func (m *Manager) DeltaPressure() (fill float64, removed int64) {
	if l := m.cur.Load(); l != nil {
		return l.DeltaFillRatio(), l.removedLen.Load()
	}

	return 0, 0
}

// SizeBytes is the approximate memory of the active filter.
func (m *Manager) SizeBytes() uint64 {
	if l := m.cur.Load(); l != nil {
		return l.Stats().Bytes
	}

	return 0
}

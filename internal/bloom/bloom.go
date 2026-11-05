package bloom

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

const (
	bitsPerItem = 10
	numHashes   = 7
)

type Filter struct {
	bits []uint64
	m    uint64
}

func New(expectedItems uint64) *Filter {
	if expectedItems < 1024 {
		expectedItems = 1024
	}

	words := (expectedItems*bitsPerItem + 63) / 64
	return &Filter{bits: make([]uint64, words), m: words * 64}
}

func (f *Filter) probe(h, i uint64) uint64 {
	h2 := (h>>32 | h<<32) | 1
	return (h + i*h2) % f.m
}

func (f *Filter) Add(h uint64) {
	for i := uint64(0); i < numHashes; i++ {
		pos := f.probe(h, i)
		atomic.OrUint64(&f.bits[pos>>6], 1<<(pos&63))
	}
}

func (f *Filter) Test(h uint64) bool {
	for i := uint64(0); i < numHashes; i++ {
		pos := f.probe(h, i)
		if atomic.LoadUint64(&f.bits[pos>>6])&(1<<(pos&63)) == 0 {
			return false
		}
	}

	return true
}

func (f *Filter) SizeBytes() uint64 { return uint64(len(f.bits)) * 8 }

var ErrRebuilding = errors.New("bloom rebuild already in progress")

type Manager struct {
	cur   atomic.Pointer[Filter]
	items atomic.Uint64

	mu         sync.Mutex
	rebuilding bool
	pending    []uint64
}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Ready() bool { return m.cur.Load() != nil }

func (m *Manager) Items() uint64 { return m.items.Load() }

func (m *Manager) SizeBytes() uint64 {
	if f := m.cur.Load(); f != nil {
		return f.SizeBytes()
	}

	return 0
}

func (m *Manager) Test(h uint64) bool {
	f := m.cur.Load()
	if f == nil {
		return true
	}

	return f.Test(h)
}

func (m *Manager) Add(h uint64) {
	m.mu.Lock()

	if m.rebuilding {
		m.pending = append(m.pending, h)
	}

	m.mu.Unlock()

	if f := m.cur.Load(); f != nil {
		f.Add(h)
	}

	m.items.Add(1)
}

func (m *Manager) Rebuild(ctx context.Context, expectedItems uint64,
	load func(ctx context.Context, emit func(uint64)) error) error {

	m.mu.Lock()

	if m.rebuilding {
		m.mu.Unlock()
		return ErrRebuilding
	}

	m.rebuilding = true
	m.pending = nil
	m.mu.Unlock()

	fresh := New(expectedItems)
	var n uint64
	err := load(ctx, func(h uint64) { fresh.Add(h); n++ })

	m.mu.Lock()
	defer m.mu.Unlock()
	m.rebuilding = false
	pending := m.pending
	m.pending = nil

	if err != nil {
		return err
	}

	for _, h := range pending {
		fresh.Add(h)
	}

	m.cur.Store(fresh)
	m.items.Store(n + uint64(len(pending)))
	return nil
}

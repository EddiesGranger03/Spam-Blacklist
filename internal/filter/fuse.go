// Package filter implements the in-memory membership filter used by the checker:
// an immutable binary fuse filter built from a snapshot of the blacklist, plus small
// mutable layers for changes made after that snapshot (see Layered).
package filter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"slices"
)

// BinaryFuse8 is a static, immutable binary fuse filter with 8-bit fingerprints
// (Graf & Lemire, "Binary Fuse Filters: Fast and Smaller Than Xor Filters", 2022).
// About 9 bits per key, false-positive rate about 1/256 (~0.39%), no false negatives.
// Contains is safe for concurrent use; the filter is never mutated after construction.
type BinaryFuse8 struct {
	Seed               uint64
	SegmentLength      uint32
	SegmentLengthMask  uint32
	SegmentCount       uint32
	SegmentCountLength uint32
	Items              uint64
	Fingerprints       []uint8
}

const fuseArity = 3

// ErrFuseConstruction is returned when the peeling never succeeds (practically only with duplicate keys).
var ErrFuseConstruction = errors.New("binary fuse: construction failed")

// murmur64 is the MurmurHash3 finalizer, used to mix key and seed.
func murmur64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

func splitmix64(seed *uint64) uint64 {
	*seed += 0x9e3779b97f4a7c15
	z := *seed
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func fingerprint(hash uint64) uint8 { return uint8(hash ^ (hash >> 32)) } // #nosec G115 -- truncation is the point

// positions maps a hash to its three slots; they lie in three consecutive segments, so they are always distinct.
func (f *BinaryFuse8) positions(hash uint64) (h0, h1, h2 uint32) {
	hi, _ := bits.Mul64(hash, uint64(f.SegmentCountLength))
	h0 = uint32(hi) // #nosec G115 -- hi < SegmentCountLength (uint32)
	h1 = h0 + f.SegmentLength
	h2 = h1 + f.SegmentLength
	h1 ^= uint32(hash>>18) & f.SegmentLengthMask // #nosec G115 -- masked
	h2 ^= uint32(hash) & f.SegmentLengthMask     // #nosec G115 -- masked
	return
}

func (f *BinaryFuse8) init(size uint32) {
	if size < 2 {
		size = 2
	}

	segLen := uint32(1) << int(math.Floor(math.Log(float64(size))/math.Log(3.33)+2.25))
	if segLen > 262144 {
		segLen = 262144
	}

	factor := math.Max(1.125, 0.875+0.25*math.Log(1e6)/math.Log(float64(size)))
	capacity := uint32(math.Round(float64(size) * factor))
	initSegCount := (capacity+segLen-1)/segLen - (fuseArity - 1)
	arrayLen := (initSegCount + fuseArity - 1) * segLen
	segCount := (arrayLen + segLen - 1) / segLen

	if segCount <= fuseArity-1 {
		segCount = 1
	} else {
		segCount -= fuseArity - 1
	}

	f.SegmentLength = segLen
	f.SegmentLengthMask = segLen - 1
	f.SegmentCount = segCount
	f.SegmentCountLength = segCount * segLen
	f.Fingerprints = make([]uint8, (segCount+fuseArity-1)*segLen)
}

// Contains reports whether key may be in the set (false means definitely not).
func (f *BinaryFuse8) Contains(key uint64) bool {
	if f == nil || len(f.Fingerprints) == 0 {
		return false
	}

	hash := murmur64(key + f.Seed)
	h0, h1, h2 := f.positions(hash)

	return fingerprint(hash)^f.Fingerprints[h0]^f.Fingerprints[h1]^f.Fingerprints[h2] == 0
}

// SizeBytes is the memory held by the fingerprint array.
func (f *BinaryFuse8) SizeBytes() uint64 {
	if f == nil {
		return 0
	}

	return uint64(len(f.Fingerprints))
}

// DedupeSorted sorts keys in place and removes duplicates, returning the shortened slice.
// O(n log n), no extra memory. Binary fuse construction requires unique keys.
func DedupeSorted(keys []uint64) []uint64 {
	slices.Sort(keys)
	return slices.Compact(keys)
}

// BuildBinaryFuse8 builds a filter from UNIQUE keys (call DedupeSorted first; duplicates make
// construction fail). keys is not modified. Construction is O(n) expected time; transient memory is about
// 15 bytes per key on top of keys (counts, xor-hashes, queue and the peel stack).
func BuildBinaryFuse8(keys []uint64) (*BinaryFuse8, error) {
	if len(keys) > math.MaxUint32/2 {
		return nil, fmt.Errorf("binary fuse: too many keys (%d)", len(keys))
	}

	f := &BinaryFuse8{Items: uint64(len(keys))}
	if len(keys) == 0 {
		return f, nil
	}

	size := uint32(len(keys)) // #nosec G115 -- bounded above
	f.init(size)

	arrayLen := uint32(len(f.Fingerprints)) // #nosec G115 -- (segCount+2)*segLen fits uint32
	counts := make([]uint8, arrayLen)
	xors := make([]uint64, arrayLen)
	queue := make([]uint32, 0, 1024)
	stackHash := make([]uint64, 0, size)
	stackIdx := make([]uint32, 0, size)

	rng := uint64(0x726b2b9d438b9d4d)

	for attempt := 0; attempt < 100; attempt++ {
		f.Seed = splitmix64(&rng)
		clear(counts)
		clear(xors)
		stackHash, stackIdx, queue = stackHash[:0], stackIdx[:0], queue[:0]
		overflow := false

		for _, k := range keys {
			hash := murmur64(k + f.Seed)
			h0, h1, h2 := f.positions(hash)

			for _, p := range [3]uint32{h0, h1, h2} {
				if counts[p] == math.MaxUint8 {
					overflow = true
				}
				counts[p]++
				xors[p] ^= hash
			}
		}

		if overflow {
			continue
		}

		for i, c := range counts {
			if c == 1 {
				queue = append(queue, uint32(i)) // #nosec G115 -- i < arrayLen
			}
		}

		for len(queue) > 0 {
			idx := queue[len(queue)-1]
			queue = queue[:len(queue)-1]

			if counts[idx] != 1 {
				continue
			}

			hash := xors[idx]
			stackHash = append(stackHash, hash)
			stackIdx = append(stackIdx, idx)

			h0, h1, h2 := f.positions(hash)
			for _, p := range [3]uint32{h0, h1, h2} {
				counts[p]--
				xors[p] ^= hash

				if p != idx && counts[p] == 1 {
					queue = append(queue, p)
				}
			}
		}

		if uint32(len(stackHash)) == size { // #nosec G115 -- bounded
			break
		}
	}

	if uint32(len(stackHash)) != size { // #nosec G115 -- bounded
		return nil, ErrFuseConstruction
	}

	for i := len(stackHash) - 1; i >= 0; i-- {
		hash, idx := stackHash[i], stackIdx[i]
		h0, h1, h2 := f.positions(hash)
		v := fingerprint(hash) ^ f.Fingerprints[h0] ^ f.Fingerprints[h1] ^ f.Fingerprints[h2]
		// idx's own (still zero) slot contributes nothing to v, so this makes the xor of all three equal the fingerprint.
		f.Fingerprints[idx] = v
	}

	return f, nil
}

const fuseHeaderLen = 8 + 4*4 + 8 + 8

// WriteTo serialises the filter (little-endian header followed by the fingerprints).
func (f *BinaryFuse8) WriteTo(w io.Writer) (int64, error) {
	var hdr [fuseHeaderLen]byte
	binary.LittleEndian.PutUint64(hdr[0:], f.Seed)
	binary.LittleEndian.PutUint32(hdr[8:], f.SegmentLength)
	binary.LittleEndian.PutUint32(hdr[12:], f.SegmentLengthMask)
	binary.LittleEndian.PutUint32(hdr[16:], f.SegmentCount)
	binary.LittleEndian.PutUint32(hdr[20:], f.SegmentCountLength)
	binary.LittleEndian.PutUint64(hdr[24:], f.Items)
	binary.LittleEndian.PutUint64(hdr[32:], uint64(len(f.Fingerprints)))

	n, err := w.Write(hdr[:])
	if err != nil {
		return int64(n), err
	}

	m, err := w.Write(f.Fingerprints)
	return int64(n + m), err
}

// ReadBinaryFuse8 is the inverse of WriteTo; it validates the geometry so a corrupt input cannot cause
// out-of-range reads in Contains.
func ReadBinaryFuse8(r io.Reader, maxBytes uint64) (*BinaryFuse8, error) {
	var hdr [fuseHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}

	f := &BinaryFuse8{
		Seed:               binary.LittleEndian.Uint64(hdr[0:]),
		SegmentLength:      binary.LittleEndian.Uint32(hdr[8:]),
		SegmentLengthMask:  binary.LittleEndian.Uint32(hdr[12:]),
		SegmentCount:       binary.LittleEndian.Uint32(hdr[16:]),
		SegmentCountLength: binary.LittleEndian.Uint32(hdr[20:]),
		Items:              binary.LittleEndian.Uint64(hdr[24:]),
	}
	n := binary.LittleEndian.Uint64(hdr[32:])

	if n > maxBytes {
		return nil, fmt.Errorf("binary fuse: fingerprint array %d bytes exceeds limit %d", n, maxBytes)
	}

	if n > 0 {
		sl := uint64(f.SegmentLength)
		if sl == 0 || sl&(sl-1) != 0 || f.SegmentLengthMask != f.SegmentLength-1 ||
			uint64(f.SegmentCountLength) != uint64(f.SegmentCount)*sl ||
			n != (uint64(f.SegmentCount)+fuseArity-1)*sl {
			return nil, errors.New("binary fuse: inconsistent geometry")
		}
	}

	f.Fingerprints = make([]uint8, n)
	if _, err := io.ReadFull(r, f.Fingerprints); err != nil {
		return nil, err
	}

	return f, nil
}

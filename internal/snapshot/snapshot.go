// Package snapshot persists the static layer of the in-memory filter so pods can start without scanning the
// blacklist table. The storage backend is behind Store (Postgres today; S3 or similar only needs another implementation).
package snapshot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc64"
	"io"
	"time"

	"vsf/internal/filter"
)

// Meta describes one stored snapshot.
type Meta struct {
	ID        int64 // assigned by the store on Save
	Kind      Kind
	Items     uint64
	CursorXID string // change_log cursor (xid8 as text, seq) the snapshot is consistent with
	CursorSeq int64
	SizeBytes int64
	Checksum  uint64 // CRC-64/ECMA of the encoded file (excluding the trailing checksum itself)
	Domain    uint64 // hash domain of the stored value_hash values (see Store.Domain); 0 = written before domains existed
	CreatedAt time.Time
}

// Kind identifies the filter algorithm stored in a snapshot.
type Kind uint8

// KindBinaryFuse8 is the only kind today.
const KindBinaryFuse8 Kind = 1

// PlainDomain is the hash domain of a process running without a sealer (unkeyed value_hash). A keyed domain is
// seal.Sealer.FilterDomain(), derived from DATA_PEPPER.
const PlainDomain uint64 = 0x706c61696e2d7631 // "plain-v1"

// ErrDomainMismatch means a snapshot was built under another hash domain (another DATA_PEPPER, or with/without
// encryption): its fingerprints describe different value_hash values, so installing it would turn every blacklisted
// value into a false negative (finding G1). Such a snapshot is skipped, never flagged corrupt: it is valid, just not ours.
var ErrDomainMismatch = errors.New("snapshot: built under another hash domain (DATA_PEPPER)")

// ErrNoSnapshot is returned by LoadLatest when no complete snapshot exists.
var ErrNoSnapshot = errors.New("snapshot: none available")

// Store persists snapshots. Implementations must make a snapshot visible to LoadLatest only once it is complete.
type Store interface {
	// Domain is the hash domain of this process (which pepper produces value_hash). Save stamps it on new snapshots and
	// the listing/loading methods only return snapshots of this domain.
	Domain() uint64
	// Save stores the encoded snapshot read from r and returns its id.
	Save(ctx context.Context, meta Meta, r io.Reader) (int64, error)
	// LatestID returns the id of the newest usable (complete, not corrupt) snapshot (ErrNoSnapshot if none).
	LatestID(ctx context.Context) (int64, error)
	// LoadLatest opens the newest usable snapshot. The caller must Close the reader.
	LoadLatest(ctx context.Context) (Meta, io.ReadCloser, error)
	// ListUsable returns the ids of usable snapshots, newest first.
	ListUsable(ctx context.Context) ([]int64, error)
	// Load opens one usable snapshot (ErrNoSnapshot if it is gone or flagged corrupt).
	Load(ctx context.Context, id int64) (Meta, io.ReadCloser, error)
	// MarkCorrupt flags a snapshot so that nobody tries it again.
	MarkCorrupt(ctx context.Context, id int64, reason string) error
	// Prune deletes all but the newest keep usable snapshots, plus abandoned incomplete and old corrupt ones.
	Prune(ctx context.Context, keep int) (int64, error)

	// RebuildState / RequestRebuild / MarkRebuildHandled implement the "no usable snapshot, leader please build"
	// protocol (see Syncer). RequestRebuild records at most one pending request.
	RebuildState(ctx context.Context) (requests, handled int64, err error)
	RequestRebuild(ctx context.Context) (recorded bool, err error)
	MarkRebuildHandled(ctx context.Context, upTo int64) error
}

// File format (little-endian):
//
//	magic   [4]byte "VSFF"
//	version uint16  (2; version 1 had no domain field and is decoded with Domain 0, which matches nothing)
//	kind    uint8
//	domain  uint64  hash domain (version 2+)
//	items   uint64
//	xidLen  uint16, xid [xidLen]byte
//	seq     int64
//	payload (filter.BinaryFuse8.WriteTo)
//	crc     uint64  CRC-64/ECMA of every byte before it
var magic = [4]byte{'V', 'S', 'F', 'F'}

const (
	formatVersion = 2
	maxXIDLen     = 32
	// MaxFilterBytes bounds the fingerprint array accepted on decode (8 GiB ≈ 7 billion items).
	MaxFilterBytes = 8 << 30
)

var crcTable = crc64.MakeTable(crc64.ECMA)

// ErrCorrupt means the stored snapshot cannot be decoded (truncated, missing chunk, wrong header/cursor). Distinct from
// transient errors (database or network), which must never cause a snapshot to be flagged.
var ErrCorrupt = errors.New("snapshot: corrupt")

// ErrChecksum means the snapshot bytes were corrupted.
var ErrChecksum = errors.New("snapshot: checksum mismatch")

// Encode writes f with the cursor header and trailing checksum, returning the checksum and size written.
func Encode(w io.Writer, f *filter.BinaryFuse8, domain uint64, xid string, seq int64) (sum uint64, size int64, err error) {
	if len(xid) > maxXIDLen {
		return 0, 0, fmt.Errorf("snapshot: xid too long")
	}

	h := crc64.New(crcTable)
	cw := &countWriter{w: io.MultiWriter(w, h)}
	bw := bufio.NewWriterSize(cw, 1<<20)

	var hdr bytes.Buffer
	hdr.Write(magic[:])
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(formatVersion))
	hdr.WriteByte(byte(KindBinaryFuse8))
	_ = binary.Write(&hdr, binary.LittleEndian, domain)
	_ = binary.Write(&hdr, binary.LittleEndian, f.Items)
	_ = binary.Write(&hdr, binary.LittleEndian, uint16(len(xid))) // #nosec G115 -- bounded above
	hdr.WriteString(xid)
	_ = binary.Write(&hdr, binary.LittleEndian, seq)

	if _, err := bw.Write(hdr.Bytes()); err != nil {
		return 0, 0, err
	}

	if _, err := f.WriteTo(bw); err != nil {
		return 0, 0, err
	}

	if err := bw.Flush(); err != nil {
		return 0, 0, err
	}

	sum = h.Sum64()

	var tail [8]byte
	binary.LittleEndian.PutUint64(tail[:], sum)
	if _, err := w.Write(tail[:]); err != nil {
		return 0, 0, err
	}

	return sum, cw.n + 8, nil
}

// Decoded is the content of a snapshot file.
type Decoded struct {
	Filter    *filter.BinaryFuse8
	Kind      Kind
	Domain    uint64 // 0 for a version-1 file
	CursorXID string
	CursorSeq int64
	Checksum  uint64
}

// Decode reads and verifies a snapshot. The checksum covers the whole file and is verified before the result is
// returned, so a corrupted or truncated snapshot is never used.
func Decode(r io.Reader) (*Decoded, error) {
	t := &errTracker{r: r}

	d, err := decode(t)
	if err == nil || errors.Is(err, ErrChecksum) {
		return d, err
	}

	if t.err != nil {
		return nil, err // the source itself failed (database, network): transient, says nothing about the snapshot
	}

	return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
}

// errTracker remembers a non-EOF error returned by the underlying reader, to tell "the bytes are bad" from "reading failed".
type errTracker struct {
	r   io.Reader
	err error
}

func (t *errTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF && !errors.Is(err, ErrCorrupt) {
		t.err = err
	}

	return n, err
}

func decode(r io.Reader) (*Decoded, error) {
	h := crc64.New(crcTable)
	br := bufio.NewReaderSize(r, 1<<20)
	tr := io.TeeReader(br, h)

	var m [4]byte
	if _, err := io.ReadFull(tr, m[:]); err != nil {
		return nil, fmt.Errorf("snapshot: header: %w", err)
	}

	if m != magic {
		return nil, errors.New("snapshot: bad magic")
	}

	var ver uint16
	var kind uint8
	var items uint64
	var xlen uint16

	for _, v := range []any{&ver, &kind} {
		if err := binary.Read(tr, binary.LittleEndian, v); err != nil {
			return nil, fmt.Errorf("snapshot: header: %w", err)
		}
	}

	if ver != 1 && ver != formatVersion {
		return nil, fmt.Errorf("snapshot: unsupported version %d", ver)
	}

	if Kind(kind) != KindBinaryFuse8 {
		return nil, fmt.Errorf("snapshot: unsupported kind %d", kind)
	}

	var domain uint64
	if ver >= 2 {
		if err := binary.Read(tr, binary.LittleEndian, &domain); err != nil {
			return nil, fmt.Errorf("snapshot: header: %w", err)
		}
	}

	for _, v := range []any{&items, &xlen} {
		if err := binary.Read(tr, binary.LittleEndian, v); err != nil {
			return nil, fmt.Errorf("snapshot: header: %w", err)
		}
	}

	if xlen > maxXIDLen {
		return nil, errors.New("snapshot: bad xid length")
	}

	xid := make([]byte, xlen)
	if _, err := io.ReadFull(tr, xid); err != nil {
		return nil, err
	}

	var seq int64
	if err := binary.Read(tr, binary.LittleEndian, &seq); err != nil {
		return nil, err
	}

	f, err := filter.ReadBinaryFuse8(tr, MaxFilterBytes)
	if err != nil {
		return nil, fmt.Errorf("snapshot: payload: %w", err)
	}

	want := h.Sum64()

	var tail [8]byte
	if _, err := io.ReadFull(br, tail[:]); err != nil {
		return nil, fmt.Errorf("snapshot: trailer: %w", err)
	}

	if binary.LittleEndian.Uint64(tail[:]) != want {
		return nil, ErrChecksum
	}

	if n, _ := br.Read(tail[:1]); n != 0 {
		return nil, errors.New("snapshot: trailing data")
	}

	if f.Items != items {
		return nil, errors.New("snapshot: item count mismatch")
	}

	return &Decoded{Filter: f, Kind: Kind(kind), Domain: domain, CursorXID: string(xid), CursorSeq: seq, Checksum: want}, nil
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

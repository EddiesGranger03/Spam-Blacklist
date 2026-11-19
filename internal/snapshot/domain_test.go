package snapshot

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc64"
	"testing"
	"time"
)

// A version-1 file (no domain field) still decodes, with Domain 0: it is readable but never matches a real domain.
func TestDecodeVersion1HasNoDomain(t *testing.T) {
	f := build(t, keys(1000, 7))

	var buf bytes.Buffer
	if _, _, err := Encode(&buf, f, 0xabcdef, "5", 3); err != nil {
		t.Fatal(err)
	}

	v2 := buf.Bytes()
	if d, err := Decode(bytes.NewReader(v2)); err != nil || d.Domain != 0xabcdef {
		t.Fatalf("v2 decode: %+v %v", d, err)
	}

	// Rebuild the same file as version 1: drop the 8 domain bytes after kind (offset 7), fix version and checksum.
	body := append(bytes.Clone(v2[:7]), v2[15:len(v2)-8]...)
	binary.LittleEndian.PutUint16(body[4:6], 1)
	v1 := binary.LittleEndian.AppendUint64(body, crc64.Checksum(body, crcTable))

	d, err := Decode(bytes.NewReader(v1))
	if err != nil {
		t.Fatal(err)
	}

	if d.Domain != 0 || d.CursorXID != "5" || d.CursorSeq != 3 || d.Filter.Items != f.Items {
		t.Fatalf("v1 decode: %+v", d)
	}
}

// G1: after a pepper rotation the stored snapshot (old domain) must be skipped, not flagged corrupt, not installed;
// a non-leader asks for a rebuild and the leader builds one under the new domain.
func TestForeignDomainSnapshotSkippedAndRebuilt(t *testing.T) {
	ctx := context.Background()
	st := &memStore{domain: 0x1111}
	db := newFakeFeed(10, 20, 30)
	free := true

	if err := NewSyncer(st, db, &fakeLeader{free: new(bool)}, quiet(), Config{}).BuildAndPublish(ctx); err != nil {
		t.Fatal(err)
	}

	st.domain = 0x2222 // processes now run with another DATA_PEPPER

	pod := newFakeFeed(10, 20, 30)
	follower := NewSyncer(st, pod, &fakeLeader{free: new(bool)}, quiet(), Config{})

	if ok, err := follower.LoadNewer(ctx); ok || !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("foreign snapshot: ok=%v err=%v (want ErrNoSnapshot)", ok, err)
	}

	if pod.m.Source().SnapshotID != 0 || st.snaps[0].corrupt {
		t.Fatalf("foreign snapshot installed=%d corrupt=%v", pod.m.Source().SnapshotID, st.snaps[0].corrupt)
	}

	// Non-leader at startup records a rebuild request instead of using it.
	bctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	_ = NewSyncer(st, pod, &fakeLeader{free: new(bool)}, quiet(), Config{PollEvery: 5 * time.Millisecond}).Bootstrap(bctx)
	cancel()

	if st.requests == 0 {
		t.Fatal("non-leader must request a rebuild when no snapshot of its domain exists")
	}

	leaderFeed := newFakeFeed(10, 20, 30)
	if err := NewSyncer(st, leaderFeed, &fakeLeader{free: &free}, quiet(), Config{}).Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}

	if leaderFeed.scans != 1 || len(st.snaps) != 2 || st.snaps[1].meta.Domain != 0x2222 {
		t.Fatalf("leader must rebuild under the new domain: scans=%d snaps=%d", leaderFeed.scans, len(st.snaps))
	}

	if ok, err := follower.LoadNewer(ctx); !ok || err != nil || pod.m.Source().SnapshotID != 2 {
		t.Fatalf("follower must install the new-domain snapshot: ok=%v err=%v id=%d", ok, err, pod.m.Source().SnapshotID)
	}
}

// Metadata claims our domain but the file was built under another: refused by the header check, not flagged corrupt.
func TestFileDomainMismatchRefused(t *testing.T) {
	ctx := context.Background()
	st := &memStore{domain: 0x1111}

	if err := NewSyncer(st, newFakeFeed(1, 2), &fakeLeader{free: new(bool)}, quiet(), Config{}).BuildAndPublish(ctx); err != nil {
		t.Fatal(err)
	}

	st.domain = 0x2222
	st.snaps[0].meta.Domain = 0x2222

	pod := newFakeFeed(1, 2)
	err := NewSyncer(st, pod, &fakeLeader{free: new(bool)}, quiet(), Config{}).tryLoad(ctx, 1)
	if !errors.Is(err, ErrDomainMismatch) || pod.m.Source().SnapshotID != 0 || st.snaps[0].corrupt {
		t.Fatalf("err=%v installed=%d corrupt=%v", err, pod.m.Source().SnapshotID, st.snaps[0].corrupt)
	}
}

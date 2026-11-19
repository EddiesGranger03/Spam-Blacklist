package changefeed

import (
	"context"
	"testing"

	"vsf/internal/filter"
	"vsf/internal/model"
)

func push(src *fakeSource, cs ...model.Change) {
	src.mu.Lock()
	src.changes = append(src.changes, cs...)
	src.mu.Unlock()
}

func TestOpRemoveRoutesToRemovedSetAndReAddRestores(t *testing.T) {
	src := &fakeSource{all: []int64{10, 20}}
	f, m := newFeed(t, src)
	ctx := context.Background()

	push(src, model.Change{Seq: 1, XID: "5", Hash: 10, Op: OpRemove}, model.Change{Seq: 2, XID: "6", Hash: 30, Op: OpAdd})
	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if m.Test(10) || !m.Test(20) || !m.Test(30) {
		t.Fatal("op=2 must remove from static, op=1 must add")
	}

	push(src, model.Change{Seq: 3, XID: "7", Hash: 10, Op: OpAdd})
	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if !m.Test(10) {
		t.Fatal("re-added hash must be present again")
	}

	if s := m.Current().Stats(); s.Removed != 0 {
		t.Fatalf("re-add must clear the removed-set: %+v", s)
	}
}

// A pending removal is deferred until it is safe; a pending add right after a safe removal (lower xid) of the same
// hash must still win when it is re-read.
func TestPendingRemovalDeferredAndOrderKept(t *testing.T) {
	src := &fakeSource{all: []int64{10}}
	f, m := newFeed(t, src)
	ctx := context.Background()

	push(src, model.Change{Seq: 1, XID: "5", Hash: 10, Op: OpRemove, Pending: true})
	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if !m.Test(10) {
		t.Fatal("pending removal must not be applied yet (could cause a false negative)")
	}

	// It becomes safe.
	src.mu.Lock()
	src.changes[0].Pending = false
	src.mu.Unlock()

	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if m.Test(10) {
		t.Fatal("safe removal must be applied")
	}

	// Pending add of 40 first (seen in this poll), then a lower-xid removal of 40 commits late and the add stays pending:
	// order by xid is remove(xid 8) then add(xid 9) → present.
	push(src, model.Change{Seq: 3, XID: "9", Hash: 40, Op: OpAdd, Pending: true})
	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	src.mu.Lock()
	src.changes = append(src.changes[:1], model.Change{Seq: 2, XID: "8", Hash: 40, Op: OpRemove}, src.changes[1])
	src.mu.Unlock()

	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if !m.Test(40) {
		t.Fatal("a re-read pending add after a late removal must be re-applied (false negative otherwise)")
	}
}

// Install replays only changes after the snapshot cursor into the new filter, then swaps.
func TestInstallReplaysAfterCursor(t *testing.T) {
	src := &fakeSource{}
	push(src,
		model.Change{Seq: 1, XID: "1", Hash: 1, Op: OpAdd},
		model.Change{Seq: 2, XID: "2", Hash: 2, Op: OpAdd},
		model.Change{Seq: 3, XID: "3", Hash: 1, Op: OpRemove},
		model.Change{Seq: 4, XID: "4", Hash: 4, Op: OpAdd},
	)

	m := filter.NewManager()
	f := New(src, m, quiet())

	// Snapshot taken at cursor (2, 2): contains 1 and 2.
	static, err := filter.BuildBinaryFuse8([]uint64{1, 2})
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Install(context.Background(), filter.NewLayered(static, 0), filter.Source{SnapshotID: 9, CursorXID: "2", CursorSeq: 2}); err != nil {
		t.Fatal(err)
	}

	if m.Test(1) || !m.Test(2) || !m.Test(4) {
		t.Fatal("replay after cursor wrong")
	}

	if s := m.Current().Stats(); s.DeltaItems != 1 || s.Removed != 1 {
		t.Fatalf("only changes after the cursor may be in delta/removed: %+v", s)
	}

	if x, s := cursorOf(f); x != "4" || s != 4 {
		t.Fatalf("cursor = %s.%d", x, s)
	}

	if f.Epoch() != "4.4" {
		t.Fatalf("epoch %q", f.Epoch())
	}
}

func TestSyncNowBeforeReadyDoesNothing(t *testing.T) {
	src := &fakeSource{}
	push(src, model.Change{Seq: 1, XID: "1", Hash: 1})
	f := New(src, filter.NewManager(), quiet())

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if x, s := cursorOf(f); x != "0" || s != 0 {
		t.Fatal("cursor must not move before a filter is installed (changes would be lost)")
	}
}

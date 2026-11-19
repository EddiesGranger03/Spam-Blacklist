package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// lastOps trả về các dòng change_log (hash, op) có seq > afterSeq, theo thứ tự seq.
func lastOps(t *testing.T, s *Store, afterSeq int64) []model.Change {
	t.Helper()

	rows, err := s.write.Query(context.Background(),
		`SELECT seq, value_hash, op FROM change_log WHERE seq > $1 ORDER BY seq`, afterSeq)
	if err != nil {
		t.Fatal(err)
	}

	defer rows.Close()

	var out []model.Change

	for rows.Next() {
		var c model.Change
		if err := rows.Scan(&c.Seq, &c.Hash, &c.Op); err != nil {
			t.Fatal(err)
		}

		out = append(out, c)
	}

	return out
}

func maxSeq(t *testing.T, s *Store) int64 {
	t.Helper()

	var n int64
	if err := s.write.QueryRow(context.Background(), `SELECT COALESCE(max(seq),0) FROM change_log`).Scan(&n); err != nil {
		t.Fatal(err)
	}

	return n
}

// TestStatusTransitionsLogCorrectOps kiểm tra op ghi vào change_log cho create / đổi status / delete.
func TestStatusTransitionsLogCorrectOps(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	k := mustKey(t, normalize.TypePhone, "", "0905111001")
	in := model.EntryInput{Category: "spam", RiskScore: 10}

	step := func(name string, fn func(), want int16) {
		t.Helper()

		before := maxSeq(t, s)
		fn()

		ops := lastOps(t, s, before)
		if len(ops) != 1 || ops[0].Op != want || ops[0].Hash != k.Hash {
			t.Fatalf("%s: change_log = %+v, want one row hash=%d op=%d", name, ops, k.Hash, want)
		}
	}

	var e model.Entry

	step("create BLACKLIST", func() {
		var err error
		if e, err = s.CreateEntry(ctx, k, in, actor); err != nil || e.Status != model.StatusBlacklist {
			t.Fatalf("%+v %v", e, err)
		}
	}, model.OpAdd)

	toWL := in
	toWL.Status = model.StatusWhitelist

	step("BLACKLIST->WHITELIST", func() {
		got, err := s.UpdateEntry(ctx, e.ID, toWL, actor)
		if err != nil || got.Status != model.StatusWhitelist {
			t.Fatalf("%+v %v", got, err)
		}
	}, model.OpRemove)

	toBL := in
	toBL.Status = model.StatusBlacklist

	step("WHITELIST->BLACKLIST", func() {
		got, err := s.UpdateEntry(ctx, e.ID, toBL, actor)
		if err != nil || got.Status != model.StatusBlacklist {
			t.Fatalf("%+v %v", got, err)
		}
	}, model.OpAdd)

	step("update with empty status keeps status", func() {
		got, err := s.UpdateEntry(ctx, e.ID, in, actor)
		if err != nil || got.Status != model.StatusBlacklist {
			t.Fatalf("%+v %v", got, err)
		}
	}, model.OpAdd)

	step("delete", func() {
		if err := s.DeleteEntry(ctx, e.ID, actor); err != nil {
			t.Fatal(err)
		}
	}, model.OpRemove)

	// Create WHITELIST: không thêm vào filter (op remove) nhưng vẫn có dòng để epoch đổi.
	k2 := mustKey(t, normalize.TypePhone, "", "0905111002")
	before := maxSeq(t, s)

	if _, err := s.CreateEntry(ctx, k2, toWL, actor); err != nil {
		t.Fatal(err)
	}

	if ops := lastOps(t, s, before); len(ops) != 1 || ops[0].Op != model.OpRemove || ops[0].Hash != k2.Hash {
		t.Fatalf("create WHITELIST: %+v", ops)
	}

	n := 0
	if err := s.AllHashes(ctx, func(uint64) { n++ }); err != nil || n != 0 {
		t.Fatalf("AllHashes must skip WHITELIST rows: n=%d err=%v", n, err)
	}

	bad := in
	bad.Status = "MAYBE"

	if _, err := s.UpdateEntry(ctx, 1, bad, actor); !errors.Is(err, normalize.ErrInvalid) {
		t.Fatalf("invalid status: %v", err)
	}

	if _, err := s.CreateEntry(ctx, mustKey(t, normalize.TypePhone, "", "0905111003"), bad, actor); !errors.Is(err, normalize.ErrInvalid) {
		t.Fatalf("invalid status on create: %v", err)
	}

	// ListEntries lọc theo status.
	wl, _, err := s.ListEntries(ctx, ListFilter{Status: model.StatusWhitelist})
	if err != nil || len(wl) != 1 || wl[0].Status != model.StatusWhitelist {
		t.Fatalf("list WHITELIST = %+v %v", wl, err)
	}

	if bl, _, err := s.ListEntries(ctx, ListFilter{Status: model.StatusBlacklist}); err != nil || len(bl) != 0 {
		t.Fatalf("list BLACKLIST = %+v %v", bl, err)
	}
}

// TestUpdateEntryKeyMovesRow kiểm tra đổi giá trị: id giữ nguyên, dòng chuyển partition, change_log 2 dòng, trùng -> ErrDuplicate.
func TestUpdateEntryKeyMovesRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := model.EntryInput{Category: "scam", RiskScore: 60, Note: "keep me"}

	partOf := func(id int64) string {
		var p string
		if err := s.write.QueryRow(ctx, `SELECT tableoid::regclass::text FROM blacklist_entries WHERE id=$1`, id).Scan(&p); err != nil {
			t.Fatal(err)
		}

		return p
	}

	curK := mustKey(t, normalize.TypePhone, "", "0905222001")

	e, err := s.CreateEntry(ctx, curK, in, actor)
	if err != nil {
		t.Fatal(err)
	}

	// Đổi giá trị liên tục cho tới khi dòng thật sự nhảy sang partition khác (32 partition nên chỉ vài lần).
	var (
		moved bool
		ops   []model.Change
		oldK  normalize.Key
		newK  normalize.Key
	)

	for i := 0; i < 100 && !moved; i++ {
		oldK = curK
		newK = mustKey(t, normalize.TypePhone, "", fmt.Sprintf("09052230%02d", i))
		oldPart := partOf(e.ID)
		before := maxSeq(t, s)

		got, err := s.UpdateEntryKey(ctx, e.ID, in, &newK, actor)
		if err != nil {
			t.Fatal(err)
		}

		if got.ID != e.ID || got.Value != newK.Value || got.Note != "keep me" || got.CreatedBy != e.CreatedBy || !got.CreatedAt.Equal(e.CreatedAt) {
			t.Fatalf("moved entry = %+v (orig %+v)", got, e)
		}

		curK = newK
		ops = lastOps(t, s, before)
		moved = partOf(e.ID) != oldPart
	}

	if !moved {
		t.Fatal("row never changed partition after 100 value changes")
	}

	if len(ops) != 2 || ops[0].Hash != oldK.Hash || ops[0].Op != model.OpRemove || ops[1].Hash != newK.Hash || ops[1].Op != model.OpAdd {
		t.Fatalf("change_log = %+v, want remove(old hash)+add(new hash)", ops)
	}

	if m, err := s.FindMatches(ctx, []normalize.Key{oldK}); err != nil || len(m) != 0 {
		t.Fatalf("old value must be gone: %+v %v", m, err)
	}

	if m, err := s.FindMatches(ctx, []normalize.Key{newK}); err != nil || len(m) != 1 || m[0].ID != e.ID {
		t.Fatalf("new value must match with the same id: %+v %v", m, err)
	}

	// Đổi cả value và status sang WHITELIST: hash mới cũng op remove.
	third := mustKey(t, normalize.TypePhone, "", "0905225999")
	toWL := in
	toWL.Status = model.StatusWhitelist
	before := maxSeq(t, s)

	if _, err := s.UpdateEntryKey(ctx, e.ID, toWL, &third, actor); err != nil {
		t.Fatal(err)
	}

	ops = lastOps(t, s, before)
	if len(ops) != 2 || ops[0].Op != model.OpRemove || ops[1].Op != model.OpRemove || ops[1].Hash != third.Hash {
		t.Fatalf("change_log (value + WHITELIST) = %+v", ops)
	}

	// Trùng entry khác -> ErrDuplicate; dòng cũ và change_log không đổi.
	other := mustKey(t, normalize.TypePhone, "", "0905226001")
	if _, err := s.CreateEntry(ctx, other, in, actor); err != nil {
		t.Fatal(err)
	}

	before = maxSeq(t, s)

	if _, err := s.UpdateEntryKey(ctx, e.ID, in, &other, actor); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}

	if cur, err := s.GetEntry(ctx, e.ID); err != nil || cur.Value != third.Value || cur.Status != model.StatusWhitelist {
		t.Fatalf("entry changed after a failed move: %+v %v", cur, err)
	}

	if ops := lastOps(t, s, before); len(ops) != 0 {
		t.Fatalf("failed move must not write change_log: %+v", ops)
	}

	// Không cho đổi type.
	urlKey := mustKey(t, normalize.TypeURL, normalize.MatchDomain, "evil.com")
	if _, err := s.UpdateEntryKey(ctx, e.ID, in, &urlKey, actor); !errors.Is(err, normalize.ErrInvalid) {
		t.Fatalf("type change must be rejected: %v", err)
	}
}

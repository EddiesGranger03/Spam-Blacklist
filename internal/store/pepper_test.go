package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// seedPhones tạo n entry phone dưới pepper hiện tại của store và trả về các số đã tạo.
func seedPhones(t *testing.T, s *Store, n int) []string {
	t.Helper()

	var phones []string

	for i := 0; i < n; i++ {
		raw := "09" + strings.Repeat("0", 2) + string(rune('0'+i/100%10)) + string(rune('0'+i/10%10)) + string(rune('0'+i%10)) + "111"
		if _, err := s.CreateEntry(context.Background(), mustKey(t, normalize.TypePhone, "", raw),
			model.EntryInput{Category: "spam", RiskScore: 50, Note: "n", Source: "s"}, actor); err != nil {
			t.Fatal(err)
		}

		phones = append(phones, raw)
	}

	return phones
}

// matches cho biết số điện thoại có khớp với entry trong store hay không (qua tra cứu thật).
func matches(t *testing.T, s *Store, phone string) bool {
	t.Helper()

	_, cands, err := normalize.Candidates(normalize.TypePhone, phone, "VN")
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.FindMatches(context.Background(), cands)
	if err != nil {
		t.Fatal(err)
	}

	return len(got) > 0
}

// TestRotatePepperMakesRowsFindableUnderTheNewPepper kiểm tra sau khi xoay, dòng vẫn tìm được bằng pepper mới.
func TestRotatePepperMakesRowsFindableUnderTheNewPepper(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := s.sealer

	phones := seedPhones(t, s, 40)

	for _, p := range phones {
		if !matches(t, s, p) {
			t.Fatalf("%s must match under the old pepper before rotating", p)
		}
	}

	var hashBefore int64
	if err := s.write.QueryRow(ctx, `SELECT value_hash FROM blacklist_entries ORDER BY id LIMIT 1`).Scan(&hashBefore); err != nil {
		t.Fatal(err)
	}

	s.SetSealer(sealerOf(t, keyA, 1, otherPeper, nil)) // the operator now configures the NEW pepper

	if matches(t, s, phones[0]) {
		t.Fatal("before the rotation the new pepper must NOT find old rows (this is why servers have to be stopped)")
	}

	// dry run: counts, writes nothing
	dry, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: old.Blind, DryRun: true, Batch: 7})
	if err != nil || dry.Rewritten != 40 || dry.Scanned != 40 {
		t.Fatalf("dry run: %+v %v", dry, err)
	}

	if matches(t, s, phones[0]) {
		t.Fatal("a dry run must not change anything")
	}

	res, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: old.Blind, Batch: 7}) // small batches
	if err != nil || res.Rewritten != 40 || res.Skipped != 0 {
		t.Fatalf("rotate: %+v %v", res, err)
	}

	for _, p := range phones {
		if !matches(t, s, p) {
			t.Fatalf("%s must match under the new pepper after rotating", p)
		}
	}

	var hashAfter int64
	if err := s.write.QueryRow(ctx, `SELECT value_hash FROM blacklist_entries ORDER BY id LIMIT 1`).Scan(&hashAfter); err != nil {
		t.Fatal(err)
	}

	if hashAfter == hashBefore {
		t.Fatal("value_hash must change with the pepper")
	}

	// pepper cũ không còn tìm thấy chúng nữa
	s.SetSealer(old)

	if matches(t, s, phones[0]) {
		t.Fatal("after the rotation the OLD pepper must no longer match")
	}

	// bản thân dữ liệu không đổi: vẫn giải mã ra cùng bản rõ
	s.SetSealer(sealerOf(t, keyA, 1, otherPeper, nil))

	list, err := s.ExportBatch(ctx, "", 0, 100)
	if err != nil || len(list) != 40 || list[0].Note != "n" || list[0].Source != "s" {
		t.Fatalf("content changed: %d rows, err=%v, first=%+v", len(list), err, list[0])
	}

	// kiểm tra khóa mà server chạy lúc khởi động vẫn qua với pepper mới
	if _, err := s.VerifyKeys(ctx); err != nil {
		t.Fatalf("VerifyKeys after rotation: %v", err)
	}
}

// TestRotatePepperIsResumableAndIdempotent kiểm tra xoay pepper chạy tiếp được sau khi bị ngắt, và chạy lại là no-op.
func TestRotatePepperIsResumableAndIdempotent(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := s.sealer

	seedPhones(t, s, 25)
	s.SetSealer(sealerOf(t, keyA, 1, otherPeper, nil))

	// mô phỏng bị ngắt sau lô đầu: dừng bằng context đã hủy sau 1 lô
	cctx, cancel := context.WithCancel(ctx)
	_, err := s.RotatePepper(cctx, actor, PepperRotateOptions{OldBlind: old.Blind, Batch: 10,
		Progress: func(r PepperRotateResult) {
			if r.Batches == 1 {
				cancel()
			}
		}})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}

	again, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: old.Blind, Batch: 10})
	if err != nil || again.Rewritten != 15 || again.AlreadyNew != 10 {
		t.Fatalf("resume must finish the remaining 15 and skip the 10 done: %+v %v", again, err)
	}

	third, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: old.Blind})
	if err != nil || third.Rewritten != 0 || third.AlreadyNew != 25 {
		t.Fatalf("a finished rotation must be a no-op: %+v %v", third, err)
	}
}

// TestRotatePepperRejectsAWrongOldPepper kiểm tra từ chối chạy khi pepper cũ cấu hình sai.
func TestRotatePepperRejectsAWrongOldPepper(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedPhones(t, s, 5)
	s.SetSealer(sealerOf(t, keyA, 1, otherPeper, nil))

	wrong := sealerOf(t, keyA, 1, "wrong-pepper-wrong-pepper-wrong-pepper-00", nil)

	_, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: wrong.Blind})
	if err == nil || !strings.Contains(err.Error(), "neither the old nor the new") {
		t.Fatalf("want a clear error for a wrong old pepper, got %v", err)
	}

	var n int
	if err := s.write.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries`).Scan(&n); err != nil || n != 5 {
		t.Fatalf("rows must be untouched: %d %v", n, err)
	}
}

// TestRotatePepperIsAudited kiểm tra việc xoay pepper được ghi audit đầy đủ.
func TestRotatePepperIsAudited(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	old := s.sealer

	seedPhones(t, s, 3)
	s.SetSealer(sealerOf(t, keyA, 1, otherPeper, nil))

	if _, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: old.Blind}); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := s.write.QueryRow(ctx, `SELECT count(*) FROM audit_logs WHERE action IN ('entry.pepper_rotate.start','entry.pepper_rotate')`).
		Scan(&n); err != nil || n != 2 {
		t.Fatalf("want a start and an end audit row, got %d (%v)", n, err)
	}
}

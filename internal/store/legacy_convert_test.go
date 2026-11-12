package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// seedLegacy tạo lại bảng ở bố cục plaintext cũ và nạp n dòng phone (id 1..n).
func seedLegacy(t *testing.T, s *Store, n int) {
	t.Helper()

	ctx := context.Background()

	if _, err := s.write.Exec(ctx, legacySchema); err != nil {
		t.Fatal(err)
	}

	if _, err := s.write.Exec(ctx, `INSERT INTO blacklist_entries (type, match_type, value_normalized, value_hash, note, source, created_by)
		SELECT 'phone', 'exact', '+8490' || lpad(i::text, 7, '0'), i * 7919, 'note ' || i, 'src ' || i, 'old-admin'
		FROM generate_series(1, $1) AS i`, n); err != nil {
		t.Fatal(err)
	}
}

// Bảng đủ lớn để bước xác minh lấy mẫu (id chia hết cho 997) thật sự chạy; dữ liệu giữ nguyên, sequence tiếp tục,
// dòng audit đã nối chuỗi hash được giữ nguyên còn dòng cũ chưa nối chuỗi bị xóa bản rõ.
func TestConvertLegacyLargeTableVerifiesSample(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacy(t, s, 2100)

	if _, err := s.write.Exec(ctx, `INSERT INTO audit_logs(actor_email, action, detail)
		VALUES ('a@x.io','entry.create','{"after":{"value":"+84900000001","note":"secret note","source":"src","id":1}}')`); err != nil {
		t.Fatal(err)
	}

	s.SetAuditKey(AuditKeyFrom("", "legacy-convert-test-secret-0123456789")) // bật chuỗi hash cho dòng audit mới

	if err := s.WriteAudit(ctx, actor, "entry.create", map[string]any{"after": map[string]any{"value": "+84900000002"}}); err != nil {
		t.Fatal(err)
	}

	var chainedBefore string
	if err := s.write.QueryRow(ctx, `SELECT detail::text || encode(entry_hash, 'hex') FROM audit_logs WHERE entry_hash IS NOT NULL AND action='entry.create'
		ORDER BY id LIMIT 1`).Scan(&chainedBefore); err != nil {
		t.Fatalf("the chained audit row must exist before the conversion: %v", err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("convert: %v", err)
	}

	var n, maxID int64
	if err := s.write.QueryRow(ctx, `SELECT count(*), max(id) FROM blacklist_entries`).Scan(&n, &maxID); err != nil || n != 2100 || maxID != 2100 {
		t.Fatalf("rows after convert: %d (max id %d) %v", n, maxID, err)
	}

	list, _, err := s.ListEntries(ctx, ListFilter{Asc: true, Limit: 5})
	if err != nil || len(list) != 5 || list[0].Value != "+84900000001" {
		t.Fatalf("first rows: %+v %v", list, err)
	}

	// các dòng nằm trong mẫu xác minh vẫn đọc đúng sau khi chuyển
	for _, id := range []int64{997, 1994} {
		var e model.Entry
		if err := s.write.QueryRow(ctx, `SELECT id FROM blacklist_entries WHERE id = $1`, id).Scan(&e.ID); err != nil {
			t.Fatalf("row %d missing: %v", id, err)
		}
	}

	e, err := s.CreateEntry(ctx, mustKey(t, normalize.TypePhone, normalize.MatchExact, "0933333333"), model.EntryInput{Category: "spam", RiskScore: 1}, actor)
	if err != nil || e.ID <= 2100 {
		t.Fatalf("the sequence must continue after the old ids: %+v %v", e, err)
	}

	var raw, chainedAfter string
	if err := s.write.QueryRow(ctx, `SELECT detail::text FROM audit_logs WHERE actor_email='a@x.io'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(raw, "84900000001") || strings.Contains(raw, "secret note") {
		t.Errorf("a legacy audit row must lose its plaintext: %s", raw)
	}

	if err := s.write.QueryRow(ctx, `SELECT detail::text || encode(entry_hash, 'hex') FROM audit_logs WHERE entry_hash IS NOT NULL AND action='entry.create'
		ORDER BY id LIMIT 1`).Scan(&chainedAfter); err != nil || chainedAfter != chainedBefore {
		t.Errorf("a hash-chained audit row must stay untouched (editing it would break the chain): %q vs %q %v", chainedBefore, chainedAfter, err)
	}
}

// Chưa có khóa mã hóa thì không được chuyển (sẽ không thể đọc lại), và bảng cũ còn nguyên.
func TestConvertLegacyWithoutSealerIsRefused(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacy(t, s, 3)

	sl := s.sealer
	s.sealer = nil

	t.Cleanup(func() { s.sealer = sl })

	if err := s.convertToSealed(ctx); !errors.Is(err, errNoSealer) {
		t.Fatalf("want errNoSealer, got %v", err)
	}

	var legacy bool
	if err := s.write.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name='blacklist_entries' AND column_name='value_normalized')`).Scan(&legacy); err != nil || !legacy {
		t.Fatalf("the plaintext table must be untouched: %v %v", legacy, err)
	}

	// khôi phục khóa rồi chuyển được bình thường
	s.sealer = sl

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate once the key is configured: %v", err)
	}
}

// Một dòng không chuyển được thì toàn bộ rollback: bảng plaintext còn nguyên, không để lại bảng dở dang.
func TestConvertLegacyRollsBackOnABadRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacy(t, s, 5)

	// 'fax' vi phạm CHECK của bảng mới; bảng cũ không có ràng buộc đó
	if _, err := s.write.Exec(ctx, `INSERT INTO blacklist_entries (type, match_type, value_normalized, value_hash)
		VALUES ('fax', 'exact', 'x', 1)`); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _, _ = s.write.Exec(context.Background(), `DELETE FROM blacklist_entries WHERE type = 'fax'`) })

	if err := s.Migrate(ctx); err == nil {
		t.Fatal("a row the sealed table rejects must fail the migration")
	}

	var rows int
	if err := s.write.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries`).Scan(&rows); err != nil || rows != 6 {
		t.Fatalf("the plaintext rows must all still be there: %d %v", rows, err)
	}

	var leftover bool
	if err := s.write.QueryRow(ctx, `SELECT to_regclass('blacklist_entries_v2') IS NOT NULL`).Scan(&leftover); err != nil || leftover {
		t.Fatalf("no half-built table may remain: %v %v", leftover, err)
	}
}

// verifySealed phải bắt được bản sao không khớp bản rõ (số dòng lệch, hoặc nội dung lệch).
func TestVerifySealedCatchesMismatches(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	seedLegacy(t, s, 1000) // có id 997 nằm trong mẫu

	run := func(mutate string) error {
		tx, err := s.write.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = tx.Rollback(ctx) }()

		if err := createSealedTable(ctx, tx); err != nil {
			t.Fatal(err)
		}

		total, err := s.copySealed(ctx, tx)
		if err != nil {
			t.Fatal(err)
		}

		if mutate != "" {
			if _, err := tx.Exec(ctx, mutate); err != nil {
				t.Fatal(err)
			}
		}

		return s.verifySealed(ctx, tx, total)
	}

	if err := run(""); err != nil {
		t.Fatalf("an exact copy must verify: %v", err)
	}

	if err := run(`DELETE FROM blacklist_entries_v2 WHERE id = 5`); err == nil || !strings.Contains(err.Error(), "row count mismatch") {
		t.Fatalf("a missing row: %v", err)
	}

	// đổi blind của dòng 997 (nằm trong mẫu): hash/blind tính lại không khớp
	if err := run(`UPDATE blacklist_entries_v2 SET value_blind = '\x00'::bytea WHERE id = 997`); err == nil ||
		!strings.Contains(err.Error(), "does not match plaintext") {
		t.Fatalf("a wrong blind index: %v", err)
	}

	// đổi bản mã của dòng 997: giải mã thất bại
	if err := run(`UPDATE blacklist_entries_v2 SET value_enc = '\x00112233445566778899aabbccddeeff00112233'::bytea WHERE id = 997`); err == nil ||
		!strings.Contains(err.Error(), "verify id 997") {
		t.Fatalf("a corrupted ciphertext: %v", err)
	}
}

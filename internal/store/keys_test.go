package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

// Các test store mã hóa bằng khóa A (phiên bản 1, xem newTestSealer). Xoay khóa nghĩa là: B trở thành khóa hiện tại ở phiên bản 2
// và A bị gỡ nhưng vẫn đọc được.
const (
	keyA       = "0123456789abcdef0123456789abcdef-data"
	keyB       = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-data-B"
	keyC       = "cccccccccccccccccccccccccccccccccccccccc-data-C"
	keyPepper  = "fedcba9876543210fedcba9876543210-pepper"
	otherPeper = "99999999999999999999999999999999999999999-other"
)

// sealerOf dựng một Sealer với khóa, phiên bản, pepper và các khóa cũ cho trước.
func sealerOf(t *testing.T, key string, version int16, pepper string, retired map[int16]string) *seal.Sealer {
	t.Helper()

	sl, err := seal.New(key, pepper, version, seal.WithRetiredKeys(retired))
	if err != nil {
		t.Fatal(err)
	}

	return sl
}

// rotate chuyển store sang khóa B (phiên bản 2) với A đã bị gỡ, giống người vận hành làm sau khi đổi DATA_KEY.
func rotate(t *testing.T, s *Store) {
	t.Helper()
	s.SetSealer(sealerOf(t, keyB, 2, keyPepper, map[int16]string{1: keyA}))
}

type rawRow struct {
	version                   int16
	valueEnc, noteEnc, srcEnc []byte
}

// rawRowOf đọc thẳng một dòng từ bảng, không qua lớp giải mã, để kiểm tra bản mã.
func rawRowOf(t *testing.T, s *Store, id int64) rawRow {
	t.Helper()

	var r rawRow
	if err := s.write.QueryRow(context.Background(), `SELECT key_version, value_enc, note_enc, source_enc FROM blacklist_entries WHERE id = $1`, id).
		Scan(&r.version, &r.valueEnc, &r.noteEnc, &r.srcEnc); err != nil {
		t.Fatal(err)
	}

	return r
}

// readableUnder mở cả ba bản mã của một dòng thô bằng sl và trả về các bản rõ: bằng chứng rằng MỘT khóa
// (khóa mà sl giữ cho phiên bản của dòng) là đủ để đọc toàn bộ dòng.
func readableUnder(t *testing.T, sl *seal.Sealer, r rawRow) (value, note, source string) {
	t.Helper()

	var err error

	if value, err = sl.OpenVersion(r.version, r.valueEnc, seal.AADValue); err != nil {
		t.Fatalf("value_enc (key_version %d): %v", r.version, err)
	}

	if note, err = sl.OpenVersion(r.version, r.noteEnc, seal.AADNote); err != nil {
		t.Fatalf("note_enc (key_version %d): %v", r.version, err)
	}

	if source, err = sl.OpenVersion(r.version, r.srcEnc, seal.AADSource); err != nil {
		t.Fatalf("source_enc (key_version %d): %v", r.version, err)
	}

	return value, note, source
}

// seedEntries tạo n entry mẫu trong store và trả về danh sách đã tạo.
func seedEntries(t *testing.T, s *Store, n int) []model.Entry {
	t.Helper()

	var out []model.Entry

	for i := 0; i < n; i++ {
		e, err := s.CreateEntry(context.Background(),
			mustKey(t, normalize.TypePhone, "", fmt.Sprintf("0902%06d", i)), // 10 digits: 0902000000, 0902000001, ...
			model.EntryInput{Category: "scam", RiskScore: 60, Note: fmt.Sprintf("ghi chú %d", i), Source: fmt.Sprintf("nguồn %d", i)}, actor)
		if err != nil {
			t.Fatal(err)
		}

		out = append(out, e)
	}

	return out
}

// Sau khi DATA_KEY được xoay, các dòng mã hóa bằng khóa cũ vẫn đọc được miễn khóa cũ còn được cấu hình, và
// sẽ báo lỗi RÕ RÀNG (không phải "decryption failed") khi khóa cũ bị gỡ bỏ.
func TestRotationKeepsOldRowsReadable(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	rows := seedEntries(t, s, 3)

	rotate(t, s)

	for _, e := range rows {
		got, err := s.GetEntry(ctx, e.ID)
		if err != nil || got.Value != e.Value || got.Note != e.Note || got.Source != e.Source {
			t.Fatalf("entry %d must stay readable after rotation: %+v %v", e.ID, got, err)
		}
	}

	if list, _, err := s.ListEntries(ctx, ListFilter{Limit: 10}); err != nil || len(list) != 3 {
		t.Fatalf("list after rotation: %d rows, %v", len(list), err)
	}

	if got, err := s.FindMatches(ctx, []normalize.Key{mustKey(t, normalize.TypePhone, "", "0902000000")}); err != nil || len(got) != 1 {
		t.Fatalf("lookup after rotation: %+v %v", got, err)
	}

	// Không có khóa cũ thì không đọc được dòng, và lỗi nêu rõ biến nào cần đặt.
	s.SetSealer(sealerOf(t, keyB, 2, keyPepper, nil))

	_, err := s.GetEntry(ctx, rows[0].ID)
	if !errors.Is(err, seal.ErrUnknownKeyVersion) || !strings.Contains(err.Error(), "DATA_KEY_V1") {
		t.Fatalf("want ErrUnknownKeyVersion naming DATA_KEY_V1, got %v", err)
	}
}

// Hồi quy C4: một dòng chỉ có MỘT key_version, nên mọi lệnh ghi đóng dấu phiên bản hiện tại phải mã hóa lại ĐỦ ba
// bản mã bằng khóa hiện tại. Trước đây UpdateEntry và upsert của import chỉ mã hóa lại một phần, và dòng đó
// không đọc được khi khóa cũ bị gỡ.
func TestWritesResealWholeRowUnderCurrentKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	rows := seedEntries(t, s, 2)
	rotate(t, s)

	onlyB := sealerOf(t, keyB, 2, keyPepper, nil) // the old key is gone

	// UpdateEntry
	if _, err := s.UpdateEntry(ctx, rows[0].ID, model.EntryInput{Category: "scam", RiskScore: 70, Note: "mới", Source: "nguồn mới"}, actor); err != nil {
		t.Fatal(err)
	}

	r := rawRowOf(t, s, rows[0].ID)
	if r.version != 2 {
		t.Fatalf("UpdateEntry must stamp the current key version, got %d", r.version)
	}

	if v, n, src := readableUnder(t, onlyB, r); v != rows[0].Value || n != "mới" || src != "nguồn mới" {
		t.Fatalf("after UpdateEntry the whole row must be readable under the current key alone: %q %q %q", v, n, src)
	}

	// Import chạm vào dòng đã tồn tại (nhánh ON CONFLICT).
	existing := ImportRow{Key: mustKey(t, normalize.TypePhone, "", "0902000001"), Input: model.EntryInput{Category: "scam", RiskScore: 80, Note: "từ import", Source: "csv"}}
	if _, err := s.ImportWith(ctx, &sliceIter{rows: []ImportRow{existing}}, actor, ImportOptions{}); err != nil {
		t.Fatal(err)
	}

	r = rawRowOf(t, s, rows[1].ID)
	if r.version != 2 {
		t.Fatalf("import upsert must stamp the current key version, got %d", r.version)
	}

	if v, n, src := readableUnder(t, onlyB, r); v != rows[1].Value || n != "từ import" || src != "csv" {
		t.Fatalf("after an import upsert the whole row must be readable under the current key alone: %q %q %q", v, n, src)
	}
}

// Cùng bất biến này cho migration đường dẫn M9, vốn ghi lại khóa và bản mã của các entry url cũ.
func TestURLPathMigrationResealsWholeRow(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	e, err := s.CreateEntry(ctx, normalize.MakeKey(normalize.TypeURL, normalize.MatchPrefix, "evil.com/SecurePath"),
		model.EntryInput{Category: "phishing", RiskScore: 90, Note: "ghi chú url", Source: "nguồn url"}, actor)
	if err != nil {
		t.Fatal(err)
	}

	rotate(t, s)

	if res, err := s.canonicalizeURLPaths(ctx, 10, 10); err != nil || res.Changed != 1 {
		t.Fatalf("migration over a rotated store: %+v %v", res, err)
	}

	r := rawRowOf(t, s, e.ID)
	if r.version != 2 {
		t.Fatalf("a moved row must carry the current key version, got %d", r.version)
	}

	if v, n, src := readableUnder(t, sealerOf(t, keyB, 2, keyPepper, nil), r); v != "evil.com/securepath" || n != "ghi chú url" || src != "nguồn url" {
		t.Fatalf("the whole moved row must be readable under the current key alone: %q %q %q", v, n, src)
	}
}

// TestRekeyMovesOldRowsToTheCurrentKey kiểm tra Rekey chuyển các dòng cũ sang khóa hiện tại, và chạy lại không làm gì thêm.
func TestRekeyMovesOldRowsToTheCurrentKey(t *testing.T) {
	s := newTestStore(t)
	s.SetAuditKey(AuditKeyFrom("", "test-secret"))
	ctx := context.Background()
	old := seedEntries(t, s, 10)

	rotate(t, s)

	fresh := seedEntries2(t, s, 2) // written after the rotation: already on version 2

	res, err := s.Rekey(ctx, actor, RekeyOptions{Batch: 3})
	if err != nil {
		t.Fatal(err)
	}

	if res.Scanned != 10 || res.Rewritten != 10 || res.Skipped != 0 || res.From[1] != 10 || res.Batches != 4 {
		t.Fatalf("res = %+v, want scanned=10 rewritten=10 skipped=0 from[1]=10 batches=4", res)
	}

	counts, err := s.KeyVersionCounts(ctx)
	if err != nil || len(counts) != 1 || counts[2] != 12 {
		t.Fatalf("every row must now be on version 2: %v %v", counts, err)
	}

	onlyB := sealerOf(t, keyB, 2, keyPepper, nil)
	for _, e := range append(old, fresh...) {
		if v, n, src := readableUnder(t, onlyB, rawRowOf(t, s, e.ID)); v != e.Value || n != e.Note || src != e.Source {
			t.Fatalf("entry %d must be readable under the new key alone with the same content: %q %q %q", e.ID, v, n, src)
		}
	}

	// Bản rõ, tra cứu và metadata giữ nguyên.
	got, err := s.FindMatches(ctx, []normalize.Key{mustKey(t, normalize.TypePhone, "", "0902000003")})
	if err != nil || len(got) != 1 || got[0].RiskScore != 60 || got[0].UpdatedAt != old[3].UpdatedAt {
		t.Fatalf("rekey must not change the data or touch updated_at: %+v %v", got, err)
	}

	actions, details := auditActions(t, s)
	if len(actions) < 2 || actions[0] != "entry.rekey" {
		t.Fatalf("rekey must leave a closing audit row, got %v", actions)
	}

	if d := auditDetail(t, details[0]); d["status"] != "done" || d["rewritten"] != float64(10) {
		t.Fatalf("closing audit row: %v", d)
	}

	// Idempotent: không còn gì để làm.
	res, err = s.Rekey(ctx, actor, RekeyOptions{})
	if err != nil || res.Scanned != 0 || res.Rewritten != 0 {
		t.Fatalf("second run must be a no-op: %+v %v", res, err)
	}
}

// seedEntries2 giống seedEntries nhưng dùng cho các test rekey khác.
func seedEntries2(t *testing.T, s *Store, n int) []model.Entry {
	t.Helper()

	var out []model.Entry

	for i := 0; i < n; i++ {
		e, err := s.CreateEntry(context.Background(), mustKey(t, normalize.TypePhone, "", fmt.Sprintf("09031%05d", i)),
			model.EntryInput{Category: "spam", RiskScore: 40, Note: fmt.Sprintf("mới %d", i), Source: "sau xoay khóa"}, actor)
		if err != nil {
			t.Fatal(err)
		}

		out = append(out, e)
	}

	return out
}

// TestRekeyDryRunWritesNothingButVerifiesEverything kiểm tra dry-run không ghi gì nhưng vẫn xác minh mọi dòng.
func TestRekeyDryRunWritesNothingButVerifiesEverything(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	seedEntries(t, s, 5)
	rotate(t, s)

	res, err := s.Rekey(ctx, actor, RekeyOptions{DryRun: true})
	if err != nil || res.Scanned != 5 || res.Rewritten != 0 {
		t.Fatalf("dry run: %+v %v", res, err)
	}

	if counts, _ := s.KeyVersionCounts(ctx); counts[1] != 5 {
		t.Fatalf("a dry run must not change anything: %v", counts)
	}

	if actions, _ := auditActions(t, s); len(actions) != 5 { // the 5 entry.create rows only
		t.Fatalf("a dry run writes no audit rows, got %v", actions)
	}

	// Khi khóa cũ bị thiếu, dry-run là thứ báo cho người vận hành biết trước khi bất cứ thứ gì bị chạm.
	s.SetSealer(sealerOf(t, keyB, 2, keyPepper, nil))

	if _, err := s.Rekey(ctx, actor, RekeyOptions{DryRun: true}); !errors.Is(err, seal.ErrUnknownKeyVersion) {
		t.Fatalf("dry run without the old key must report ErrUnknownKeyVersion, got %v", err)
	}
}

// TestRekeyStopsOnUnknownVersionAndRecordsFailure kiểm tra Rekey dừng khi gặp phiên bản khóa chưa cấu hình và ghi audit failed.
func TestRekeyStopsOnUnknownVersionAndRecordsFailure(t *testing.T) {
	s := newTestStore(t)
	s.SetAuditKey(AuditKeyFrom("", "test-secret"))
	ctx := context.Background()
	seedEntries(t, s, 4)

	s.SetSealer(sealerOf(t, keyB, 2, keyPepper, nil)) // rotated WITHOUT keeping key A

	res, err := s.Rekey(ctx, actor, RekeyOptions{})
	if !errors.Is(err, seal.ErrUnknownKeyVersion) || res.Rewritten != 0 {
		t.Fatalf("must stop, rewriting nothing: %+v %v", res, err)
	}

	_, details := auditActions(t, s)
	if d := auditDetail(t, details[0]); d["status"] != "failed" {
		t.Fatalf("the closing audit row must say failed: %v", d)
	}
}

// Một dòng mà admin vừa sửa giữa lúc đọc và lúc ghi đã ở khóa hiện tại: lệnh UPDATE có điều kiện phải bỏ qua nó
// thay vì ghi đè bản sửa bằng nội dung cũ.
func TestRekeySkipsRowsEditedMeanwhile(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	rows := seedEntries(t, s, 4)
	rotate(t, s)

	edited := false

	res, err := s.Rekey(ctx, actor, RekeyOptions{afterScan: func() {
		if edited {
			return
		}

		edited = true

		if _, err := s.UpdateEntry(ctx, rows[1].ID, model.EntryInput{Category: "scam", RiskScore: 99, Note: "sửa giữa chừng", Source: "admin"}, actor); err != nil {
			t.Error(err)
		}
	}})
	if err != nil {
		t.Fatal(err)
	}

	if res.Rewritten != 3 || res.Skipped != 1 {
		t.Fatalf("res = %+v, want rewritten=3 skipped=1", res)
	}

	got, err := s.GetEntry(ctx, rows[1].ID)
	if err != nil || got.Note != "sửa giữa chừng" || got.RiskScore != 99 {
		t.Fatalf("the concurrent edit must survive: %+v %v", got, err)
	}
}

// TestVerifyKeys kiểm tra VerifyKeys phát hiện đúng các kiểu cấu hình khóa sai.
func TestVerifyKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if chk, err := s.VerifyKeys(ctx); err != nil || chk.Sampled != 0 {
		t.Fatalf("an empty table passes: %+v %v", chk, err)
	}

	seedEntries(t, s, 5)

	if chk, err := s.VerifyKeys(ctx); err != nil || chk.Sampled != 5 || chk.Versions[1] != 5 {
		t.Fatalf("the right keys pass: %+v %v", chk, err)
	}

	// Đã xoay và giữ khóa cũ: ổn, và báo cả hai phiên bản khi đã có dòng mới.
	rotate(t, s)
	seedEntries2(t, s, 2)

	if chk, err := s.VerifyKeys(ctx); err != nil || chk.Versions[1] != 5 || chk.Versions[2] != 2 {
		t.Fatalf("rotated with the old key kept must pass and see both versions: %+v %v", chk, err)
	}

	// Đã xoay mà KHÔNG giữ khóa cũ: từ chối và nêu rõ biến nào cần đặt.
	s.SetSealer(sealerOf(t, keyB, 2, keyPepper, nil))

	_, err := s.VerifyKeys(ctx)
	if !errors.Is(err, seal.ErrUnknownKeyVersion) || !strings.Contains(err.Error(), "DATA_KEY_V1") {
		t.Fatalf("missing old key must be reported with the variable to set, got %v", err)
	}

	// Cùng số phiên bản nhưng khác secret (DATA_KEY bị đổi mà không tăng DATA_KEY_VERSION).
	s.SetSealer(sealerOf(t, keyC, 1, keyPepper, nil))

	_, err = s.VerifyKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
		t.Fatalf("a wrong key under the right version must be reported as undecryptable, got %v", err)
	}

	// Đúng khóa dữ liệu nhưng sai pepper: giải mã vẫn được nhưng chỉ mục tra cứu không còn khớp (trường hợp im lặng và tệ nhất).
	s.SetSealer(sealerOf(t, keyA, 1, otherPeper, nil))

	_, err = s.VerifyKeys(ctx)
	if err == nil || !strings.Contains(err.Error(), "DATA_PEPPER") {
		t.Fatalf("a wrong DATA_PEPPER must be reported, got %v", err)
	}
}

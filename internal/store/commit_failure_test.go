package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// Lỗi ở bước COMMIT được mô phỏng bằng cách tất định, không cần giả lập driver hay giết kết nối: một CONSTRAINT TRIGGER
// DEFERRABLE INITIALLY DEFERRED chạy đúng lúc COMMIT và ném lỗi, nên COMMIT thất bại và PostgreSQL hủy cả giao dịch.
// Đây chính là tình huống "câu lệnh nào cũng chạy được, nhưng commit thì lỗi" mà các test khác không tạo ra được.

const commitFailMessage = "simulated commit failure"

const failCommitFunction = `
	CREATE OR REPLACE FUNCTION vsf_fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$
	BEGIN RAISE EXCEPTION '` + commitFailMessage + `'; END $$`

// failCommitOn làm mọi giao dịch có ghi (event = INSERT hoặc UPDATE) vào bảng table đều thất bại ở COMMIT.
// Trả hàm gỡ trigger; cũng tự gỡ khi test kết thúc.
func failCommitOn(t *testing.T, s *Store, table, event string) (remove func()) {
	t.Helper()

	ctx := context.Background()
	name := "vsf_fail_commit_" + table

	if _, err := s.write.Exec(ctx, failCommitFunction); err != nil {
		t.Fatal(err)
	}

	if _, err := s.write.Exec(ctx, `CREATE CONSTRAINT TRIGGER `+name+` AFTER `+event+` ON `+table+`
		DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION vsf_fail_commit()`); err != nil {
		t.Fatal(err)
	}

	removed := false
	remove = func() {
		if !removed {
			removed = true

			if _, err := s.write.Exec(context.Background(), `DROP TRIGGER IF EXISTS `+name+` ON `+table); err != nil {
				t.Fatal(err)
			}
		}
	}

	t.Cleanup(remove)

	return remove
}

func wantCommitFailure(t *testing.T, what string, err error) {
	t.Helper()

	if err == nil || !strings.Contains(err.Error(), commitFailMessage) {
		t.Errorf("%s: want the commit failure to be reported, got %v", what, err)
	}
}

// COMMIT lỗi ở mọi thao tác quản trị và ghi entry (giao dịch có kèm dòng audit): thao tác phải báo lỗi và KHÔNG để lại
// gì: không tài khoản, không key, không entry, không thay đổi, và phiên không bị xóa oan.
func TestCommitFailureRollsBackEveryAuditedWrite(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	in := model.EntryInput{Category: "spam", RiskScore: 10, Note: "before"}

	e1, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000301"), in, actor)
	if err != nil {
		t.Fatal(err)
	}

	admin, err := s.CreateAdmin(ctx, "c1@example.com", "h", model.RoleEditor, actor)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.CreateSession(ctx, []byte("c1-session"), admin.ID, "csrf", "ip", "ua", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	key, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "k", Prefix: "cmt00001", KeyHash: []byte("h"), RPSLimit: 5}, actor)
	if err != nil {
		t.Fatal(err)
	}

	auditBefore := countRows(t, s, "audit_logs")
	remove := failCommitOn(t, s, "audit_logs", "INSERT")

	_, err = s.CreateAdmin(ctx, "c2@example.com", "h", model.RoleViewer, actor)
	wantCommitFailure(t, "CreateAdmin", err)

	wantCommitFailure(t, "UpdateAdmin", s.UpdateAdmin(ctx, admin.ID, model.RoleAdmin, true, actor))

	_, err = s.CreateAPIKey(ctx, NewAPIKey{Name: "k2", Prefix: "cmt00002", KeyHash: []byte("h2")}, actor)
	wantCommitFailure(t, "CreateAPIKey", err)

	wantCommitFailure(t, "RevokeAPIKey", s.RevokeAPIKey(ctx, key.ID, actor))

	_, err = s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000302"), in, actor)
	wantCommitFailure(t, "CreateEntry", err)

	_, err = s.UpdateEntry(ctx, e1.ID, model.EntryInput{Category: "scam", RiskScore: 99, Note: "after"}, actor)
	wantCommitFailure(t, "UpdateEntry", err)

	wantCommitFailure(t, "DeleteEntry", s.DeleteEntry(ctx, e1.ID, actor))
	wantCommitFailure(t, "WriteAudit", s.WriteAudit(ctx, actor, "x.y", map[string]any{}))

	remove() // gỡ trigger để đọc trạng thái

	if n := countRows(t, s, "admins"); n != 1 {
		t.Errorf("a failed CreateAdmin left an account behind: %d admins", n)
	}

	if a, _ := s.GetAdminByEmail(ctx, "c1@example.com"); a.Role != model.RoleEditor || a.Disabled {
		t.Errorf("a failed UpdateAdmin changed the account: %+v", a)
	}

	if _, err := s.GetSession(ctx, []byte("c1-session")); err != nil {
		t.Errorf("a failed UpdateAdmin must not have ended the session: %v", err)
	}

	if n := countRows(t, s, "api_keys"); n != 1 {
		t.Errorf("a failed CreateAPIKey left a key behind: %d", n)
	}

	if k, _ := s.GetAPIKey(ctx, key.ID); k.Status != "active" {
		t.Errorf("a failed revoke changed the key: %+v", k)
	}

	if n := countRows(t, s, "blacklist_entries"); n != 1 {
		t.Errorf("a failed CreateEntry/DeleteEntry changed the entries: %d rows", n)
	}

	if got, err := s.GetEntry(ctx, e1.ID); err != nil || got.Note != "before" || got.RiskScore != 10 {
		t.Errorf("a failed UpdateEntry changed the entry: %+v %v", got, err)
	}

	if n := countRows(t, s, "audit_logs"); n != auditBefore {
		t.Errorf("no audit row may survive a failed commit: %d -> %d", auditBefore, n)
	}

	// không để lại trạng thái hỏng: cùng thao tác chạy lại được
	if _, err := s.CreateAdmin(ctx, "c2@example.com", "h", model.RoleViewer, actor); err != nil {
		t.Errorf("after the fault is gone the same operation must succeed: %v", err)
	}
}

// COMMIT lỗi ở import và ở bước chuẩn hóa URL (cả hai ghi change_log trong cùng giao dịch với dữ liệu): không dòng nào
// được lưu một nửa, và chạy lại sau khi hết lỗi thì hoàn tất.
func TestCommitFailureRollsBackImportAndURLMoves(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	// dòng URL cũ cần được chuẩn hóa lại; tạo TRƯỚC khi đặt lỗi
	legacy := legacyEntry(t, s, normalize.MatchPrefix, "evil.example/SecurePath", 90, nil)
	rowsBefore := countRows(t, s, "blacklist_entries")

	remove := failCommitOn(t, s, "change_log", "INSERT")

	var importRows []ImportRow
	for _, p := range []string{"0905000401", "0905000402", "0905000403"} {
		importRows = append(importRows, ImportRow{Key: mustKey(t, "phone", "exact", p), Input: model.EntryInput{Category: "spam", RiskScore: 1}})
	}

	if _, err := s.Import(ctx, &sliceIter{rows: importRows}, actor); err == nil || !strings.Contains(err.Error(), commitFailMessage) {
		t.Errorf("Import must report the failed commit, got %v", err)
	}

	if _, err := s.canonicalizeURLPaths(ctx, 10, 10); err == nil || !strings.Contains(err.Error(), commitFailMessage) {
		t.Errorf("the URL migration must report the failed commit, got %v", err)
	}

	remove()

	if n := countRows(t, s, "blacklist_entries"); n != rowsBefore {
		t.Fatalf("a failed import must leave no row behind: %d -> %d", rowsBefore, n)
	}

	for _, e := range matchedBy(t, s, "http://evil.example/securepath/x") {
		if e.ID == legacy.ID {
			t.Fatal("a failed URL move must not have changed the stored key")
		}
	}

	// sau khi hết lỗi: chạy lại hoàn tất
	res, err := s.canonicalizeURLPaths(ctx, 10, 10)
	if err != nil || res.Changed != 1 {
		t.Fatalf("rerun after the fault is gone: %+v %v", res, err)
	}

	found := false

	for _, e := range matchedBy(t, s, "http://evil.example/securepath/x") {
		if e.ID == legacy.ID {
			found = true
		}
	}

	if !found {
		t.Fatal("after the rerun the entry must block its canonical URL")
	}

	if _, err := s.Import(ctx, &sliceIter{rows: importRows}, actor); err != nil {
		t.Fatalf("import after the fault is gone: %v", err)
	}
}

// COMMIT của một migration lỗi: migration đó bị hủy hẳn (không có bảng nào), và chạy lại sau khi hết lỗi thì dựng đủ.
func TestCommitFailureDuringMigrationLeavesNothingBehind(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	// Migrate tự tạo schema_migrations; tạo sẵn để gắn trigger lên nó
	if _, err := s.write.Exec(ctx, `CREATE TABLE schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}

	remove := failCommitOn(t, s, "schema_migrations", "INSERT")

	if err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), commitFailMessage) {
		t.Fatalf("Migrate must report the failed commit, got %v", err)
	}

	var exists bool
	if err := s.write.QueryRow(ctx, `SELECT to_regclass('admins') IS NOT NULL`).Scan(&exists); err != nil || exists {
		t.Fatalf("a migration whose commit failed must leave no table behind: exists=%v err=%v", exists, err)
	}

	remove()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate after the fault is gone: %v", err)
	}

	if len(appliedMigrations(t, s)) < 4 {
		t.Fatalf("every migration must be recorded after the rerun: %v", appliedMigrations(t, s))
	}
}

// Bản ghi "đã chạy xong migration URL" nằm trong cùng giao dịch với dòng audit: COMMIT lỗi thì KHÔNG được coi là đã chạy
// (nếu coi là đã chạy, các entry cũ sẽ không bao giờ được chuẩn hóa).
func TestCommitFailureDoesNotMarkTheURLMigrationDone(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := s.write.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, urlPathMigrationVersion); err != nil {
		t.Fatal(err)
	}

	recorded := func() int {
		var n int
		if err := s.write.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = $1`, urlPathMigrationVersion).Scan(&n); err != nil {
			t.Fatal(err)
		}

		return n
	}

	remove := failCommitOn(t, s, "audit_logs", "INSERT")

	if err := s.runURLPathMigration(ctx); err == nil || !strings.Contains(err.Error(), commitFailMessage) {
		t.Fatalf("want the failed commit reported, got %v", err)
	}

	if recorded() != 0 {
		t.Fatal("a failed commit must not leave the migration marked as done")
	}

	remove()

	if err := s.runURLPathMigration(ctx); err != nil || recorded() != 1 {
		t.Fatalf("rerun after the fault is gone: err=%v recorded=%d", err, recorded())
	}
}

// COMMIT lỗi khi chuyển bảng plaintext cũ sang bảng mã hóa: toàn bộ chuyển đổi bị hủy và bảng cũ còn nguyên, không có
// bảng dở dang; chạy lại sau khi hết lỗi thì chuyển được.
func TestCommitFailureKeepsTheLegacyTableIntact(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	seedLegacy(t, s, 30)

	// dòng audit cũ chứa bản rõ: bước cuối của chuyển đổi (scrubAudit) sẽ UPDATE nó
	if _, err := s.write.Exec(ctx, `INSERT INTO audit_logs(actor_email, action, detail)
		VALUES ('a@x.io','entry.create','{"after":{"value":"+84900000001","note":"secret","source":"s","id":1}}')`); err != nil {
		t.Fatal(err)
	}

	remove := failCommitOn(t, s, "audit_logs", "UPDATE")

	if err := s.Migrate(ctx); err == nil || !strings.Contains(err.Error(), commitFailMessage) {
		t.Fatalf("the conversion must report the failed commit, got %v", err)
	}

	var legacyCol, v2 bool
	if err := s.write.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
		WHERE table_name='blacklist_entries' AND column_name='value_normalized'), to_regclass('blacklist_entries_v2') IS NOT NULL`).
		Scan(&legacyCol, &v2); err != nil {
		t.Fatal(err)
	}

	if !legacyCol || v2 {
		t.Fatalf("the plaintext table must be untouched and no half-built table may remain: legacy=%v v2=%v", legacyCol, v2)
	}

	if n := countRows(t, s, "blacklist_entries"); n != 30 {
		t.Fatalf("no plaintext row may be lost: %d", n)
	}

	remove()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("conversion after the fault is gone: %v", err)
	}

	if n := countRows(t, s, "blacklist_entries"); n != 30 {
		t.Fatalf("all rows must survive the conversion: %d", n)
	}
}

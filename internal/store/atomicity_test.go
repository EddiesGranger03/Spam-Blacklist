package store

import (
	"context"
	"testing"

	"vsf/internal/model"
)

// rename đổi tên một bảng để mô phỏng "bước phụ của giao dịch hỏng"; trả hàm khôi phục.
func (s *Store) renameForTest(t *testing.T, table string) func() {
	t.Helper()

	ctx := context.Background()

	if _, err := s.write.Exec(ctx, `ALTER TABLE `+table+` RENAME TO `+table+`_hidden`); err != nil {
		t.Fatal(err)
	}

	return func() {
		if _, err := s.write.Exec(ctx, `ALTER TABLE `+table+`_hidden RENAME TO `+table); err != nil {
			t.Fatal(err)
		}
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()

	var n int
	if err := s.write.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(&n); err != nil {
		t.Fatal(err)
	}

	return n
}

// Mỗi thao tác ghi gồm nhiều bước trong MỘT giao dịch (dữ liệu, change_log để Bloom filter biết, audit). Nếu bước phụ
// hỏng, thao tác phải hỏng HẲN và không để lại gì: không có entry mà Bloom không biết (một số bị chặn bị báo an toàn),
// không có hành động quản trị nào mà không có dấu vết audit.
func TestWritesAreAtomicWhenASideStepFails(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	in := model.EntryInput{Category: "spam", RiskScore: 10, Note: "before"}

	e1, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000201"), in, actor)
	if err != nil {
		t.Fatal(err)
	}

	admin, err := s.CreateAdmin(ctx, "a1@example.com", "h", model.RoleEditor, actor)
	if err != nil {
		t.Fatal(err)
	}

	key, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "k1", Prefix: "atom0001", KeyHash: []byte("h"), RPSLimit: 5}, actor)
	if err != nil {
		t.Fatal(err)
	}

	// 1) change_log hỏng: ghi entry phải hỏng hẳn
	restore := s.renameForTest(t, "change_log")

	if _, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000202"), in, actor); err == nil {
		t.Error("CreateEntry must fail when the change log cannot be written")
	}

	if _, err := s.UpdateEntry(ctx, e1.ID, model.EntryInput{Category: "scam", RiskScore: 99, Note: "after"}, actor); err == nil {
		t.Error("UpdateEntry must fail when the change log cannot be written")
	}

	if err := s.DeleteEntry(ctx, e1.ID, actor); err == nil {
		t.Error("DeleteEntry must fail when the change log cannot be written")
	}

	restore()

	if n := countRows(t, s, "blacklist_entries"); n != 1 {
		t.Fatalf("a failed create must leave no entry behind, and a failed delete must keep the entry: %d rows", n)
	}

	if got, err := s.GetEntry(ctx, e1.ID); err != nil || got.Note != "before" || got.RiskScore != 10 || got.Category != "spam" {
		t.Fatalf("a failed update must change nothing: %+v %v", got, err)
	}

	// 2) audit_logs hỏng: mọi thao tác quản trị phải hỏng hẳn
	restore = s.renameForTest(t, "audit_logs")

	if _, err := s.CreateAdmin(ctx, "a2@example.com", "h", model.RoleViewer, actor); err == nil {
		t.Error("CreateAdmin must fail when the audit row cannot be written")
	}

	if err := s.UpdateAdmin(ctx, admin.ID, model.RoleAdmin, true, actor); err == nil {
		t.Error("UpdateAdmin must fail when the audit row cannot be written")
	}

	if _, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "k2", Prefix: "atom0002", KeyHash: []byte("h2")}, actor); err == nil {
		t.Error("CreateAPIKey must fail when the audit row cannot be written")
	}

	if err := s.RevokeAPIKey(ctx, key.ID, actor); err == nil {
		t.Error("RevokeAPIKey must fail when the audit row cannot be written")
	}

	if _, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000203"), in, actor); err == nil {
		t.Error("CreateEntry must fail when the audit row cannot be written")
	}

	restore()

	if n := countRows(t, s, "admins"); n != 1 {
		t.Fatalf("a failed CreateAdmin must leave no account behind: %d", n)
	}

	if after, _ := s.GetAdminByEmail(ctx, "a1@example.com"); after.Role != model.RoleEditor || after.Disabled {
		t.Fatalf("a failed UpdateAdmin must change nothing: %+v", after)
	}

	if n := countRows(t, s, "api_keys"); n != 1 {
		t.Fatalf("a failed CreateAPIKey must leave no key behind: %d", n)
	}

	if k, _ := s.GetAPIKey(ctx, key.ID); k.Status != "active" {
		t.Fatalf("a failed revoke must leave the key active: %+v", k)
	}

	if n := countRows(t, s, "blacklist_entries"); n != 1 {
		t.Fatalf("a create whose audit failed must leave no entry: %d", n)
	}
}

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"vsf/internal/model"
)

func TestAdminsAndSessions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if n, err := s.CountAdmins(ctx); err != nil || n != 0 {
		t.Fatalf("a fresh database has no admins: %d %v", n, err)
	}

	a, err := s.CreateAdmin(ctx, "  Boss@Example.COM ", "hash-1", model.RoleAdmin, actor)
	if err != nil || a.Email != "boss@example.com" || a.Role != model.RoleAdmin || a.ID == 0 {
		t.Fatalf("create: %+v %v", a, err)
	}

	if _, err := s.CreateAdmin(ctx, "boss@example.com", "hash-2", model.RoleViewer, actor); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate email: %v", err)
	}

	got, err := s.GetAdminByEmail(ctx, " BOSS@example.com")
	if err != nil || got.ID != a.ID || got.PasswordHash != "hash-1" {
		t.Fatalf("lookup is case-insensitive and trims: %+v %v", got, err)
	}

	if _, err := s.GetAdminByEmail(ctx, "nobody@example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown email: %v", err)
	}

	b, _ := s.CreateAdmin(ctx, "second@example.com", "h", model.RoleEditor, actor)

	list, err := s.ListAdmins(ctx)
	if err != nil || len(list) != 2 || list[0].ID != a.ID || list[1].ID != b.ID {
		t.Fatalf("list in id order: %+v %v", list, err)
	}

	// phiên: tạo, đọc (kèm vai trò), chạm, xóa
	id1, id2 := []byte("session-hash-1"), []byte("session-hash-2")

	for _, h := range [][]byte{id1, id2} {
		if err := s.CreateSession(ctx, h, a.ID, "csrf", "10.0.0.1", strings.Repeat("u", 500), time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}

	sess, err := s.GetSession(ctx, id1)
	if err != nil || sess.AdminID != a.ID || sess.Role != model.RoleAdmin || sess.Email != a.Email || sess.CSRFToken != "csrf" {
		t.Fatalf("session: %+v %v", sess, err)
	}

	time.Sleep(20 * time.Millisecond)

	if err := s.TouchSession(ctx, id1); err != nil {
		t.Fatal(err)
	}

	touched, _ := s.GetSession(ctx, id1)
	if !touched.LastSeenAt.After(sess.LastSeenAt) {
		t.Fatal("TouchSession must move last_seen_at forward")
	}

	if err := s.DeleteSession(ctx, id1); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSession(ctx, id1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a deleted session: %v", err)
	}

	if err := s.DeleteSession(ctx, id1); err != nil {
		t.Fatalf("deleting twice is not an error: %v", err)
	}

	// dọn phiên: hết hạn hoặc không hoạt động lâu
	if _, err := s.write.Exec(ctx, `UPDATE sessions SET last_seen_at = now() - interval '2 hours' WHERE id_hash = $1`, id2); err != nil {
		t.Fatal(err)
	}

	if n, err := s.PurgeSessions(ctx, 30*time.Minute); err != nil || n != 1 {
		t.Fatalf("an idle session must be purged: %d %v", n, err)
	}

	_ = s.CreateSession(ctx, []byte("expired"), a.ID, "c", "ip", "ua", time.Now().Add(-time.Minute))

	if n, err := s.PurgeSessions(ctx, time.Hour); err != nil || n != 1 {
		t.Fatalf("an expired session must be purged: %d %v", n, err)
	}

	// đổi vai trò hoặc khóa tài khoản xóa mọi phiên của người đó và ghi audit
	_ = s.CreateSession(ctx, []byte("b-session"), b.ID, "c", "ip", "ua", time.Now().Add(time.Hour))

	// lưu đúng giá trị hiện có: không đổi gì thì không được xóa phiên
	if err := s.UpdateAdmin(ctx, b.ID, model.RoleEditor, false, actor); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSession(ctx, []byte("b-session")); err != nil {
		t.Fatalf("an update that changes nothing must keep the sessions: %v", err)
	}

	if err := s.UpdateAdmin(ctx, b.ID, model.RoleViewer, true, actor); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSession(ctx, []byte("b-session")); !errors.Is(err, ErrNotFound) {
		t.Fatal("updating an admin must end their sessions")
	}

	if after, _ := s.GetAdminByEmail(ctx, b.Email); after.Role != model.RoleViewer || !after.Disabled {
		t.Fatalf("update not applied: %+v", after)
	}

	if err := s.UpdateAdmin(ctx, 999999, model.RoleViewer, false, actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("updating an unknown admin: %v", err)
	}

	if n, _ := s.CountAdmins(ctx); n != 2 {
		t.Fatalf("count: %d", n)
	}
}

func TestListAuditPaging(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for i := 0; i < 7; i++ {
		if err := s.WriteAudit(ctx, actor, fmt.Sprintf("test.action.%d", i), map[string]any{"i": i}); err != nil {
			t.Fatal(err)
		}
	}

	page1, next, err := s.ListAudit(ctx, 0, 3)
	if err != nil || len(page1) != 3 || next == 0 || page1[0].ID < page1[1].ID {
		t.Fatalf("first page, newest first: %d next=%d %v", len(page1), next, err)
	}

	if page1[0].Action != "test.action.6" || page1[0].ActorEmail != actor.Email || !strings.Contains(page1[0].Detail, `"i": 6`) {
		t.Fatalf("newest row: %+v", page1[0])
	}

	page2, next2, err := s.ListAudit(ctx, next, 3)
	if err != nil || len(page2) != 3 || page2[0].ID >= next || next2 == 0 {
		t.Fatalf("second page: %+v %v", page2, err)
	}

	last, next3, err := s.ListAudit(ctx, next2, 3)
	if err != nil || len(last) != 1 || next3 != 0 {
		t.Fatalf("the last page has no next cursor: %d %d %v", len(last), next3, err)
	}

	// limit ngoài khoảng dùng mặc định 50
	if all, _, err := s.ListAudit(ctx, 0, 0); err != nil || len(all) != 7 {
		t.Fatalf("default limit: %d %v", len(all), err)
	}

	if got := truncate("abcdef", 3); got != "abc" || truncate("ab", 3) != "ab" {
		t.Fatalf("truncate: %q", got)
	}
}

func TestAPIKeysLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	exp := time.Now().Add(24 * time.Hour).UTC()

	k, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "n1", Prefix: "pfx00001", KeyHash: []byte("h1"), RPSLimit: 50, MaxBatch: 20,
		DailyQuota: 1000, ExpiresAt: &exp}, actor)
	if err != nil || k.ID == 0 || k.Status != "active" || k.MaxBatch != 20 || k.ExpiresAt == nil {
		t.Fatalf("create: %+v %v", k, err)
	}

	if _, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "dup", Prefix: "pfx00001", KeyHash: []byte("h2")}, actor); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate prefix: %v", err)
	}

	rot, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "n1 (rotated)", Prefix: "pfx00002", KeyHash: []byte("h3"), RPSLimit: 50, RotatedFrom: &k.ID}, actor)
	if err != nil || rot.RotatedFrom == nil || *rot.RotatedFrom != k.ID {
		t.Fatalf("rotated key: %+v %v", rot, err)
	}

	byPrefix, err := s.GetAPIKeyByPrefix(ctx, "pfx00001")
	if err != nil || byPrefix.ID != k.ID || string(byPrefix.KeyHash) != "h1" {
		t.Fatalf("by prefix: %+v %v", byPrefix, err)
	}

	byID, err := s.GetAPIKey(ctx, k.ID)
	if err != nil || byID.Prefix != "pfx00001" {
		t.Fatalf("by id: %+v %v", byID, err)
	}

	if _, err := s.GetAPIKeyByPrefix(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown prefix: %v", err)
	}

	if _, err := s.GetAPIKey(ctx, 999999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}

	list, err := s.ListAPIKeys(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d %v", len(list), err)
	}

	// hạn dùng
	later := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	if err := s.SetAPIKeyExpiry(ctx, k.ID, later); err != nil {
		t.Fatal(err)
	}

	if after, _ := s.GetAPIKey(ctx, k.ID); after.ExpiresAt == nil || !after.ExpiresAt.Truncate(time.Second).Equal(later) {
		t.Fatalf("expiry not set: %+v", after.ExpiresAt)
	}

	// ghi lượt dùng
	if err := s.TouchAPIKeys(ctx, nil); err != nil {
		t.Fatalf("touching nothing is a no-op: %v", err)
	}

	if err := s.TouchAPIKeys(ctx, []int64{k.ID, 999999}); err != nil {
		t.Fatal(err)
	}

	if touched, _ := s.GetAPIKey(ctx, k.ID); touched.LastUsedAt == nil {
		t.Fatal("TouchAPIKeys must set last_used_at")
	}

	// thu hồi: chỉ một lần
	if err := s.RevokeAPIKey(ctx, k.ID, actor); err != nil {
		t.Fatal(err)
	}

	if revoked, _ := s.GetAPIKey(ctx, k.ID); revoked.Status != "revoked" || revoked.RevokedAt == nil {
		t.Fatalf("revoked: %+v", revoked)
	}

	if err := s.RevokeAPIKey(ctx, k.ID, actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking twice: %v", err)
	}
}

func TestChangeLogHeadAndPurge(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	xid, seq, err := s.Head(ctx)
	if err != nil || xid != "0" || seq != 0 {
		t.Fatalf("an empty change_log: %q %d %v", xid, seq, err)
	}

	for i := 0; i < 3; i++ {
		if _, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", fmt.Sprintf("090200030%d", i)), model.EntryInput{Category: "spam", RiskScore: 5}, actor); err != nil {
			t.Fatal(err)
		}
	}

	// Head chỉ trả dòng nằm trước xmin của cả cụm Postgres: một transaction mở ở nơi khác (phiên khác, pg_sleep) giữ xmin
	// lại thì Head hợp lệ trả "0". Khi đó test này không đo được gì, nên bỏ qua thay vì đỏ giả.
	var foreign int
	if err := s.write.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'
		AND pid <> pg_backend_pid() AND xact_start IS NOT NULL`).Scan(&foreign); err != nil {
		t.Fatal(err)
	}

	if foreign > 0 {
		t.Skipf("%d transaction mở ở nơi khác trong cụm Postgres đang giữ xmin", foreign)
	}

	xid, seq, err = s.Head(ctx)
	if err != nil || xid == "0" || seq == 0 {
		t.Fatalf("head must point at the latest change: %q %d %v", xid, seq, err)
	}

	if n, err := s.PurgeChanges(ctx, time.Hour); err != nil || n != 0 {
		t.Fatalf("recent changes must be kept: %d %v", n, err)
	}

	time.Sleep(20 * time.Millisecond)

	if n, err := s.PurgeChanges(ctx, time.Millisecond); err != nil || n != 3 {
		t.Fatalf("old changes are purged: %d %v", n, err)
	}
}

func TestParseExpiry(t *testing.T) {
	for in, want := range map[string]string{
		"2030-01-02":           "2030-01-02T00:00:00Z",
		"  2030-01-02  ":       "2030-01-02T00:00:00Z",
		"2030-01-02T15:04":     "2030-01-02T15:04:00Z",
		"2030-01-02T15:04:05Z": "2030-01-02T15:04:05Z",
	} {
		got, err := ParseExpiry(in)
		if err != nil || got == nil || got.UTC().Format(time.RFC3339) != want {
			t.Errorf("ParseExpiry(%q) = %v, %v; want %s", in, got, err, want)
		}
	}

	if got, err := ParseExpiry("  "); got != nil || err != nil {
		t.Errorf("empty means no expiry: %v %v", got, err)
	}

	for _, bad := range []string{"tomorrow", "2030-13-45", "01/02/2030"} {
		if _, err := ParseExpiry(bad); err == nil {
			t.Errorf("ParseExpiry(%q) must fail", bad)
		}
	}
}

func TestStoreConnectionHelpers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	if inUse, total := s.PoolStats(); inUse < 0 || total < 1 {
		t.Fatalf("pool stats: %d/%d", inUse, total)
	}

	_ = s.LastKeyCheck()

	// có replica: đọc đi qua replica; DSN sai thì lỗi rõ ràng
	dsn := os.Getenv("TEST_DATABASE_URL")

	both, err := New(ctx, dsn, dsn, 2)
	if err != nil {
		t.Fatal(err)
	}

	if err := both.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	both.Close()

	dead := "postgres://vsf:vsf@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"

	if _, err := New(ctx, dead, "", 2); err == nil || !strings.Contains(err.Error(), "open primary") {
		t.Fatalf("an unreachable primary: %v", err)
	}

	if _, err := New(ctx, dsn, dead, 2); err == nil || !strings.Contains(err.Error(), "open replica") {
		t.Fatalf("an unreachable replica: %v", err)
	}

	if _, err := New(ctx, "not a dsn ::", "", 2); err == nil {
		t.Fatal("a malformed DSN must be an error")
	}
}

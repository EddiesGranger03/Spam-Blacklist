package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	ctx := context.Background()
	s, err := New(ctx, dsn, "", 8)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(s.Close)
	s.SetSealer(newTestSealer(t))

	// CHỐT AN TOÀN: test này TRUNCATE (xóa sạch) mọi bảng. Chỉ chạy trên database có tên kết thúc bằng
	// "_test"; nếu lỡ trỏ TEST_DATABASE_URL vào DB thật (vd "vsf") thì dừng NGAY, chưa đụng gì tới dữ liệu.
	var dbName string
	if err := s.write.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		t.Fatal(err)
	}

	if !strings.HasSuffix(dbName, "_test") {
		t.Fatalf("TỪ CHỐI chạy: database %q không kết thúc bằng \"_test\"; test này sẽ XÓA SẠCH dữ liệu. "+
			"Hãy trỏ TEST_DATABASE_URL vào một database riêng cho test (vd vsf_test).", dbName)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}

	if _, err := s.write.Exec(ctx, `TRUNCATE blacklist_entries, change_log, audit_logs, sessions, api_keys, admins RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}

	return s
}

var actor = model.Actor{ID: 0, Email: "tester@example.com", IP: "127.0.0.1"}

func mustKey(t *testing.T, ty normalize.Type, m normalize.MatchType, raw string) normalize.Key {
	t.Helper()
	k, err := normalize.NormalizeEntry(ty, m, raw, "VN")
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func TestEntriesLifecycle(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	k := mustKey(t, normalize.TypeURL, normalize.MatchDomain, "evil.com")
	e, err := s.CreateEntry(ctx, k, model.EntryInput{Category: "phishing", RiskScore: 90}, actor)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateEntry(ctx, k, model.EntryInput{Category: "spam", RiskScore: 10}, actor); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}

	_, cands, err := normalize.Candidates(normalize.TypeURL, "http://a.evil.com/x?utm_source=1", "VN")
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.FindMatches(ctx, cands)
	if err != nil || len(got) != 1 || got[0].ID != e.ID || got[0].RiskScore != 90 {
		t.Fatalf("FindMatches = %+v, %v", got, err)
	}

	up, err := s.UpdateEntry(ctx, e.ID, model.EntryInput{Category: "scam", RiskScore: 70, Note: "n"}, actor)
	if err != nil || up.Category != "scam" || up.RiskScore != 70 {
		t.Fatalf("update = %+v, %v", up, err)
	}

	past := time.Now().Add(-time.Hour)
	if _, err := s.UpdateEntry(ctx, e.ID, model.EntryInput{Category: "scam", RiskScore: 70, ExpiresAt: &past}, actor); err != nil {
		t.Fatal(err)
	}

	if got, _ := s.FindMatches(ctx, cands); len(got) != 0 {
		t.Fatalf("expired entry must not match: %+v", got)
	}

	if err := s.DeleteEntry(ctx, e.ID, actor); err != nil {
		t.Fatal(err)
	}

	if err := s.DeleteEntry(ctx, e.ID, actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	if _, err := s.GetEntry(ctx, e.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestListPagination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	for _, p := range []string{"0901000001", "0901000002", "0901000003", "0901000004", "0901000005"} {
		if _, err := s.CreateEntry(ctx, mustKey(t, normalize.TypePhone, "", p), model.EntryInput{Category: "spam"}, actor); err != nil {
			t.Fatal(err)
		}
	}

	p1, next, err := s.ListEntries(ctx, ListFilter{Limit: 2})
	if err != nil || len(p1) != 2 || next == 0 {
		t.Fatalf("page1 = %d next=%d err=%v", len(p1), next, err)
	}

	p2, next2, _ := s.ListEntries(ctx, ListFilter{Limit: 2, Cursor: next})
	p3, next3, _ := s.ListEntries(ctx, ListFilter{Limit: 2, Cursor: next2})
	if len(p2) != 2 || len(p3) != 1 || next3 != 0 {
		t.Fatalf("p2=%d p3=%d next3=%d", len(p2), len(p3), next3)
	}

	if p1[0].ID <= p1[1].ID || p1[1].ID <= p2[0].ID {
		t.Fatal("expected strictly descending ids across pages")
	}

	_, keys, _ := normalize.Candidates(normalize.TypePhone, "+84 901 000 003", "VN")
	found, _, err := s.ListEntries(ctx, ListFilter{Search: keys})
	if err != nil || len(found) != 1 || found[0].Value != "+84901000003" {
		t.Fatalf("search = %+v, %v", found, err)
	}
}

type sliceIter struct {
	rows []ImportRow
	i    int
}

func (s *sliceIter) Next() (ImportRow, bool) {
	if s.i >= len(s.rows) {
		return ImportRow{}, false
	}

	s.i++
	return s.rows[s.i-1], true
}
func (s *sliceIter) Err() error { return nil }

func TestImportAndChanges(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	existing := mustKey(t, normalize.TypeURL, normalize.MatchDomain, "old.com")
	if _, err := s.CreateEntry(ctx, existing, model.EntryInput{Category: "spam", RiskScore: 10}, actor); err != nil {
		t.Fatal(err)
	}

	headX, headS, err := s.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}

	in := model.EntryInput{Category: "scam", RiskScore: 80}
	it := &sliceIter{rows: []ImportRow{
		{Key: mustKey(t, normalize.TypePhone, "", "0902000001"), Input: in},
		{Key: mustKey(t, normalize.TypePhone, "", "0902000002"), Input: in},
		{Key: mustKey(t, normalize.TypePhone, "", "0902000001"), Input: model.EntryInput{Category: "scam", RiskScore: 99}},
		{Key: existing, Input: in},
	}}
	res, err := s.Import(ctx, it, actor)
	if err != nil {
		t.Fatal(err)
	}

	if res.Inserted != 2 || res.Updated != 1 {
		t.Fatalf("import result = %+v, want inserted=2 updated=1", res)
	}

	got, err := s.FindMatches(ctx, []normalize.Key{mustKey(t, normalize.TypePhone, "", "0902000001")})
	if err != nil || len(got) != 1 || got[0].RiskScore != 99 {
		t.Fatalf("dedupe within file: %+v %v", got, err)
	}

	ch, err := s.ChangesSince(ctx, headX, headS, 1000)
	if err != nil {
		t.Fatal(err)
	}

	hashes := map[int64]bool{}

	for _, c := range ch {
		hashes[c.Hash] = true
	}

	if len(hashes) != 3 {
		t.Fatalf("want 3 distinct changed hashes, got %d (%+v)", len(hashes), ch)
	}

	n := 0
	if err := s.AllHashes(ctx, func(uint64) { n++ }); err != nil || n != 3 {
		t.Fatalf("AllHashes n=%d err=%v", n, err)
	}

	if est, err := s.EstimatedCount(ctx); err != nil || est < 0 {
		t.Fatalf("estimate = %d, %v", est, err)
	}
}

func TestAdminsSessionsAPIKeys(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, err := s.CreateAdmin(ctx, " Admin@Example.com ", "hash", model.RoleAdmin, actor)
	if err != nil || a.Email != "admin@example.com" {
		t.Fatalf("create admin = %+v, %v", a, err)
	}

	if _, err := s.CreateAdmin(ctx, "admin@example.com", "x", model.RoleViewer, actor); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("want ErrDuplicate, got %v", err)
	}

	id := []byte("session-hash-1234567890123456789")
	if err := s.CreateSession(ctx, id, a.ID, "csrf", "1.2.3.4", "ua", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	ss, err := s.GetSession(ctx, id)
	if err != nil || ss.Email != "admin@example.com" || ss.Role != model.RoleAdmin || ss.CSRFToken != "csrf" {
		t.Fatalf("session = %+v, %v", ss, err)
	}

	if err := s.UpdateAdmin(ctx, a.ID, model.RoleAdmin, true, actor); err != nil {
		t.Fatal(err)
	}

	if _, err := s.GetSession(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session should be gone, got %v", err)
	}

	k, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "n", Prefix: "abcd1234", KeyHash: []byte("h"), RPSLimit: 10}, actor)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.RevokeAPIKey(ctx, k.ID, actor); err != nil {
		t.Fatal(err)
	}

	got, _ := s.GetAPIKeyByPrefix(ctx, "abcd1234")
	if got.Status != "revoked" || got.RevokedAt == nil {
		t.Fatalf("key = %+v", got)
	}

	if err := s.RevokeAPIKey(ctx, k.ID, actor); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking twice: %v", err)
	}

	logs, _, err := s.ListAudit(ctx, 0, 100)
	if err != nil || len(logs) < 4 {
		t.Fatalf("audit logs = %d, %v", len(logs), err)
	}
}

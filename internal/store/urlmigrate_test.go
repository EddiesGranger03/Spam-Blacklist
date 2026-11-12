package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// legacyEntry lưu một entry url ĐÚNG như code trước M9 sẽ làm: giá trị được lấy nguyên văn (kể cả hoa/thường của path
// và mọi thứ khác) thay vì đi qua NormalizeEntry hiện tại, nên hash và chỉ mục blind là của luật cũ.
func legacyEntry(t *testing.T, s *Store, m normalize.MatchType, value string, score int, exp *time.Time) model.Entry {
	t.Helper()

	e, err := s.CreateEntry(context.Background(), normalize.MakeKey(normalize.TypeURL, m, value),
		model.EntryInput{Category: "phishing", RiskScore: score, ExpiresAt: exp}, actor)
	if err != nil {
		t.Fatal(err)
	}

	return e
}

// matchedBy trả về các entry khớp với một giá trị kiểm tra (qua tra cứu thật).
func matchedBy(t *testing.T, s *Store, check string) []model.Entry {
	t.Helper()

	_, cands, err := normalize.Candidates(normalize.TypeURL, check, "VN")
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.FindMatches(context.Background(), cands)
	if err != nil {
		t.Fatal(err)
	}

	return got
}

// M9: entry lưu theo luật path cũ phải được chuyển sang dạng chuẩn mới, nếu không chính việc đổi luật
// sẽ làm chúng ngừng khớp.
func TestURLPathMigrationMovesLegacyEntries(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	prefix := legacyEntry(t, s, normalize.MatchPrefix, "evil.com/SecurePath", 90, nil)
	exact := legacyEntry(t, s, normalize.MatchExact, "evil.com/Login?a=1", 80, nil)
	already := legacyEntry(t, s, normalize.MatchPrefix, "ok.com/x", 70, nil)

	domain, err := s.CreateEntry(ctx, mustKey(t, normalize.TypeURL, normalize.MatchDomain, "evil.com"),
		model.EntryInput{Category: "spam", RiskScore: 10}, actor)
	if err != nil {
		t.Fatal(err)
	}

	phone, err := s.CreateEntry(ctx, mustKey(t, normalize.TypePhone, "", "0902000555"),
		model.EntryInput{Category: "spam", RiskScore: 10}, actor)
	if err != nil {
		t.Fatal(err)
	}

	unparseable := legacyEntry(t, s, normalize.MatchPrefix, "localhost/Path", 50, nil) // no dot in host: today's rules reject it

	// Trước đó: hash cũ đã lỗi thời, nên entry không còn khớp với những gì Candidates tính ra.
	for _, e := range matchedBy(t, s, "http://EVIL.COM/SECUREPATH/x") {
		if e.ID == prefix.ID {
			t.Fatal("trước migration entry cũ chưa được khớp bằng khóa chuẩn mới (đây là lý do phải migrate)")
		}
	}

	headX, headS, err := s.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}

	res, err := s.canonicalizeURLPaths(ctx, 2, 2) // tiny pages to exercise the batching
	if err != nil {
		t.Fatal(err)
	}

	if res.Scanned != 5 || res.Changed != 2 || res.Merged != 0 || res.Skipped != 1 {
		t.Fatalf("res = %+v, want scanned=5 (url prefix/exact/domain) changed=2 merged=0 skipped=1", res)
	}

	for _, v := range []string{"http://EVIL.COM/SECUREPATH/x", "http://evil.com//securepath/./x", "http://evil.com/%73ecurepath/x"} {
		found := false

		for _, e := range matchedBy(t, s, v) {
			if e.ID == prefix.ID {
				found = true
			}
		}

		if !found {
			t.Errorf("sau migration entry prefix phải chặn %q", v)
		}
	}

	exactFound := false

	for _, e := range matchedBy(t, s, "http://EVIL.com/LOGIN/?a=1&utm_source=z") { // the evil.com domain entry matches too
		if e.ID == exact.ID {
			exactFound = true
		}
	}

	if !exactFound {
		t.Error("sau migration entry exact phải khớp")
	}

	e, err := s.GetEntry(ctx, prefix.ID)
	if err != nil || e.Value != "evil.com/securepath" {
		t.Fatalf("giá trị đã lưu phải được viết lại thành dạng chuẩn: %+v %v", e, err)
	}

	if e.RiskScore != 90 || e.Category != "phishing" {
		t.Fatalf("migration chỉ đổi khóa, không được đổi dữ liệu khác: %+v", e)
	}

	// Changefeed phải biết các hash mới, nếu không các instance đang chạy sẽ tiếp tục bỏ sót entry đã chuyển.
	ch, err := s.ChangesSince(ctx, headX, headS, 100)
	if err != nil {
		t.Fatal(err)
	}

	logged := map[int64]bool{}
	for _, c := range ch {
		logged[c.Hash] = true
	}

	newPrefix, _ := normalize.NormalizeEntry(normalize.TypeURL, normalize.MatchPrefix, "evil.com/securepath", "VN")
	newExact, _ := normalize.NormalizeEntry(normalize.TypeURL, normalize.MatchExact, "evil.com/login?a=1", "VN")

	if !logged[newPrefix.Hash] || !logged[newExact.Hash] {
		t.Fatalf("change_log phải có hash mới của các entry đã chuyển (cần cho Bloom): %+v", ch)
	}

	// Mọi thứ không cần đổi thì giữ nguyên.
	for _, id := range []int64{already.ID, domain.ID, phone.ID, unparseable.ID} {
		if _, err := s.GetEntry(ctx, id); err != nil {
			t.Errorf("entry %d không được mất: %v", id, err)
		}
	}

	if got := matchedBy(t, s, "http://ok.com/x/y"); len(got) == 0 || got[0].ID != already.ID {
		t.Error("entry đã chuẩn từ trước vẫn phải khớp")
	}

	// Idempotent: lần chạy thứ hai không tìm thấy gì để làm.
	res, err = s.canonicalizeURLPaths(ctx, 2, 2)
	if err != nil || res.Changed != 0 || res.Merged != 0 {
		t.Fatalf("chạy lại phải là no-op: %+v %v", res, err)
	}
}

// Hai entry cũ chỉ khác hoa/thường sẽ gộp thành một: entry thắng là entry có risk cao hơn (rồi tới
// id nhỏ hơn), và expiry là expiry bảo vệ nhiều nhất của hai (không hết hạn thắng mọi ngày, ngày muộn thắng ngày sớm).
func TestURLPathMigrationMergesCollisions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	later := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	earlier := time.Now().Add(24 * time.Hour).Truncate(time.Second)

	// Nhóm 1: cả ba gộp thành evil.com/admin. Entry chuẩn (y) hòa risk với z, nên id nhỏ hơn thắng.
	x := legacyEntry(t, s, normalize.MatchPrefix, "evil.com/Admin", 50, nil)
	y := legacyEntry(t, s, normalize.MatchPrefix, "evil.com/admin", 80, &later)
	z := legacyEntry(t, s, normalize.MatchPrefix, "evil.com/ADMIN", 80, nil)

	// Nhóm 2: entry phải CHUYỂN thắng (risk cao hơn); expiry trở thành ngày muộn hơn trong hai.
	w := legacyEntry(t, s, normalize.MatchPrefix, "evil2.com/Shop", 90, &earlier)
	v := legacyEntry(t, s, normalize.MatchPrefix, "evil2.com/shop", 10, &later)

	res, err := s.canonicalizeURLPaths(ctx, 100, 100)
	if err != nil {
		t.Fatal(err)
	}

	if res.Merged != 3 || res.Changed != 3 {
		t.Fatalf("res = %+v, want changed=3 (x, z, w) merged=3", res)
	}

	for _, id := range []int64{x.ID, z.ID, v.ID} {
		if _, err := s.GetEntry(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("entry %d phải bị gộp (xóa), got %v", id, err)
		}
	}

	ys, err := s.GetEntry(ctx, y.ID)
	if err != nil || ys.RiskScore != 80 || ys.ExpiresAt != nil || ys.Value != "evil.com/admin" {
		t.Fatalf("người thắng nhóm 1 phải là y, risk 80, KHÔNG hết hạn (bảo vệ nhiều nhất): %+v %v", ys, err)
	}

	ws, err := s.GetEntry(ctx, w.ID)
	if err != nil || ws.RiskScore != 90 || ws.Value != "evil2.com/shop" {
		t.Fatalf("người thắng nhóm 2 phải là w (risk 90) và đã chuyển sang khóa chuẩn: %+v %v", ws, err)
	}

	if ws.ExpiresAt == nil || !ws.ExpiresAt.Equal(later) {
		t.Fatalf("hết hạn phải là ngày muộn hơn (%v), got %v", later, ws.ExpiresAt)
	}

	if got := matchedBy(t, s, "http://EVIL2.com/SHOP/x"); len(got) != 1 || got[0].ID != w.ID {
		t.Fatalf("sau khi gộp chỉ còn đúng một entry khớp: %+v", got)
	}
}

// Hàm bao khởi động chạy migration đúng một lần, ghi nhận đã chạy, và để lại một dòng audit kèm tổng số.
func TestURLPathMigrationRunsOnceAndIsAudited(t *testing.T) {
	s := newTestStore(t)
	s.SetAuditKey(AuditKeyFrom("", "test-secret"))
	ctx := context.Background()

	// newTestStore đã chạy Migrate trên bảng rỗng, và việc đó đã ghi dấu; xóa dấu để chạy thật.
	if _, err := s.write.Exec(ctx, `DELETE FROM schema_migrations WHERE version = $1`, urlPathMigrationVersion); err != nil {
		t.Fatal(err)
	}

	legacyEntry(t, s, normalize.MatchPrefix, "evil.com/SecurePath", 90, nil)

	if err := s.runURLPathMigration(ctx); err != nil {
		t.Fatal(err)
	}

	var n int
	if err := s.write.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = $1`, urlPathMigrationVersion).Scan(&n); err != nil || n != 1 {
		t.Fatalf("migration phải để lại dấu đã chạy: n=%d err=%v", n, err)
	}

	// (entry mẫu cũng để lại một dòng entry.create, nên chỉ xem các dòng của chính migration)
	summaries := func() (details []string) {
		actions, all := auditActions(t, s)
		for i, a := range actions {
			if a == "migrate.url_path_canonical" {
				details = append(details, all[i])
			}
		}

		return details
	}

	details := summaries()
	if len(details) != 1 {
		t.Fatalf("phải có đúng một dòng audit tổng kết, got %d", len(details))
	}

	if d := auditDetail(t, details[0]); d["changed"] != float64(1) || d["merged"] != float64(0) {
		t.Fatalf("audit thiếu tổng kết: %v", d)
	}

	if err := s.runURLPathMigration(ctx); err != nil { // second start-up: no-op, no second audit row
		t.Fatal(err)
	}

	if n := len(summaries()); n != 1 {
		t.Fatalf("chạy lần hai không được ghi thêm audit, có %d dòng", n)
	}

	if v, err := s.VerifyAuditChain(ctx); err != nil || !v.OK {
		t.Fatalf("chuỗi audit phải còn nguyên: %+v %v", v, err)
	}
}

// Quy tắc v2: entry cũ ghi dưới dạng "evil.org/Login;jsessionid=1" hoặc host IP kiểu thập phân phải được đưa về dạng
// chuẩn, để các URL viết khác đi (";x=2", "0x7f000001", "\") vẫn bị chặn.
func TestURLPathMigrationV2Rules(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	param := legacyEntry(t, s, normalize.MatchPrefix, "evil.org/Login;jsessionid=1", 90, nil)
	ip := legacyEntry(t, s, normalize.MatchPrefix, "2130706433/admin", 80, nil)

	res, err := s.canonicalizeURLPaths(ctx, 10, 10)
	if err != nil {
		t.Fatal(err)
	}

	if res.Changed != 2 || res.Skipped != 0 {
		t.Fatalf("res = %+v, want changed=2 skipped=0", res)
	}

	cases := map[int64][]string{
		param.ID: {"http://evil.org/login", "http://EVIL.org/Login;jsessionid=999", `http://evil.org\login`},
		ip.ID:    {"http://127.0.0.1/admin", "http://0x7f.1/admin/x", "http://0177.0.0.1/admin", "http://2130706433/admin"},
	}

	for id, urls := range cases {
		for _, u := range urls {
			found := false

			for _, e := range matchedBy(t, s, u) {
				if e.ID == id {
					found = true
				}
			}

			if !found {
				t.Errorf("entry %d phải chặn %q sau migration", id, u)
			}
		}
	}
}

package store

import (
	"context"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// mustCandidates tạo các khóa ứng viên cho một giá trị và báo lỗi test nếu chuẩn hóa thất bại.
func mustCandidates(t *testing.T, ty normalize.Type, raw string) []normalize.Key {
	t.Helper()

	_, keys, err := normalize.Candidates(ty, raw, "VN")
	if err != nil {
		t.Fatal(err)
	}

	return keys
}

// matchedIDs trả về tập ID của các entry đã cho, để so sánh kết quả.
func matchedIDs(entries []model.Entry) map[int64]bool {
	out := map[int64]bool{}
	for _, e := range entries {
		out[e.ID] = true
	}

	return out
}

// FindMatches phải trả về đúng các entry có (hash, type, match_type, blind) bằng một trong các khóa ứng viên:
// không thừa, không thiếu, và không bao giờ trả entry đã hết hạn.
func TestFindMatches_MultiKeyAndFilters(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := model.EntryInput{Category: "spam", RiskScore: 80}

	domain, err := s.CreateEntry(ctx, mustKey(t, normalize.TypeURL, normalize.MatchDomain, "evil.com"), in, actor)
	if err != nil {
		t.Fatal(err)
	}

	prefix, err := s.CreateEntry(ctx, mustKey(t, normalize.TypeURL, normalize.MatchPrefix, "shop.example.org/bad"), in, actor)
	if err != nil {
		t.Fatal(err)
	}

	phone, err := s.CreateEntry(ctx, mustKey(t, normalize.TypePhone, "", "0902000001"), in, actor)
	if err != nil {
		t.Fatal(err)
	}

	past := time.Now().Add(-time.Hour)
	if _, err := s.CreateEntry(ctx, mustKey(t, normalize.TypeURL, normalize.MatchDomain, "expired.com"),
		model.EntryInput{Category: "spam", RiskScore: 50, ExpiresAt: &past}, actor); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateEntry(ctx, mustKey(t, normalize.TypeURL, normalize.MatchDomain, "unrelated.net"), in, actor); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		keys []normalize.Key
		want []int64
	}{
		{"subdomain hits domain entry", mustCandidates(t, normalize.TypeURL, "http://a.evil.com/x?utm_source=1"), []int64{domain.ID}},
		{"path under prefix entry", mustCandidates(t, normalize.TypeURL, "http://shop.example.org/bad/item"), []int64{prefix.ID}},
		{"other path is not blocked", mustCandidates(t, normalize.TypeURL, "http://shop.example.org/good"), nil},
		{"expired entry is ignored", mustCandidates(t, normalize.TypeURL, "http://expired.com/"), nil},
		{"unknown url", mustCandidates(t, normalize.TypeURL, "http://nothing-here.org/"), nil},
		{"phone", mustCandidates(t, normalize.TypePhone, "0902000001"), []int64{phone.ID}},
		{"unknown phone", mustCandidates(t, normalize.TypePhone, "0902999999"), nil},
		{"phone and url keys in one call", append(mustCandidates(t, normalize.TypePhone, "0902000001"),
			mustCandidates(t, normalize.TypeURL, "http://evil.com/")...), []int64{phone.ID, domain.ID}},
		{"no keys", nil, nil},
	}

	for _, c := range cases {
		got, err := s.FindMatches(ctx, c.keys)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}

		ids := matchedIDs(got)
		if len(got) != len(c.want) {
			t.Errorf("%s: got %d entries %+v, want ids %v", c.name, len(got), ids, c.want)
			continue
		}

		for _, id := range c.want {
			if !ids[id] {
				t.Errorf("%s: missing entry %d (got %v)", c.name, id, ids)
			}
		}
	}
}

// Một khóa mà các phần không thuộc cùng một entry thì không được khớp, kể cả khi từng phần riêng lẻ có trong bảng.
// Test này bảo vệ phép so khớp chính xác theo từng khóa.
func TestFindMatches_MismatchedKeyPartsDoNotMatch(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := model.EntryInput{Category: "spam", RiskScore: 80}

	kEvil := mustKey(t, normalize.TypeURL, normalize.MatchDomain, "evil.com")
	kOther := mustKey(t, normalize.TypeURL, normalize.MatchDomain, "other.com")

	if _, err := s.CreateEntry(ctx, kEvil, in, actor); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateEntry(ctx, kOther, in, actor); err != nil {
		t.Fatal(err)
	}

	// hash của entry này ghép với blind index của entry kia, và ngược lại:
	// mỗi hash và mỗi blind đều có trong bảng, nhưng không bao giờ cùng xuất hiện trong một ứng viên.
	crossA := kEvil
	crossA.Blind = kOther.Blind
	crossB := kOther
	crossB.Blind = kEvil.Blind

	wrongMatch := kEvil
	wrongMatch.MatchType = normalize.MatchPrefix

	wrongType := kEvil
	wrongType.Type = normalize.TypePhone

	for name, keys := range map[string][]normalize.Key{
		"hash and blind from different entries": {crossA, crossB},
		"right hash+blind, wrong match_type":    {wrongMatch},
		"right hash+blind, wrong type":          {wrongType},
	} {
		got, err := s.FindMatches(ctx, keys)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if len(got) != 0 {
			t.Errorf("%s: must not match, got %+v", name, got)
		}
	}

	// kiểm tra tỉnh táo: các khóa đúng vẫn khớp, riêng lẻ và cùng nhau.
	got, err := s.FindMatches(ctx, []normalize.Key{kEvil, kOther})
	if err != nil || len(got) != 2 {
		t.Fatalf("genuine keys: got %d entries, err=%v", len(got), err)
	}
}

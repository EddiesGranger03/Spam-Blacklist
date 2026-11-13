package normalize

import "testing"

// hitEntry cho biết một entry (đã chuẩn hóa) có nằm trong tập khóa ứng viên của URL raw hay không,
// tức là /v1/check sẽ chặn raw nếu entry này nằm trong DB.
func hitEntry(t *testing.T, entry Key, raw string) bool {
	t.Helper()

	_, cands, err := Candidates(TypeURL, raw, "VN")
	if err != nil {
		t.Fatalf("Candidates(%q): %v", raw, err)
	}

	for _, c := range cands {
		if c.Hash == entry.Hash && c.Value == entry.Value && c.MatchType == entry.MatchType && string(c.Blind) == string(entry.Blind) {
			return true
		}
	}

	return false
}

// Ví dụ trong checklist: entry domain "evil.com" phải chặn http://a.evil.com/x?utm_source=1.
func TestChecklistDomainEntryBlocksSubdomainWithTracking(t *testing.T) {
	dom, err := NormalizeEntry(TypeURL, MatchDomain, "evil.com", "VN")
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []string{
		"http://a.evil.com/x?utm_source=1",
		"http://evil.com/x?utm_source=1",
		"https://WWW.Evil.com/x",
		"http://deep.sub.evil.com/",
	} {
		if !hitEntry(t, dom, v) {
			t.Errorf("entry domain evil.com phải chặn %q", v)
		}
	}

	// Domain khác (kể cả chỉ khác một phần tên miền) không được bị chặn oan.
	for _, v := range []string{"http://notevil.com/x", "http://evil.com.example.org/x", "http://evil2.com/x"} {
		if hitEntry(t, dom, v) {
			t.Errorf("entry domain evil.com không được chặn %q", v)
		}
	}
}

// Ví dụ trong checklist: prefix "evil2.com/shop" chặn /shop và trang con nhưng không chặn /blog.
func TestChecklistPrefixEntryDoesNotBlockSiblingPath(t *testing.T) {
	pre, err := NormalizeEntry(TypeURL, MatchPrefix, "evil2.com/shop", "VN")
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []string{
		"http://evil2.com/shop",
		"http://evil2.com/shop/",
		"http://evil2.com/shop/item?id=5",
		"http://EVIL2.com/Shop/x?utm_source=1",
	} {
		if !hitEntry(t, pre, v) {
			t.Errorf("entry prefix evil2.com/shop phải chặn %q", v)
		}
	}

	for _, v := range []string{
		"http://evil2.com/blog",
		"http://evil2.com/blog/shop",
		"http://evil2.com/shopping",
		"http://evil2.com/",
		"http://evil.com/shop",
	} {
		if hitEntry(t, pre, v) {
			t.Errorf("entry prefix evil2.com/shop không được chặn %q", v)
		}
	}
}

package normalize

import (
	"math/rand"
	"testing"
)

// M9: phần path của URL phải về một dạng chuẩn, để cách viết hoa/thường, "//", "/./", "%7e"... không qua mặt được
// entry khớp theo path (docs/ATTACK_PUBLIC_API.md). Host đã được chuẩn hóa từ trước.
func TestParseURLCanonicalPath(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"mixed case path", "http://Evil.com/SecurePath/X", "evil.com/securepath/x"},
		{"all upper", "http://EVIL.COM/SECUREPATH", "evil.com/securepath"},
		{"double slash", "http://evil.com//a///b", "evil.com/a/b"},
		{"dot segment", "http://evil.com/a/./b", "evil.com/a/b"},
		{"dot dot", "http://evil.com/a/b/../c", "evil.com/a/c"},
		{"dot dot above root", "http://evil.com/../../a", "evil.com/a"},
		{"unreserved percent decoded", "http://evil.com/%73ecure%7Epath", "evil.com/secure~path"},
		{"unreserved percent decoded lower hex", "http://evil.com/%73ecure%7epath", "evil.com/secure~path"},
		{"encoded dots are dot segments", "http://evil.com/a/%2e%2e/b", "evil.com/b"},
		{"encoded slash kept (structure)", "http://evil.com/a%2Fb", "evil.com/a%2fb"},
		{"encoded slash hex case", "http://evil.com/a%2fB", "evil.com/a%2fb"},
		{"query keeps its case", "http://evil.com/A?Token=AbC", "evil.com/a?Token=AbC"},
		{"unicode path", "http://evil.com/Café", "evil.com/caf%c3%a9"},
		{"root", "http://evil.com/", "evil.com"},
		{"only slashes", "http://evil.com///", "evil.com"},
		{"trailing slash after dots", "http://evil.com/a/b/./", "evil.com/a/b"},
		{"custom port kept", "http://Evil.com:8080/A//B", "evil.com:8080/a/b"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseURL(tc.in)
			if err != nil || p.Full() != tc.want {
				t.Fatalf("ParseURL(%q).Full() = %q, %v; want %q", tc.in, p.Full(), err, tc.want)
			}
		})
	}
}

// Chuẩn hóa hai lần phải ra cùng kết quả: nếu không, giá trị đã lưu (đã chuẩn hóa) sẽ không khớp lại khi migration
// hoặc khi tra cứu chuẩn hóa thêm một lần nữa.
func TestParseURLCanonicalPathIsIdempotent(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []string{"a", "B", "c", "/", "/", ".", "..", "%2e", "%2E", "%2f", "%2F", "%7e", "%41", "%c3%a9", "%25", "-", "_", "~", "x1"}
	checked := 0

	for i := 0; i < 20000; i++ {
		path := ""
		for n := rng.Intn(10); n >= 0; n-- {
			path += alphabet[rng.Intn(len(alphabet))]
		}

		p1, err := ParseURL("http://Evil.com/" + path)
		if err != nil {
			continue
		}

		checked++

		p2, err := ParseURL(p1.Full())
		if err != nil || p2.Full() != p1.Full() {
			t.Fatalf("không idempotent với path %q: lần 1 = %q, lần 2 = %q (%v)", path, p1.Full(), p2.Full(), err)
		}
	}

	if checked < 5000 {
		t.Fatalf("chỉ %d mẫu hợp lệ, bộ sinh dữ liệu quá hẹp", checked)
	}
}

// Entry (khi tạo/import) và tra cứu phải cùng một dạng chuẩn: mọi cách viết khác nhau của cùng một đường dẫn phải
// khớp cùng một entry, còn đường dẫn khác thật sự thì không.
func TestEntryAndCandidatesAgreeOnPathVariants(t *testing.T) {
	hit := func(k Key, check string) bool {
		_, cands, err := Candidates(TypeURL, check, "VN")
		if err != nil {
			t.Fatalf("Candidates(%q): %v", check, err)
		}

		for _, c := range cands {
			if c.Hash == k.Hash && c.Value == k.Value && c.MatchType == k.MatchType && string(c.Blind) == string(k.Blind) {
				return true
			}
		}

		return false
	}

	prefix, err := NormalizeEntry(TypeURL, MatchPrefix, "Evil.com/SecurePath", "VN")
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []string{
		"http://evil.com/SecurePath/x",
		"http://EVIL.COM/SECUREPATH/x",
		"http://evil.com/securepath/x",
		"http://evil.com//securepath/./x",
		"http://evil.com/%73ecurepath/x",
		"http://evil.com/a/../SecurePath/x",
		"evil.com/SecurePath/x?utm_source=1",
	} {
		if !hit(prefix, v) {
			t.Errorf("entry prefix evil.com/SecurePath phải chặn %q", v)
		}
	}

	for _, v := range []string{"http://evil.com/securepath2", "http://evil.com/other/securepath", "http://evil.com/"} {
		if hit(prefix, v) {
			t.Errorf("entry prefix evil.com/SecurePath không được chặn %q", v)
		}
	}

	exact, err := NormalizeEntry(TypeURL, MatchExact, "http://Evil.com/Login?B=2&a=1", "VN")
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range []string{"http://evil.com/login?a=1&B=2", "http://EVIL.com//LOGIN/?a=1&B=2&fbclid=z"} {
		if !hit(exact, v) {
			t.Errorf("entry exact phải khớp %q", v)
		}
	}

	if hit(exact, "http://evil.com/login?a=1&b=2") { // tên tham số query vẫn phân biệt hoa/thường
		t.Error("query giữ nguyên hoa/thường: B=2 khác b=2")
	}
}

// Các cách viết khác của cùng một URL mà trình duyệt vẫn mở như nhau phải về cùng một dạng chuẩn.
func TestParseURLEvasions(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"backslash path", `http://evil.com\a\b`, "evil.com/a/b"},
		{"backslash after scheme", `http:\evil.com\a`, "evil.com/a"},
		{"two backslashes after scheme", "http:\\\\evil.com\\a", "evil.com/a"},
		{"single slash after scheme", "http:/evil.com/a", "evil.com/a"},
		{"many slashes after scheme", "https:////evil.com/a", "evil.com/a"},
		{"backslash only before query", `http://evil.com\a?x=\y`, `evil.com/a?x=%5Cy`},
		{"jsessionid param", "http://evil.com/login;jsessionid=ABC123", "evil.com/login"},
		{"param mid path", "http://evil.com/a;x=1/b;y=2", "evil.com/a/b"},
		{"param only segment dropped", "http://evil.com/a/;x=1/b", "evil.com/a/b"},
		{"decimal ip", "http://2130706433/x", "127.0.0.1/x"},
		{"hex ip", "http://0x7f000001/x", "127.0.0.1/x"},
		{"hex dotted", "http://0x7f.0x0.0x0.0x1/x", "127.0.0.1/x"},
		{"octal ip", "http://0177.0.0.1/x", "127.0.0.1/x"},
		{"mixed bases", "http://0x7f.1/x", "127.0.0.1/x"},
		{"three parts", "http://127.1.1/x", "127.1.0.1/x"},
		{"plain ip unchanged", "http://8.8.8.8/x", "8.8.8.8/x"},
		{"ip with port", "http://2130706433:8080/x", "127.0.0.1:8080/x"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseURL(tc.in)
			if err != nil || p.Full() != tc.want {
				t.Fatalf("ParseURL(%q).Full() = %q, %v; want %q", tc.in, p.Full(), err, tc.want)
			}

			// idempotent: giá trị đã lưu phải giữ nguyên khi chuẩn hóa lại
			again, err := ParseURL(p.Full())
			if err != nil || again.Full() != p.Full() {
				t.Fatalf("not idempotent: %q -> %q (%v)", p.Full(), again.Full(), err)
			}
		})
	}
}

// Tên miền thật không được bị coi là IP, và số không hợp lệ không được đổi bừa.
func TestLegacyIPv4LeavesDomainsAlone(t *testing.T) {
	for _, h := range []string{"evil.com", "a.b.c.d.e", "1.2.3.4.5", "0xzz.1", "256.1.1.1", "999999999999", "08.1", "example.co.uk", "0x1ffffffff"} {
		if got, ok := legacyIPv4(h); ok {
			t.Errorf("legacyIPv4(%q) = %q, want no conversion", h, got)
		}
	}
}

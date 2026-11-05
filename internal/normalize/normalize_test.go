package normalize

import (
	"errors"
	"reflect"
	"testing"
)

func TestPhone(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"vn local", "0901234567", "+84901234567", false},
		{"vn spaces", "0901 234 567", "+84901234567", false},
		{"vn plus", "+84 901 234 567", "+84901234567", false},
		{"vn no plus", "84901234567", "+84901234567", false},
		{"vn dashes", "+84-901-234-567", "+84901234567", false},
		{"us international", "+1 415 555 2671", "+14155552671", false},
		{"empty", "", "", true},
		{"letters", "abc", "", true},
		{"too short", "12", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Phone(tc.in, "VN")

			if tc.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("want ErrInvalid, got %v", err)
				}

				return
			}

			if err != nil || got != tc.want {
				t.Fatalf("Phone(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestParseURL(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"basic", "http://evil.com", "evil.com", false},
		{"no scheme", "Evil.COM/a", "evil.com/a", false},
		{"www and trailing slash", "https://www.evil.com/a/", "evil.com/a", false},
		{"tracking removed, query sorted", "HTTPS://WWW.Example.COM/a/?utm_x=1&b=2&a=1&fbclid=zz#frag", "example.com/a?a=1&b=2", false},
		{"default port dropped", "https://evil.com:443/x", "evil.com/x", false},
		{"custom port kept", "http://evil.com:8080/x", "evil.com:8080/x", false},
		{"userinfo ignored", "http://user:pw@evil.com/x", "evil.com/x", false},
		{"punycode", "http://bücher.example/x", "xn--bcher-kva.example/x", false},
		{"ip", "http://1.2.3.4/x", "1.2.3.4/x", false},
		{"protocol-relative", "//evil.com/x", "evil.com/x", false},
		{"empty", "", "", true},
		{"no dot host", "http://localhost/x", "", true},
		{"ftp scheme", "ftp://evil.com", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseURL(tc.in)

			if tc.wantErr {
				if !errors.Is(err, ErrInvalid) {
					t.Fatalf("want ErrInvalid, got %v", err)
				}

				return
			}

			if err != nil || p.Full() != tc.want {
				t.Fatalf("ParseURL(%q).Full() = %q, %v; want %q", tc.in, p.Full(), err, tc.want)
			}
		})
	}
}

func TestDomainChain(t *testing.T) {
	got := domainChain("a.b.example.com")
	want := []string{"a.b.example.com", "b.example.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	got = domainChain("x.foo.co.uk")
	want = []string{"x.foo.co.uk", "foo.co.uk"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}

	if got := domainChain("1.2.3.4"); !reflect.DeepEqual(got, []string{"1.2.3.4"}) {
		t.Fatalf("ip chain: %v", got)
	}
}

func TestNormalizeEntry(t *testing.T) {
	k, err := NormalizeEntry(TypePhone, "", "0901 234 567", "VN")
	if err != nil || k.Value != "+84901234567" || k.MatchType != MatchExact {
		t.Fatalf("phone: %+v %v", k, err)
	}

	if _, err := NormalizeEntry(TypePhone, MatchDomain, "0901234567", "VN"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("phone+domain should fail, got %v", err)
	}

	k, err = NormalizeEntry(TypeURL, "", "https://www.Evil.com", "VN")
	if err != nil || k.Value != "evil.com" || k.MatchType != MatchDomain {
		t.Fatalf("domain: %+v %v", k, err)
	}

	if _, err := NormalizeEntry(TypeURL, MatchDomain, "evil.com/shop", "VN"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("domain with path should fail, got %v", err)
	}

	k, err = NormalizeEntry(TypeURL, MatchPrefix, "http://evil2.com/shop/", "VN")
	if err != nil || k.Value != "evil2.com/shop" {
		t.Fatalf("prefix: %+v %v", k, err)
	}

	if _, err := NormalizeEntry(TypeURL, MatchPrefix, "evil2.com/shop?a=1", "VN"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prefix with query should fail, got %v", err)
	}

	if _, err := NormalizeEntry("email", "", "a@b.com", "VN"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown type should fail, got %v", err)
	}
}

func has(keys []Key, m MatchType, v string) bool {
	for _, k := range keys {
		if k.MatchType == m && k.Value == v {
			return true
		}
	}

	return false
}

func TestCandidatesURL(t *testing.T) {
	norm, keys, err := Candidates(TypeURL, "http://a.evil.com/shop/item?utm_source=1&id=5", "VN")
	if err != nil {
		t.Fatal(err)
	}

	if norm != "a.evil.com/shop/item?id=5" {
		t.Fatalf("normalized = %q", norm)
	}

	mustHave := []struct {
		m MatchType
		v string
	}{
		{MatchExact, "a.evil.com/shop/item?id=5"},
		{MatchPrefix, "a.evil.com"},
		{MatchPrefix, "a.evil.com/shop"},
		{MatchPrefix, "a.evil.com/shop/item"},
		{MatchDomain, "a.evil.com"},
		{MatchDomain, "evil.com"},
	}
	for _, w := range mustHave {
		if !has(keys, w.m, w.v) {
			t.Errorf("missing candidate %s %q in %+v", w.m, w.v, keys)
		}
	}

	if has(keys, MatchDomain, "com") {
		t.Errorf("must not include public suffix 'com'")
	}
}

func TestStoredKeyMatchesCandidate(t *testing.T) {
	stored := func(m MatchType, raw string) Key {
		k, err := NormalizeEntry(TypeURL, m, raw, "VN")
		if err != nil {
			t.Fatal(err)
		}

		return k
	}

	hit := func(k Key, check string) bool {
		_, cands, err := Candidates(TypeURL, check, "VN")
		if err != nil {
			t.Fatal(err)
		}

		for _, c := range cands {
			if c.Hash == k.Hash && c.Value == k.Value && c.MatchType == k.MatchType {
				return true
			}
		}

		return false
	}

	if !hit(stored(MatchDomain, "evil.com"), "http://x.evil.com/abc?utm_source=1") {
		t.Error("domain evil.com should block x.evil.com")
	}

	if hit(stored(MatchDomain, "evil.com"), "http://notevil.com/") {
		t.Error("domain evil.com must not block notevil.com")
	}

	p := stored(MatchPrefix, "evil2.com/shop")
	if !hit(p, "https://www.evil2.com/shop/item1") {
		t.Error("prefix should block /shop/item1")
	}

	if hit(p, "https://evil2.com/blog") {
		t.Error("prefix must not block /blog")
	}

	if hit(p, "https://evil2.com/shopping") {
		t.Error("prefix must respect segment boundary")
	}

	e := stored(MatchExact, "evil3.com/a?b=1&a=2")
	if !hit(e, "http://EVIL3.com/a/?a=2&b=1&utm_medium=x") {
		t.Error("exact should match after normalization")
	}

	pk, _ := NormalizeEntry(TypePhone, "", "0901234567", "VN")
	_, pc, _ := Candidates(TypePhone, "+84 901 234 567", "VN")
	if len(pc) != 1 || pc[0].Hash != pk.Hash {
		t.Error("phone variants must produce the same key")
	}
}

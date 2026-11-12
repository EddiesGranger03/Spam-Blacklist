package normalize

import "testing"

// Các cách viết khác nhau của cùng một địa chỉ IP phải cho cùng một host chuẩn (IPv6 viết gọn, IPv4-mapped về IPv4).
func TestParseURLCanonicalizesIPHosts(t *testing.T) {
	cases := map[string]string{
		"http://[2001:0DB8:0:0:0:0:0:1]/x":    "2001:db8::1",
		"http://[2001:db8::1]/x":              "2001:db8::1",
		"http://[2001:DB8::0001]/x":           "2001:db8::1",
		"http://[0:0:0:0:0:0:0:1]/":           "::1",
		"http://[::ffff:1.2.3.4]/":            "1.2.3.4",
		"http://[::FFFF:0102:0304]/":          "1.2.3.4",
		"http://2130706433/":                  "127.0.0.1",
		"http://0x7f.1/":                      "127.0.0.1",
		"http://EVIL.example/":                "evil.example",
		"http://[2001:db8::1]:8080/a":         "2001:db8::1",
		"http://[2001:0db8:0000:0000::0001]/": "2001:db8::1",
	}

	for in, want := range cases {
		p, err := ParseURL(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}

		if p.Hostname != want {
			t.Errorf("%s: host = %q, want %q", in, p.Hostname, want)
		}
	}
}

// Giá trị entry domain đã lưu được đưa về dạng chuẩn, kể cả host là IP; giá trị đã chuẩn thì giữ nguyên (idempotent).
func TestCanonicalURLValueDomain(t *testing.T) {
	cases := map[string]string{
		"2001:0DB8::1": "2001:db8::1",
		"2001:db8::1":  "2001:db8::1",
		"2130706433":   "127.0.0.1",
		"Evil.COM":     "evil.com",
		"evil.com":     "evil.com",
	}

	for in, want := range cases {
		got, err := CanonicalURLValue(MatchDomain, in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}

		if got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}

		again, err := CanonicalURLValue(MatchDomain, got)
		if err != nil || again != got {
			t.Errorf("%s: không idempotent (%q -> %q, err %v)", in, got, again, err)
		}
	}
}

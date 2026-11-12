package normalize

import "strings"

// NormalizeEntry chuẩn hóa giá trị khi tạo hoặc nhập entry và trả về Key tương ứng.
func NormalizeEntry(t Type, m MatchType, raw, region string) (Key, error) {
	switch t {
	case TypePhone:
		if m != "" && m != MatchExact {
			return Key{}, invalidf("phone only supports match_type %q", MatchExact)
		}

		e164, err := Phone(raw, region)
		if err != nil {
			return Key{}, err
		}

		return MakeKey(TypePhone, MatchExact, e164), nil

	case TypeURL:
		p, err := ParseURL(raw)
		if err != nil {
			return Key{}, err
		}

		if m == "" {
			m = MatchDomain
		}

		switch m {
		case MatchDomain:
			if p.Path != "" || p.Query != "" || p.Port != "" {
				return Key{}, invalidf("domain entry must be a host only (no path, query or port)")
			}

			return MakeKey(TypeURL, MatchDomain, p.Hostname), nil

		case MatchPrefix:
			if p.Query != "" {
				return Key{}, invalidf("prefix entry must not contain a query")
			}

			return MakeKey(TypeURL, MatchPrefix, p.Host()+p.Path), nil

		case MatchExact:
			return MakeKey(TypeURL, MatchExact, p.Full()), nil

		default:
			return Key{}, invalidf("unknown match_type %q", m)
		}

	default:
		return Key{}, invalidf("unknown type %q", t)
	}
}

// Candidates trả về giá trị đã chuẩn hóa và danh sách khóa ứng viên để tra cứu.
func Candidates(t Type, raw, region string) (string, []Key, error) {
	switch t {
	case TypePhone:
		e164, err := Phone(raw, region)
		if err != nil {
			return "", nil, err
		}

		return e164, []Key{MakeKey(TypePhone, MatchExact, e164)}, nil

	case TypeURL:
		p, err := ParseURL(raw)
		if err != nil {
			return "", nil, err
		}

		keys := []Key{MakeKey(TypeURL, MatchExact, p.Full())}

		for _, pre := range pathPrefixes(p) {
			keys = append(keys, MakeKey(TypeURL, MatchPrefix, pre))
		}

		for _, d := range domainChain(p.Hostname) {
			keys = append(keys, MakeKey(TypeURL, MatchDomain, d))
		}

		return p.Full(), keys, nil

	default:
		return "", nil, invalidf("unknown type %q", t)
	}
}

// CanonicalURLValue chuẩn hóa lại giá trị đã lưu của một entry url (chuỗi "host/path[?query]" mà NormalizeEntry tạo trước đó)
// theo luật hiện tại. Hàm dùng cho migration dữ liệu một lần sau khi đổi luật path (M9): các dòng lưu theo luật cũ có hash và chỉ mục blind
// không còn khớp với những gì Candidates tính ra. Entry domain chỉ giữ host nên được trả về không đổi.
func CanonicalURLValue(m MatchType, stored string) (string, error) {
	if m == MatchDomain {
		// Entry domain chỉ giữ host. Host có thể là IP (IPv6 cần dấu ngoặc vuông để ParseURL đọc được).
		raw := "http://" + stored
		if strings.Contains(stored, ":") {
			raw = "http://[" + stored + "]"
		}

		p, err := ParseURL(raw)
		if err != nil {
			return "", err
		}

		return p.Hostname, nil
	}

	if m != MatchPrefix && m != MatchExact {
		return stored, nil
	}

	p, err := ParseURL(stored)
	if err != nil {
		return "", err
	}

	if m == MatchPrefix {
		return p.Host() + p.Path, nil
	}

	return p.Full(), nil
}

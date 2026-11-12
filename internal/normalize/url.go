package normalize

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

type URLParts struct {
	Hostname string
	Port     string
	Path     string
	Query    string
}

// Host trả về host đã chuẩn hóa của URL.
func (p URLParts) Host() string {
	h := p.Hostname
	if strings.Contains(h, ":") {
		h = "[" + h + "]"
	}

	if p.Port != "" {
		return h + ":" + p.Port
	}

	return h
}

// Full trả về dạng đầy đủ host + path + query của URL đã chuẩn hóa.
func (p URLParts) Full() string {
	s := p.Host() + p.Path

	if p.Query != "" {
		s += "?" + p.Query
	}

	return s
}

var trackingParams = map[string]bool{
	"fbclid": true, "gclid": true, "mc_cid": true, "mc_eid": true,
	"igshid": true, "yclid": true, "msclkid": true,
}

// isTracking cho biết tham số query có phải tham số theo dõi (utm_..., fbclid, ...) hay không.
func isTracking(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "utm_") || trackingParams[name]
}

// ParseURL phân tích và chuẩn hóa một URL (scheme, host, path, query) theo luật blacklist.
func ParseURL(raw string) (URLParts, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return URLParts{}, invalidf("url is empty")
	}

	if len(s) > 2048 {
		return URLParts{}, invalidf("url is too long")
	}

	s = backslashesToSlashes(s)
	s = schemeSlashes.ReplaceAllString(s, "${1}://")

	if strings.HasPrefix(s, "//") {
		s = "http:" + s
	} else if !strings.Contains(s, "://") {
		s = "http://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return URLParts{}, invalidf("cannot parse url %q: %v", raw, err)
	}

	if sc := strings.ToLower(u.Scheme); sc != "http" && sc != "https" {
		return URLParts{}, invalidf("unsupported scheme %q", u.Scheme)
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if rest, ok := strings.CutPrefix(host, "www."); ok && strings.Contains(rest, ".") {
		host = rest
	}

	if host == "" {
		return URLParts{}, invalidf("url has no host")
	}

	if v4, ok := legacyIPv4(host); ok {
		host = v4
	}

	if ip := net.ParseIP(host); ip != nil {
		// Dạng chuẩn của IP: IPv6 viết gọn và hạ chữ thường, bỏ số 0 thừa; IPv4-mapped IPv6 (::ffff:1.2.3.4) về dạng IPv4.
		// Nhờ vậy các cách viết khác nhau của cùng một địa chỉ cho cùng một khóa tra cứu.
		host = ip.String()
	} else {
		ascii, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return URLParts{}, invalidf("invalid host %q: %v", host, err)
		}

		host = ascii
		if !strings.Contains(host, ".") {
			return URLParts{}, invalidf("host %q has no dot", host)
		}
	}

	port := u.Port()
	if port == "80" || port == "443" {
		port = ""
	}

	path := canonicalPath(u.EscapedPath())

	q := u.Query()
	for k := range q {
		if isTracking(k) {
			q.Del(k)
		}
	}

	return URLParts{Hostname: host, Port: port, Path: path, Query: q.Encode()}, nil
}

// domainChain trả về các domain cha của host (ví dụ a.b.com cho a.b.com, b.com).
func domainChain(host string) []string {
	if net.ParseIP(host) != nil {
		return []string{host}
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return []string{host}
	}

	chain := []string{host}
	cur := host
	for cur != etld1 {
		i := strings.IndexByte(cur, '.')
		if i < 0 {
			break
		}

		cur = cur[i+1:]
		chain = append(chain, cur)
	}

	return chain
}

// pathPrefixes trả về các tiền tố path của URL, dùng để khớp kiểu prefix.
func pathPrefixes(p URLParts) []string {
	cur := p.Host()
	out := []string{cur}

	if p.Path == "" {
		return out
	}

	for _, seg := range strings.Split(strings.TrimPrefix(p.Path, "/"), "/") {
		cur += "/" + seg
		out = append(out, cur)
	}

	return out
}

// canonicalPath đưa path của URL về một dạng chuẩn duy nhất, để nhiều cách viết cùng một path không thể
// lọt qua một entry khớp theo path (M9, docs/ATTACK_PUBLIC_API.md). Hàm theo RFC 3986 mục 6.2.2:
//
//  1. các escape % của ký tự không bảo lưu được giải mã (%7e -> ~, %73 -> s), các escape còn lại giữ nguyên;
//  2. dot segment được giải quyết ("/a/./b" và "/a/b/../b" -> "/a/b", không bao giờ vượt gốc), và các dấu / lặp hoặc ở cuối được gộp;
//  3. kết quả được hạ chữ thường (chỉ ASCII: mọi thứ khác đã được percent-encode).
//
// Hạ chữ thường toàn bộ path là lựa chọn có chủ ý cho blacklist: một trang chỉ khác hoa/thường so với trang bị chặn
// nhiều khả năng là cùng một trang (nhiều server và trình chuyển hướng bỏ qua hoa/thường) hơn là một trang vô hại khác,
// trong khi giữ nguyên hoa/thường sẽ cho phép một link lách entry chỉ bằng cách đổi một chữ cái. Dấu / đã escape
// (%2f) KHÔNG được giải mã, vì làm vậy sẽ đổi cấu trúc path. Query được giữ nguyên.
//
// Kết quả luôn bắt đầu bằng "/" trừ khi path rỗng, không có dấu / cuối, và canonicalPath(canonicalPath(p))
// bằng canonicalPath(p): các giá trị lưu trong database là dạng chuẩn và phải giữ như vậy khi chuẩn hóa lại.
func canonicalPath(escaped string) string {
	var b strings.Builder

	b.Grow(len(escaped))

	for i := 0; i < len(escaped); i++ {
		c := escaped[i]

		if c == '%' && i+2 < len(escaped) && isHex(escaped[i+1]) && isHex(escaped[i+2]) {
			v := unhex(escaped[i+1])<<4 | unhex(escaped[i+2])

			if isUnreserved(v) {
				b.WriteByte(v)
			} else {
				b.WriteByte('%')
				b.WriteByte("0123456789ABCDEF"[v>>4])
				b.WriteByte("0123456789ABCDEF"[v&15])
			}

			i += 2

			continue
		}

		b.WriteByte(c)
	}

	var segs []string

	for _, seg := range strings.Split(b.String(), "/") {
		// Tham số path (RFC 3986 "segment;param", ví dụ "/a;jsessionid=XYZ/b"): server bỏ qua nó khi định tuyến, nên
		// "/login;jsessionid=1" là cùng trang với "/login". Bỏ nó đi ngăn một hậu tố ngẫu nhiên làm lách entry.
		if i := strings.IndexByte(seg, ';'); i >= 0 {
			seg = seg[:i]
		}

		switch seg {
		case "", ".":
			// dấu / lặp lại, hoặc một segment không làm gì

		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}

		default:
			segs = append(segs, seg)
		}
	}

	if len(segs) == 0 {
		return ""
	}

	return strings.ToLower("/" + strings.Join(segs, "/"))
}

// isHex cho biết byte có phải chữ số hex hay không.
func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// unhex đổi một chữ số hex thành giá trị 0 đến 15.
func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}

	return c - 'A' + 10
}

// isUnreserved cho biết b có phải ký tự không bảo lưu theo RFC 3986 (ALPHA, DIGIT, "-", ".", "_", "~") hay không.
func isUnreserved(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' ||
		b == '-' || b == '.' || b == '_' || b == '~'
}

// schemeSlashes: trình duyệt chấp nhận bất kỳ số dấu / nào sau "http:" ("http:/evil.com", "http:///evil.com").
var schemeSlashes = regexp.MustCompile(`(?i)^(https?):/+`)

// backslashesToSlashes: trình duyệt coi dấu gạch ngược là dấu / trong phần authority và path của URL http(s)
// (http://evil.com\a\b mở ra evil.com/a/b), nên blacklist cũng phải làm vậy. Query và fragment được giữ nguyên.
func backslashesToSlashes(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}

	end := len(s)
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		end = i
	}

	return strings.ReplaceAll(s[:end], "\\", "/") + s[end:]
}

// legacyIPv4 đổi các cách viết IPv4 kiểu inet_aton cũ (trình duyệt vẫn chấp nhận) sang dạng thập phân có dấu chấm:
// "2130706433", "0x7f000001", "0177.0.0.1", "0x7f.1" -> "127.0.0.1". Hàm trả về false với mọi thứ không chỉ gồm
// các số như vậy (để domain bình thường không bao giờ bị động đến), hoặc khi bị tràn.
func legacyIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return "", false
	}

	nums := make([]uint64, len(parts))

	for i, p := range parts {
		n, ok := parseIPv4Part(p)
		if !ok {
			return "", false
		}

		nums[i] = n
	}

	// Mọi phần trừ phần cuối đều là một byte; phần cuối lấp đầy các byte còn lại.
	last := len(nums) - 1
	limit := uint64(1) << (8 * uint(4-last))

	var addr uint64

	for i := 0; i < last; i++ {
		if nums[i] > 255 {
			return "", false
		}

		addr |= nums[i] << (8 * uint(3-i))
	}

	if nums[last] >= limit {
		return "", false
	}

	addr |= nums[last]

	return fmt.Sprintf("%d.%d.%d.%d", addr>>24&255, addr>>16&255, addr>>8&255, addr&255), true
}

// parseIPv4Part đọc một thành phần IPv4 kiểu inet_aton (thập phân, hex hoặc bát phân).
func parseIPv4Part(p string) (uint64, bool) {
	if p == "" || len(p) > 11 {
		return 0, false
	}

	base := 10

	switch {
	case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}

	n, err := strconv.ParseUint(p, base, 64)

	return n, err == nil
}

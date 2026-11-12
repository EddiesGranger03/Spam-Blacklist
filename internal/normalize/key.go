package normalize

import (
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/cespare/xxhash/v2"
)

type Type string

const (
	TypePhone Type = "phone"
	TypeURL   Type = "url"
)

type MatchType string

const (
	MatchExact  MatchType = "exact"
	MatchDomain MatchType = "domain"
	MatchPrefix MatchType = "prefix"
)

var ErrInvalid = errors.New("invalid input")

// invalidf tạo lỗi đầu vào không hợp lệ (bọc ErrInvalid) với nội dung theo định dạng.
func invalidf(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

type Key struct {
	Type      Type
	MatchType MatchType
	Value     string
	Hash      int64
	Blind     []byte // keyed lookup index; nil when no Hasher is installed
}

// Hasher tính hash có khóa (khóa partition/Bloom) và chỉ mục blind của một giá trị. Store cài một Hasher khi bật mã hóa lưu trữ,
// nên mọi Key tạo sau đó được khớp bằng HMAC thay vì xxhash có thể dò ngược.
type Hasher func(typ, matchType, value string) (hash int64, blind []byte)

var hasher atomic.Pointer[Hasher]

// SetHasher cài hàm băm có khóa dùng cho mọi Key tạo sau đó (khi bật mã hóa lưu trữ).
func SetHasher(h Hasher) { hasher.Store(&h) }

// MakeKey tạo Key tra cứu cho loại, kiểu khớp và giá trị, kèm hash và chỉ mục blind.
func MakeKey(t Type, m MatchType, value string) Key {
	if hp := hasher.Load(); hp != nil {
		h, b := (*hp)(string(t), string(m), value)
		return Key{Type: t, MatchType: m, Value: value, Hash: h, Blind: b}
	}

	h := xxhash.Sum64String(string(t) + "|" + string(m) + "|" + value)
	return Key{Type: t, MatchType: m, Value: value, Hash: int64(h)}  // #nosec G115 -- chủ ý: hash 64 bit được lưu vào cột BIGINT, cùng bit pattern
}

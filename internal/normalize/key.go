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

// Hasher computes the keyed hash (partition/Bloom key) and the blind index of a
// value. The store installs one when encryption at rest is enabled, so every
// Key built afterwards is matched by HMAC instead of a brute-forceable xxhash.
type Hasher func(typ, matchType, value string) (hash int64, blind []byte)

var hasher atomic.Pointer[Hasher]

func SetHasher(h Hasher) { hasher.Store(&h) }

func MakeKey(t Type, m MatchType, value string) Key {
	if hp := hasher.Load(); hp != nil {
		h, b := (*hp)(string(t), string(m), value)
		return Key{Type: t, MatchType: m, Value: value, Hash: h, Blind: b}
	}

	h := xxhash.Sum64String(string(t) + "|" + string(m) + "|" + value)
	return Key{Type: t, MatchType: m, Value: value, Hash: int64(h)}
}

package normalize

import (
	"errors"
	"fmt"

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
}

func MakeKey(t Type, m MatchType, value string) Key {
	h := xxhash.Sum64String(string(t) + "|" + string(m) + "|" + value)
	return Key{Type: t, MatchType: m, Value: value, Hash: int64(h)}
}

package normalize

import (
	"strings"

	"github.com/nyaruka/phonenumbers"
)

func Phone(raw, region string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", invalidf("phone is empty")
	}

	if len(raw) > 32 {
		return "", invalidf("phone is too long")
	}

	num, err := phonenumbers.Parse(raw, region)
	if err != nil {
		return "", invalidf("cannot parse phone %q: %v", raw, err)
	}

	if !phonenumbers.IsPossibleNumber(num) {
		return "", invalidf("phone %q is not a possible number", raw)
	}

	return phonenumbers.Format(num, phonenumbers.E164), nil
}

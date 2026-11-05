package normalize

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

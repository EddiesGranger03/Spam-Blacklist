package normalize

import (
	"net"
	"net/url"
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

func isTracking(name string) bool {
	name = strings.ToLower(name)
	return strings.HasPrefix(name, "utm_") || trackingParams[name]
}

func ParseURL(raw string) (URLParts, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return URLParts{}, invalidf("url is empty")
	}

	if len(s) > 2048 {
		return URLParts{}, invalidf("url is too long")
	}

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

	if net.ParseIP(host) == nil {
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

	path := strings.TrimRight(u.EscapedPath(), "/")

	q := u.Query()
	for k := range q {
		if isTracking(k) {
			q.Del(k)
		}
	}

	return URLParts{Hostname: host, Port: port, Path: path, Query: q.Encode()}, nil
}

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

// Command risktest is the measurement helper behind docs/SCALE_TEST.md (Redis freeze, replica lag). It only talks
// HTTP (and `docker` for the Redis freeze), so it never touches the server's logic.
//
//	risktest setup  -node URL [-csv file]                         login, create an API key, optionally import a CSV; prints the key
//	risktest fresh  -writer URL -readers URL,URL -key K           write at one node, probe the others (read-after-write, F6 with a lagging replica)
//	risktest redis  -writer URL -reader URL -key K -container NAME  freeze Redis (docker pause) and measure detection / write latency / sync
//	risktest import -node URL -csv file [-metrics-token T]        time a CSV import and sample the node's /metrics while it runs
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

type node struct {
	base, csrf, token string
	c                 *http.Client
}

func newNode(base, token string) *node {
	jar, _ := cookiejar.New(nil)

	return &node{base: strings.TrimRight(base, "/"), token: token, c: &http.Client{
		Jar: jar, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (n *node) do(method, path string, body io.Reader, hdr map[string]string) (int, string, error) {
	req, err := http.NewRequest(method, n.base+path, body)
	if err != nil {
		return 0, "", err
	}

	for k, v := range hdr {
		req.Header.Set(k, v)
	}

	resp, err := n.c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	return resp.StatusCode, string(b), nil
}

func (n *node) form(method, path string, f url.Values, extra map[string]string) (int, string, error) {
	h := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	for k, v := range extra {
		h[k] = v
	}

	return n.do(method, path, strings.NewReader(f.Encode()), h)
}

var csrfRe = regexp.MustCompile(`X-CSRF-Token":"([^"]*)`)

func (n *node) login(email, pass string) error {
	code, _, err := n.form("POST", "/admin/login", url.Values{"email": {email}, "password": {pass}}, nil)
	if err != nil || code != 303 {
		return fmt.Errorf("login: code %d err %v", code, err)
	}

	_, page, err := n.do("GET", "/admin/entries", nil, nil)
	if err != nil {
		return err
	}

	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		return fmt.Errorf("no CSRF token")
	}

	n.csrf = m[1]

	return nil
}

func (n *node) write(method, path string, f url.Values) (int, string, error) {
	return n.form(method, path, f, map[string]string{"X-CSRF-Token": n.csrf, "HX-Request": "true"})
}

var keyRe = regexp.MustCompile(`vsf_[a-z0-9]{8}_[a-z0-9]{32}`)

func (n *node) newAPIKey() (string, error) {
	_, page, err := n.write("POST", "/admin/apikeys", url.Values{"name": {"risk-" + strconv.Itoa(rand.IntN(1e6))},  // #nosec G404 -- tên API key thử nghiệm, không phải giá trị bảo mật
		"rps_limit": {"1000000"}, "daily_quota": {"0"}, "expires_days": {""}})
	if err != nil {
		return "", err
	}

	if k := keyRe.FindString(page); k != "" {
		return k, nil
	}

	return "", fmt.Errorf("no API key in response")
}

func entryForm(phone, status string) url.Values {
	return url.Values{"type": {"phone"}, "match_type": {""}, "value": {phone}, "category": {"spam"}, "risk_score": {"50"},
		"status": {status}, "source": {"risktest"}, "note": {"n"}, "expires_at": {""}}
}

var editRe = regexp.MustCompile(`/admin/entries/(\d+)/edit`)

func (n *node) latestEntryID() (string, error) {
	_, page, err := n.do("GET", "/admin/entries?dir=desc", nil, nil)
	if err != nil {
		return "", err
	}

	if m := editRe.FindStringSubmatch(page); m != nil {
		return m[1], nil
	}

	return "", fmt.Errorf("no entry row")
}

func (n *node) check(key, phone string) (bool, error) {
	code, body, err := n.do("GET", "/v1/check?type=phone&value="+url.QueryEscape(phone), nil, map[string]string{"X-API-Key": key})
	if err != nil {
		return false, err
	}

	if code != 200 {
		return false, fmt.Errorf("HTTP %d", code)
	}

	var r struct {
		Blacklisted bool `json:"blacklisted"`
	}

	return r.Blacklisted, json.Unmarshal([]byte(body), &r)
}

// metric returns the value of the first sample of the named metric (0, false when absent).
func (n *node) metric(name string) (float64, bool) {
	_, body, err := n.do("GET", "/metrics", nil, map[string]string{"Authorization": "Bearer " + n.token})
	if err != nil {
		return 0, false
	}

	for _, l := range strings.Split(body, "\n") {
		if strings.HasPrefix(l, name+" ") || strings.HasPrefix(l, name+"{") {
			if f := strings.Fields(l); len(f) == 2 {
				v, e := strconv.ParseFloat(f[1], 64)

				return v, e == nil
			}
		}
	}

	return 0, false
}

func phone() string { return fmt.Sprintf("09%08d", rand.IntN(100_000_000)) }  // #nosec G404 -- số điện thoại giả để test, không phải giá trị bảo mật

func pcts(d []time.Duration) string {
	if len(d) == 0 {
		return "n=0"
	}

	s := slices.Clone(d)
	slices.Sort(s)

	at := func(p float64) time.Duration {
		return s[min(int(float64(len(s))*p), len(s)-1)].Truncate(100 * time.Microsecond)
	}

	return fmt.Sprintf("n=%d p50=%s p90=%s p99=%s max=%s", len(s), at(.5), at(.9), at(.99), s[len(s)-1].Truncate(100*time.Microsecond))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: risktest setup|fresh|redis|import [flags]")
		os.Exit(2)
	}

	switch os.Args[1] {
	case "setup":
		cmdSetup(os.Args[2:])
	case "fresh":
		cmdFresh(os.Args[2:])
	case "redis":
		cmdRedis(os.Args[2:])
	case "import":
		cmdImport(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand", os.Args[1])
		os.Exit(2)
	}
}

func adminFlags(fs *flag.FlagSet) (email, pass *string) {
	return fs.String("email", "admin@risk.test", "admin email"), fs.String("pass", "ChangeMe-12345", "admin password")
}

func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	base := fs.String("node", "http://127.0.0.1:8300", "server URL")
	csv := fs.String("csv", "", "CSV to import (optional)")
	email, pass := adminFlags(fs)
	_ = fs.Parse(args)

	n := newNode(*base, "")
	must(n.login(*email, *pass))

	k, err := n.newAPIKey()
	must(err)

	if *csv != "" {
		must(uploadCSV(n, *csv))
	}

	fmt.Println(k)
}

func uploadCSV(n *node, path string) error {
	f, err := os.Open(path)  // #nosec G304 -- đường dẫn CSV do người vận hành truyền qua flag của công cụ đo nội bộ
	if err != nil {
		return err
	}
	defer f.Close()

	var buf bytes.Buffer

	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("default_type", "phone")
	w, _ := mw.CreateFormFile("file", "import.csv")

	if _, err := io.Copy(w, f); err != nil {
		return err
	}

	_ = mw.Close()

	code, _, err := n.do("POST", "/admin/import", &buf, map[string]string{
		"Content-Type": mw.FormDataContentType(), "X-CSRF-Token": n.csrf, "HX-Request": "true"})
	if err != nil || code != 200 {
		return fmt.Errorf("import upload: code %d err %v", code, err)
	}

	return nil
}

// cmdFresh: for each round create a BLACKLIST entry at the writer and probe every reader until it reports blacklisted
// (read-after-write), counting probes that answered "safe" first; then flip it to WHITELIST and wait until readers say safe.
func cmdFresh(args []string) {
	fs := flag.NewFlagSet("fresh", flag.ExitOnError)
	w := fs.String("writer", "http://127.0.0.1:8201", "writer node")
	rs := fs.String("readers", "http://127.0.0.1:8202,http://127.0.0.1:8203", "reader nodes")
	key := fs.String("key", "", "API key")
	rounds := fs.Int("rounds", 30, "rounds")
	gap := fs.Duration("interval", 10*time.Millisecond, "probe interval")
	limit := fs.Duration("timeout", 60*time.Second, "give up after")
	email, pass := adminFlags(fs)
	_ = fs.Parse(args)

	wn := newNode(*w, "")
	must(wn.login(*email, *pass))

	var readers []*node
	for _, u := range strings.Split(*rs, ",") {
		readers = append(readers, newNode(u, ""))
	}

	var add, rem []time.Duration

	var firstProbeWrong, probes, wrongProbes, neverSeen int

	for i := 0; i < *rounds; i++ {
		p := phone()
		t0 := time.Now()

		if code, _, err := wn.write("POST", "/admin/entries", entryForm(p, "BLACKLIST")); err != nil || code != 204 {
			must(fmt.Errorf("create: %d %v", code, err))
		}

		tw := time.Since(t0)

		for _, r := range readers {
			first := true

			for time.Since(t0) < *limit {
				b, err := r.check(*key, p)
				if err == nil {
					probes++

					if b {
						break
					}

					wrongProbes++

					if first {
						firstProbeWrong++
					}

					first = false
				}

				time.Sleep(*gap)
			}

			if time.Since(t0) >= *limit {
				neverSeen++
			}

			add = append(add, time.Since(t0))
		}

		_ = tw

		id, err := wn.latestEntryID()
		must(err)

		t1 := time.Now()
		if code, _, err := wn.write("PUT", "/admin/entries/"+id, entryForm(p, "WHITELIST")); err != nil || code != 204 {
			must(fmt.Errorf("flip: %d %v", code, err))
		}

		for _, r := range readers {
			for time.Since(t1) < *limit {
				if b, err := r.check(*key, p); err == nil && !b {
					break
				}

				time.Sleep(*gap)
			}

			rem = append(rem, time.Since(t1))
		}
	}

	fmt.Printf("fresh: rounds=%d readers=%d probe-interval=%s\n", *rounds, len(readers), *gap)
	fmt.Printf("  add (BLACKLIST create -> reader says blacklisted, incl. write HTTP): %s\n", pcts(add))
	fmt.Printf("  flip (BLACKLIST->WHITELIST -> reader says safe):                    %s\n", pcts(rem))
	fmt.Printf("  FALSE NEGATIVE probes (said safe for an entry already written): first-probe-wrong=%d of %d reads, wrong-probes=%d of %d, never-converged=%d\n",
		firstProbeWrong, *rounds*len(readers), wrongProbes, probes, neverSeen)
}

func docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()  // #nosec G204 -- công cụ đo nội bộ, chỉ gọi "docker" với tham số do script/người vận hành truyền vào

	return strings.TrimSpace(string(out)), err
}

// cmdRedis freezes the Redis container (a hung peer: TCP stays open, nothing answers) and measures what the pods do.
func cmdRedis(args []string) {
	fs := flag.NewFlagSet("redis", flag.ExitOnError)
	w := fs.String("writer", "http://127.0.0.1:8201", "writer node")
	r := fs.String("reader", "http://127.0.0.1:8202", "reader node (watched via /metrics)")
	tok := fs.String("metrics-token", "multi-metrics-token-0123", "metrics token")
	key := fs.String("key", "", "API key")
	ctr := fs.String("container", "", "Redis container name")
	freeze := fs.Duration("freeze", 60*time.Second, "how long to freeze")
	email, pass := adminFlags(fs)
	_ = fs.Parse(args)

	wn, rn := newNode(*w, *tok), newNode(*r, *tok)
	must(wn.login(*email, *pass))

	probeWrite := func(label string) (time.Duration, time.Duration) {
		p := phone()
		t0 := time.Now()

		code, _, err := wn.write("POST", "/admin/entries", entryForm(p, "BLACKLIST"))
		wd := time.Since(t0)

		if err != nil || code != 204 {
			fmt.Printf("  [%s] write FAILED code=%d err=%v after %s\n", label, code, err, wd)
			return wd, -1
		}

		var seen time.Duration

		for time.Since(t0) < 90*time.Second {
			if b, err := rn.check(*key, p); err == nil && b {
				seen = time.Since(t0)
				break
			}

			time.Sleep(20 * time.Millisecond)
		}

		return wd, seen
	}

	sub := func() float64 { v, _ := rn.metric("vsf_sync_subscribed"); return v }

	fmt.Printf("before freeze: reader vsf_sync_subscribed=%v\n", sub())

	for i := 0; i < 5; i++ {
		wd, seen := probeWrite("baseline")
		fmt.Printf("  [baseline] write=%s visible-at-reader=%s\n", wd.Truncate(time.Millisecond), seen.Truncate(time.Millisecond))
	}

	fb0, _ := rn.metric("vsf_sync_fallback_total")

	t0 := time.Now()
	_, err := docker("pause", *ctr)
	must(err)
	fmt.Printf("redis FROZEN (docker pause) at t=0 (%s)\n", t0.Format("15:04:05.000"))

	var detected time.Duration

	var wroteSlow []time.Duration

	var visible []time.Duration

	var failed int

	// Drive writes every 2 s and sample subscribed every 200 ms until the freeze ends.
	var mu sync.Mutex

	done := make(chan struct{})

	go func() {
		tick := time.NewTicker(200 * time.Millisecond)
		defer tick.Stop()

		for {
			select {
			case <-done:
				return
			case <-tick.C:
				if v := sub(); v == 0 {
					mu.Lock()
					if detected == 0 {
						detected = time.Since(t0)
					}
					mu.Unlock()
				}
			}
		}
	}()

	for time.Since(t0) < *freeze {
		wd, seen := probeWrite("frozen")

		mu.Lock()
		wroteSlow = append(wroteSlow, wd)

		if seen < 0 {
			failed++
		} else {
			visible = append(visible, seen)
		}
		mu.Unlock()

		time.Sleep(2 * time.Second)
	}

	_, err = docker("unpause", *ctr)
	must(err)

	t1 := time.Now()
	fmt.Printf("redis UNPAUSED at t=%s\n", time.Since(t0).Truncate(time.Millisecond))

	var resub time.Duration

	for time.Since(t1) < 60*time.Second {
		if sub() == 1 {
			resub = time.Since(t1)
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	close(done)

	var after []time.Duration

	for i := 0; i < 10; i++ {
		_, seen := probeWrite("after")
		after = append(after, seen)
	}

	fb1, _ := rn.metric("vsf_sync_fallback_total")
	_ = visible

	fmt.Printf("reader detected loss of Pub/Sub (subscribed=0) after: %s (0 = never)\n", detected.Truncate(time.Millisecond))
	fmt.Printf("writes during freeze: write latency %s ; write failures=%d\n", pcts(wroteSlow), failed)
	fmt.Printf("visibility at reader during freeze (write->check true): %s\n", pcts(visible))
	fmt.Printf("reader re-subscribed after unpause: %s ; vsf_sync_fallback_total %v -> %v\n", resub.Truncate(time.Millisecond), fb0, fb1)
	fmt.Printf("visibility after recovery: %s\n", pcts(after))
}

// cmdImport uploads a CSV through the admin UI and samples the node's metrics every second until the job is idle.
func cmdImport(args []string) {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	base := fs.String("node", "http://127.0.0.1:8300", "server URL")
	csv := fs.String("csv", "", "CSV file")
	tok := fs.String("metrics-token", "risk-metrics-token-0123", "metrics token")
	email, pass := adminFlags(fs)
	_ = fs.Parse(args)

	n := newNode(*base, *tok)
	must(n.login(*email, *pass))

	t0 := time.Now()
	must(uploadCSV(n, *csv))
	fmt.Printf("upload accepted after %s\n", time.Since(t0).Truncate(time.Millisecond))

	for time.Since(t0) < 30*time.Minute {
		a, _ := n.metric("vsf_bloom_items")
		b, _ := n.metric("vsf_bloom_bytes")
		l, _ := n.metric("vsf_changefeed_lag_seconds")
		tl, _ := n.metric("vsf_changefeed_tail_changes")
		fmt.Printf("t=%6.1fs bloom_items=%.0f bloom_bytes=%.0f feed_lag_s=%.2f tail=%.0f\n", time.Since(t0).Seconds(), a, b, l, tl)
		time.Sleep(2 * time.Second)
	}
}

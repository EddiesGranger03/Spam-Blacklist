// Command multitest checks a multi-instance deployment over real HTTP: several server processes (containers, VMs or
// machines) sharing one Postgres (optionally with a read replica) and one Redis. Nothing here knows how the instances
// were started: they are addressed by URL, so moving to several machines only means changing -nodes.
//
//	go run ./cmd/multitest -nodes http://127.0.0.1:8201,http://127.0.0.1:8202,http://127.0.0.1:8203
//
// Scenarios (each prints PASS/FAIL lines and a measurement summary):
//
//	propagation   create / status flip / value change at node A, poll /v1/check at B and C until they agree
//	rolling       restart every node in turn while a probe loop hits the others: zero wrong answers, bounded errors
//	leader        find the snapshot leader via /metrics, kill it, expect another node to take over and a freshly started
//	              node to become ready from the existing snapshot
//
// "rolling" and "leader" need a way to restart/kill an instance. By default they use docker compose (-compose,
// -services); for other environments set -restart-cmd / -kill-cmd (templates with {name}) or run with
// -scenarios propagation only.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type node struct {
	name    string // service name used by the control commands
	base    string
	c       *http.Client
	csrf    string
	metrics string // bearer token for /metrics ("" = none)
}

var (
	pass, fail int
	results    []string
)

func ok(cond bool, format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	if cond {
		pass++
		fmt.Println("  PASS -", line)
	} else {
		fail++
		fmt.Println("  FAIL -", line)
	}
}

func note(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	results = append(results, line)
	fmt.Println("  note -", line)
}

func newNode(name, base, tok string) *node {
	jar, _ := cookiejar.New(nil)

	return &node{name: name, base: strings.TrimRight(base, "/"), metrics: tok, c: &http.Client{
		Jar: jar, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (n *node) do(method, path string, form url.Values, hdr map[string]string) (int, string, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequest(method, n.base+path, body)
	if err != nil {
		return 0, "", err
	}

	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for k, v := range hdr {
		req.Header.Set(k, v)
	}

	resp, err := n.c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	return resp.StatusCode, string(b), nil
}

func (n *node) ready() bool {
	code, _, err := n.do("GET", "/readyz", nil, nil)
	return err == nil && code == 200
}

func (n *node) waitReady(limit time.Duration) (time.Duration, bool) {
	start := time.Now()

	for time.Since(start) < limit {
		if n.ready() {
			return time.Since(start), true
		}

		time.Sleep(100 * time.Millisecond)
	}

	return time.Since(start), false
}

var csrfRe = regexp.MustCompile(`X-CSRF-Token":"([^"]*)`)

// login signs in as the bootstrap admin and fetches the CSRF token (sessions live in Postgres, so any node accepts the cookie).
func (n *node) login(email, pass string) error {
	code, _, err := n.do("POST", "/admin/login", url.Values{"email": {email}, "password": {pass}}, nil)
	if err != nil || code != 303 {
		return fmt.Errorf("login %s: code %d err %v", n.name, code, err)
	}

	_, page, err := n.do("GET", "/admin/entries", nil, nil)
	if err != nil {
		return err
	}

	m := csrfRe.FindStringSubmatch(page)
	if m == nil {
		return fmt.Errorf("no CSRF token on /admin/entries of %s", n.name)
	}

	n.csrf = m[1]

	return nil
}

func (n *node) write(method, path string, form url.Values) (int, string, error) {
	return n.do(method, path, form, map[string]string{"X-CSRF-Token": n.csrf, "HX-Request": "true"})
}

var keyRe = regexp.MustCompile(`vsf_[a-z0-9]{8}_[a-z0-9]{32}`)

func (n *node) newAPIKey(name string) (string, error) {
	_, page, err := n.write("POST", "/admin/apikeys", url.Values{"name": {name}, "rps_limit": {"100000"}, "daily_quota": {"0"}, "expires_days": {""}})
	if err != nil {
		return "", err
	}

	if k := keyRe.FindString(page); k != "" {
		return k, nil
	}

	return "", fmt.Errorf("no API key in response (%d bytes)", len(page))
}

func phoneNumber() string { return fmt.Sprintf("09%08d", rand.IntN(100_000_000)) }

func entryForm(phone, status string) url.Values {
	return url.Values{"type": {"phone"}, "match_type": {""}, "value": {phone}, "category": {"spam"}, "risk_score": {"50"},
		"status": {status}, "source": {"multitest"}, "note": {"n"}, "expires_at": {""}}
}

var editRe = regexp.MustCompile(`/admin/entries/(\d+)/edit`)

func (n *node) latestEntryID() (string, error) {
	_, page, err := n.do("GET", "/admin/entries?dir=desc", nil, nil)
	if err != nil {
		return "", err
	}

	m := editRe.FindStringSubmatch(page)
	if m == nil {
		return "", fmt.Errorf("no entry row on the list page")
	}

	return m[1], nil
}

// blacklisted asks /v1/check; err != nil means the request itself failed (node down), not "safe".
func (n *node) blacklisted(key, phone string) (bool, error) {
	code, body, err := n.do("GET", "/v1/check?type=phone&value="+url.QueryEscape(phone), nil, map[string]string{"X-API-Key": key})
	if err != nil {
		return false, err
	}

	if code != 200 {
		return false, fmt.Errorf("HTTP %d: %.100s", code, body)
	}

	var r struct {
		Blacklisted bool `json:"blacklisted"`
	}

	if err := json.Unmarshal([]byte(body), &r); err != nil {
		return false, err
	}

	return r.Blacklisted, nil
}

func waitFor(limit time.Duration, f func() bool) (time.Duration, bool) {
	start := time.Now()

	for time.Since(start) < limit {
		if f() {
			return time.Since(start), true
		}

		time.Sleep(2 * time.Millisecond)
	}

	return time.Since(start), false
}

func pcts(d []time.Duration) string {
	if len(d) == 0 {
		return "n=0"
	}

	s := slices.Clone(d)
	slices.Sort(s)

	at := func(p float64) time.Duration {
		return s[min(int(float64(len(s))*p), len(s)-1)].Truncate(100 * time.Microsecond)
	}

	return fmt.Sprintf("n=%d p50=%s p90=%s p99=%s max=%s", len(s), at(0.5), at(0.9), at(0.99), s[len(s)-1].Truncate(100*time.Microsecond))
}

// ---------- scenario 1: propagation ----------

func propagation(nodes []*node, key string, rounds int) {
	fmt.Println("== propagation: write on", nodes[0].name, "-> read on every other node (real HTTP, real Redis Pub/Sub)")

	a, others := nodes[0], nodes[1:]

	var create, flip, move []time.Duration

	allOK := true

	for range rounds {
		phone := phoneNumber()
		t0 := time.Now()

		if code, body, err := a.write("POST", "/admin/entries", entryForm(phone, "BLACKLIST")); err != nil || code != 204 {
			ok(false, "create at %s: %d %v %.80s", a.name, code, err, body)
			return
		}

		for _, o := range others {
			var lastB bool

			var lastE error

			_, hit := waitFor(5*time.Second, func() bool { lastB, lastE = o.blacklisted(key, phone); return lastE == nil && lastB })
			if !hit {
				fmt.Printf("  debug - %s never saw %s as blacklisted: last answer blacklisted=%v err=%v\n", o.name, phone, lastB, lastE)
			}

			allOK = allOK && hit

			create = append(create, time.Since(t0))
		}

		id, err := a.latestEntryID()
		if err != nil {
			ok(false, "latest entry id: %v", err)
			return
		}

		t0 = time.Now()
		if code, _, err := a.write("PUT", "/admin/entries/"+id, entryForm(phone, "WHITELIST")); err != nil || code != 204 {
			ok(false, "status flip at %s: %d %v", a.name, code, err)
			return
		}

		for _, o := range others {
			_, gone := waitFor(5*time.Second, func() bool { b, e := o.blacklisted(key, phone); return e == nil && !b })
			allOK = allOK && gone

			flip = append(flip, time.Since(t0))
		}

		np := phoneNumber()
		t0 = time.Now()
		if code, _, err := a.write("PUT", "/admin/entries/"+id, entryForm(np, "BLACKLIST")); err != nil || code != 204 {
			ok(false, "value change at %s: %d %v", a.name, code, err)
			return
		}

		for _, o := range others {
			_, moved := waitFor(5*time.Second, func() bool {
				nb, e1 := o.blacklisted(key, np)
				ob, e2 := o.blacklisted(key, phone)

				return e1 == nil && e2 == nil && nb && !ob
			})
			allOK = allOK && moved

			move = append(move, time.Since(t0))
		}
	}

	ok(allOK, "every node converged on every create / status flip / value change (%d rounds x %d nodes)", rounds, len(others))
	note("propagation (includes the write's own HTTP time): create %s", pcts(create))
	note("propagation: BLACKLIST->WHITELIST %s", pcts(flip))
	note("propagation: value change %s", pcts(move))
}

// ---------- control commands ----------

type control struct {
	restart, kill string // templates with {name}; "" = docker compose defaults below
	compose       string
}

func (c control) run(tmpl, name, def string) error {
	cmdline := tmpl
	if cmdline == "" {
		cmdline = c.compose + " " + def + " {name}"
	}

	cmdline = strings.ReplaceAll(cmdline, "{name}", name)
	out, err := exec.Command("sh", "-c", cmdline).CombinedOutput()

	if err != nil {
		return fmt.Errorf("%s: %v: %s", cmdline, err, strings.TrimSpace(string(out)))
	}

	return nil
}

// ---------- scenario 2: rolling restart ----------

func rolling(nodes []*node, key string, ctl control) {
	fmt.Println("== rolling restart: restart each node in turn; probes keep hitting the nodes that stay up")

	pre := phoneNumber()
	if code, _, err := nodes[0].write("POST", "/admin/entries", entryForm(pre, "BLACKLIST")); err != nil || code != 204 {
		ok(false, "seed entry: %d %v", code, err)
		return
	}

	for _, n := range nodes {
		waitFor(5*time.Second, func() bool { b, e := n.blacklisted(key, pre); return e == nil && b })
	}

	for i, victim := range nodes {
		var up []*node

		for j, n := range nodes {
			if j != i {
				up = append(up, n)
			}
		}

		var wrong, errs, total atomic.Int64

		stop := make(chan struct{})

		var wg sync.WaitGroup

		for _, p := range up {
			wg.Add(1)

			go func() {
				defer wg.Done()

				for {
					select {
					case <-stop:
						return
					default:
					}

					b, err := p.blacklisted(key, pre)

					total.Add(1)

					switch {
					case err != nil:
						errs.Add(1)
					case !b:
						wrong.Add(1)
					}

					time.Sleep(5 * time.Millisecond)
				}
			}()
		}

		t0 := time.Now()
		if err := ctl.run(ctl.restart, victim.name, "restart"); err != nil {
			close(stop)
			wg.Wait()
			ok(false, "restart %s: %v", victim.name, err)

			return
		}

		cmdT := time.Since(t0)
		readyT, up2 := victim.waitReady(3 * time.Minute)

		// a write made while the victim was restarting must be visible on it once it is ready
		during := phoneNumber()
		wcode, _, werr := up[0].write("POST", "/admin/entries", entryForm(during, "BLACKLIST"))

		close(stop)
		wg.Wait()

		ok(up2, "%s ready again %s after the restart command returned (command took %s)", victim.name, readyT.Truncate(time.Millisecond), cmdT.Truncate(time.Millisecond))
		ok(wrong.Load() == 0, "while %s restarted: %d probes on the other nodes, %d wrong answers, %d request errors", victim.name, total.Load(), wrong.Load(), errs.Load())

		if werr == nil && wcode == 204 {
			_, seen := waitFor(10*time.Second, func() bool { b, e := victim.blacklisted(key, during); return e == nil && b })
			ok(seen, "write made on %s just after restarting %s is visible on %s", up[0].name, victim.name, victim.name)
		}

		b, e := victim.blacklisted(key, pre)
		ok(e == nil && b, "%s still blocks the pre-existing entry after restart", victim.name)
	}
}

// ---------- scenario 3: kill the snapshot leader ----------

var leaderRe = regexp.MustCompile(`(?m)^vsf_filter_leader\s+([01])`)

func (n *node) isLeader() (bool, bool) {
	hdr := map[string]string{}
	if n.metrics != "" {
		hdr["Authorization"] = "Bearer " + n.metrics
	}

	code, body, err := n.do("GET", "/metrics", nil, hdr)
	if err != nil || code != 200 {
		return false, false
	}

	m := leaderRe.FindStringSubmatch(body)
	if m == nil {
		return false, false
	}

	return m[1] == "1", true
}

func leaderScenario(nodes []*node, key string, ctl control, snapPoll time.Duration) {
	fmt.Println("== kill the leader: another node must take over, a new node must start from the existing snapshot")

	var lead *node

	// A node takes the lock at its first maintenance tick (FILTER_SNAPSHOT_POLL), so right after a restart wait for one.
	waitFor(2*snapPoll+10*time.Second, func() bool {
		for _, n := range nodes {
			if l, okk := n.isLeader(); okk && l {
				lead = n
				return true
			}
		}

		return false
	})

	if lead == nil {
		ok(false, "no node reports vsf_filter_leader 1 (is METRICS_TOKEN set and passed with -metrics-token?)")
		return
	}

	note("current leader: %s", lead.name)

	var survivors []*node

	for _, n := range nodes {
		if n != lead {
			survivors = append(survivors, n)
		}
	}

	t0 := time.Now()
	if err := ctl.run(ctl.kill, lead.name, "kill"); err != nil {
		ok(false, "kill %s: %v", lead.name, err)
		return
	}

	// survivors keep serving and syncing without a leader
	phone := phoneNumber()
	if code, _, err := survivors[0].write("POST", "/admin/entries", entryForm(phone, "BLACKLIST")); err != nil || code != 204 {
		ok(false, "write on %s after the kill: %d %v", survivors[0].name, code, err)
		return
	}

	_, seen := waitFor(10*time.Second, func() bool { b, e := survivors[1].blacklisted(key, phone); return e == nil && b })
	ok(seen, "with the leader dead, a write on %s still reaches %s", survivors[0].name, survivors[1].name)

	d, took := waitFor(2*snapPoll+20*time.Second, func() bool {
		for _, s := range survivors {
			if l, okk := s.isLeader(); okk && l {
				return true
			}
		}

		return false
	})
	ok(took, "a surviving node took over leadership %s after the kill (FILTER_SNAPSHOT_POLL=%s)", d.Truncate(time.Millisecond), snapPoll)

	// the killed node comes back from the shared snapshot
	if err := ctl.run("", lead.name, "up -d"); err != nil {
		ok(false, "start %s: %v", lead.name, err)
		return
	}

	rt, up := lead.waitReady(3 * time.Minute)
	ok(up, "killed node %s is ready again %s after being started (total outage %s)", lead.name, rt.Truncate(time.Millisecond), time.Since(t0).Truncate(100*time.Millisecond))

	b, e := lead.blacklisted(key, phone)
	ok(e == nil && b, "%s sees the write made while it was dead (snapshot + replay)", lead.name)
}

func main() {
	nodesFlag := flag.String("nodes", os.Getenv("MULTI_NODES"), "comma separated base URLs of the instances; the first one takes the writes")
	names := flag.String("services", "server-a,server-b,server-c", "service name per node, used by the control commands")
	email := flag.String("admin-email", "admin@multi.test", "bootstrap admin e-mail")
	passw := flag.String("admin-password", "ChangeMe-12345", "bootstrap admin password (development only)")
	scen := flag.String("scenarios", "propagation,rolling,leader", "comma separated list")
	rounds := flag.Int("rounds", 100, "propagation rounds")
	compose := flag.String("compose", "docker compose -f deploy/docker-compose.multi.yml", "compose command prefix for the default restart/kill")
	restart := flag.String("restart-cmd", "", "restart command template with {name} (default: <compose> restart {name})")
	kill := flag.String("kill-cmd", "", "kill command template with {name} (default: <compose> kill {name})")
	tok := flag.String("metrics-token", os.Getenv("METRICS_TOKEN"), "bearer token for /metrics")
	poll := flag.Duration("snapshot-poll", 5*time.Second, "FILTER_SNAPSHOT_POLL the instances run with")
	flag.Parse()

	if *nodesFlag == "" {
		fmt.Fprintln(os.Stderr, "set -nodes or MULTI_NODES")
		os.Exit(2)
	}

	urls := strings.Split(*nodesFlag, ",")
	svc := strings.Split(*names, ",")

	var nodes []*node

	for i, u := range urls {
		name := fmt.Sprintf("node%d", i+1)
		if i < len(svc) {
			name = strings.TrimSpace(svc[i])
		}

		nodes = append(nodes, newNode(name, strings.TrimSpace(u), *tok))
	}

	if len(nodes) < 3 {
		fmt.Fprintln(os.Stderr, "need at least 3 nodes")
		os.Exit(2)
	}

	fmt.Println("== waiting for all nodes to be ready")

	for _, n := range nodes {
		d, up := n.waitReady(5 * time.Minute)
		ok(up, "%s (%s) ready after %s", n.name, n.base, d.Truncate(time.Millisecond))
	}

	if fail > 0 {
		os.Exit(1)
	}

	if err := nodes[0].login(*email, *passw); err != nil {
		fmt.Println("login failed:", err)
		os.Exit(1)
	}

	key, err := nodes[0].newAPIKey(fmt.Sprintf("multitest-%d", time.Now().Unix()))
	if err != nil {
		fmt.Println("API key:", err)
		os.Exit(1)
	}

	// Sessions live in Postgres but the cookie jar is per client: sign in on every node (needed to write via any of them).
	for _, n := range nodes[1:] {
		if err := n.login(*email, *passw); err != nil {
			fmt.Println("login failed:", err)
			os.Exit(1)
		}
	}

	ctl := control{restart: *restart, kill: *kill, compose: *compose}

	for _, s := range strings.Split(*scen, ",") {
		switch strings.TrimSpace(s) {
		case "propagation":
			propagation(nodes, key, *rounds)
		case "rolling":
			rolling(nodes, key, ctl)
		case "leader":
			leaderScenario(nodes, key, ctl, *poll)
		}
	}

	fmt.Printf("\n== summary: %d PASS, %d FAIL\n", pass, fail)

	for _, r := range results {
		fmt.Println("  -", r)
	}

	if fail > 0 {
		os.Exit(1)
	}
}

package changefeed

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"vsf/internal/filter"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/store"
)

// ---------- unit: thứ tự add/remove từ message (không cần DB/Redis) ----------

func hint(t *testing.T, f *Feed, seqMax int64, cs ...model.Change) {
	t.Helper()
	f.HandleMessage(string(EncodeMessage(seqMax, cs, time.Now())))
}

// (e) remove trong message không bao giờ được áp trực tiếp; chỉ catch-up theo thứ tự seq mới gỡ.
func TestMessageRemoveIsOnlyAppliedViaCatchUp(t *testing.T) {
	src := &fakeSource{all: []int64{10}}
	f, m := newFeed(t, src)

	// remove seq1 rồi add seq2 cho cùng hash; message remove đến trễ, sau khi catch-up đã áp cả hai.
	push(src, model.Change{Seq: 1, XID: "5", Hash: 10, Op: OpRemove}, model.Change{Seq: 2, XID: "6", Hash: 10, Op: OpAdd})
	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	hint(t, f, 1, model.Change{Seq: 1, Hash: 10, Op: OpRemove})

	if !m.Test(10) {
		t.Fatal("late remove message must not undo a later add (false negative)")
	}

	// Message remove cho thay đổi mới chưa catch-up: filter giữ nguyên cho tới khi SyncNow áp theo thứ tự.
	push(src, model.Change{Seq: 3, XID: "7", Hash: 10, Op: OpRemove})
	hint(t, f, 3, model.Change{Seq: 3, Hash: 10, Op: OpRemove})

	if !m.Test(10) {
		t.Fatal("remove must wait for catch-up")
	}

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if m.Test(10) {
		t.Fatal("catch-up must apply the remove")
	}
}

// (e) add trong message được áp ngay; add đã cũ (con trỏ đã vượt seq_max) bị bỏ để không thêm lại hash vừa bị gỡ.
func TestMessageAddAppliedNowAndStaleAddIgnored(t *testing.T) {
	src := &fakeSource{}
	f, m := newFeed(t, src)

	hint(t, f, 1, model.Change{Seq: 1, Hash: 77, Op: OpAdd})
	if !m.Test(77) {
		t.Fatal("add from message must be visible immediately")
	}

	push(src, model.Change{Seq: 1, XID: "5", Hash: 77, Op: OpAdd}, model.Change{Seq: 2, XID: "6", Hash: 77, Op: OpRemove})
	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if m.Test(77) {
		t.Fatal("catch-up remove must win")
	}

	hint(t, f, 1, model.Change{Seq: 1, Hash: 77, Op: OpAdd}) // message add đến trễ (duplicate)
	if m.Test(77) {
		t.Fatal("stale add (seq_max <= cursor) must be ignored")
	}
}

func TestWakeCoalesces(t *testing.T) {
	f, _ := newFeed(t, &fakeSource{})
	for range 1000 {
		f.Wake()
	}

	if n := len(f.wake); n != 1 {
		t.Fatalf("wake channel holds %d signals, want 1", n)
	}
}

func TestLargeChangeSetIsSignalOnly(t *testing.T) {
	cs := make([]model.Change, MaxHintHashes+1)
	if b := EncodeMessage(9, cs, time.Now()); len(b) > 64 {
		t.Fatalf("large message not reduced to a signal: %d bytes", len(b))
	}
}

// ---------- integration: 2 pod trên cùng Postgres + Redis ----------

type pod struct {
	feed *Feed
	m    *filter.Manager
}

func testRedisAddr(t *testing.T) string {
	t.Helper()

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR is not set; skipping Redis integration test")
	}

	return addr
}

func newRedis(t *testing.T, addr string) *redis.Client {
	t.Helper()

	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD"),
		MaxRetries: -1, DialTimeout: 500 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	return rdb
}

func channelName(t *testing.T) string { return "vsf:test:" + t.Name() + ":" + time.Now().Format("150405.000000") }

// startPod dựng một Feed trên st, chạy RunSync và (nếu rdb != nil) Subscribe.
func startPod(t *testing.T, st *store.Store, rdb *redis.Client, ch string, safety, fallback time.Duration) *pod {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m := filter.NewManager()
	f := New(st, m, quiet())

	if err := f.Init(ctx, 1000); err != nil {
		t.Fatal(err)
	}

	go f.RunSync(ctx, safety, fallback)

	if rdb != nil {
		go f.Subscribe(ctx, rdb, ch)
		waitFor(t, 5*time.Second, "subscribe", f.Live)
	}

	return &pod{feed: f, m: m}
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) time.Duration {
	t.Helper()

	start := time.Now()
	for time.Since(start) < d {
		if cond() {
			return time.Since(start)
		}

		time.Sleep(2 * time.Millisecond)
	}

	t.Fatalf("timeout after %s waiting for %s", d, what)
	return 0
}

func phoneKey(t *testing.T, phone string) normalize.Key {
	t.Helper()

	k, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, phone, "VN")
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func createEntry(t *testing.T, st *store.Store, k normalize.Key, status string) model.Entry {
	t.Helper()

	e, err := st.CreateEntry(context.Background(), k, model.EntryInput{Status: status, Category: "spam", RiskScore: 1, Note: "n"},
		model.Actor{Email: "t"})
	if err != nil {
		t.Fatal(err)
	}

	return e
}

func setStatus(t *testing.T, st *store.Store, id int64, status string) {
	t.Helper()

	if _, err := st.UpdateEntry(context.Background(), id, model.EntryInput{Status: status, Category: "spam", RiskScore: 1, Note: "n"},
		model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}
}

func has(p *pod, k normalize.Key) bool { return p.m.Test(uint64(k.Hash)) } // #nosec G115 -- test

// (a) cập nhật ở pod A, pod B thấy (filter + epoch) trong < 500ms dù safety poll rất thưa.
func TestPubSubTwoPodsPropagateUnder500ms(t *testing.T) {
	addr := testRedisAddr(t)
	env := newNetEnv(t)
	ch := channelName(t)

	rdbA, rdbB := newRedis(t, addr), newRedis(t, addr)
	env.direct.SetChangeNotifier(NewPublisher(rdbA, ch, quiet()))

	a := startPod(t, env.direct, rdbA, ch, time.Hour, time.Hour)
	b := startPod(t, env.proxied(t), rdbB, ch, time.Hour, time.Hour)

	k := phoneKey(t, "0912000001")
	epoch := b.feed.Epoch()
	e := createEntry(t, env.direct, k, model.StatusBlacklist)

	d := waitFor(t, 500*time.Millisecond, "B sees new BLACKLIST hash", func() bool { return has(b, k) })
	waitFor(t, 500*time.Millisecond, "B epoch changes after create", func() bool { return b.feed.Epoch() != epoch })
	t.Logf("create propagated to B in %s", d)

	// Đổi status sang WHITELIST ở A: B phải gỡ hash và đổi epoch (cache cũ bị vô hiệu) ngay, không chờ safety poll.
	epoch = b.feed.Epoch()
	setStatus(t, env.direct, e.ID, model.StatusWhitelist)

	d = waitFor(t, 500*time.Millisecond, "B removes hash after WHITELIST", func() bool { return !has(b, k) })
	waitFor(t, 500*time.Millisecond, "B epoch changes after status update", func() bool { return b.feed.Epoch() != epoch })
	t.Logf("status update propagated to B in %s", d)

	waitFor(t, 500*time.Millisecond, "A converges too", func() bool { return !has(a, k) && a.feed.Epoch() == b.feed.Epoch() })
}

// (e, tích hợp) chuỗi add -> remove -> add -> remove nhanh trên cùng hash: B kết thúc đúng theo thứ tự seq.
func TestPubSubRapidStatusFlipsEndInOrder(t *testing.T) {
	addr := testRedisAddr(t)
	env := newNetEnv(t)
	ch := channelName(t)

	rdbA, rdbB := newRedis(t, addr), newRedis(t, addr)
	env.direct.SetChangeNotifier(NewPublisher(rdbA, ch, quiet()))
	b := startPod(t, env.proxied(t), rdbB, ch, time.Hour, time.Hour)

	k := phoneKey(t, "0912000002")
	e := createEntry(t, env.direct, k, model.StatusBlacklist)

	for i := range 10 {
		st := model.StatusWhitelist
		if i%2 == 1 {
			st = model.StatusBlacklist
		}

		setStatus(t, env.direct, e.ID, st)
	}

	// Cuối cùng là BLACKLIST (i = 9).
	waitFor(t, time.Second, "B catches up to the last change", func() bool {
		_, seq, err := env.direct.Head(context.Background())
		return err == nil && b.feed.cursorSeq.Load() >= seq
	})

	if !has(b, k) {
		t.Fatal("final state BLACKLIST must be present on B")
	}

	setStatus(t, env.direct, e.ID, model.StatusWhitelist)
	waitFor(t, 500*time.Millisecond, "final WHITELIST removes", func() bool { return !has(b, k) })
}

// dropNotifier mô phỏng message bị mất: không publish gì.
type dropNotifier struct{}

func (dropNotifier) NotifyChanges(context.Context, int64, []model.Change) {}

// (b) message bị drop: B vẫn hội tụ nhờ safety poll.
func TestPubSubLostMessageConvergesViaSafetyPoll(t *testing.T) {
	addr := testRedisAddr(t)
	env := newNetEnv(t)
	ch := channelName(t)

	env.direct.SetChangeNotifier(dropNotifier{})
	b := startPod(t, env.proxied(t), newRedis(t, addr), ch, 300*time.Millisecond, time.Hour)

	k := phoneKey(t, "0912000003")
	createEntry(t, env.direct, k, model.StatusBlacklist)

	d := waitFor(t, 2*time.Second, "B converges via safety poll", func() bool { return has(b, k) })
	t.Logf("converged via safety poll in %s", d)
}

// (c) Redis mất rồi có lại: B về fallback trong lúc mất, và resync ngay khi subscribe lại.
func TestPubSubRedisDownThenUpResyncs(t *testing.T) {
	addr := testRedisAddr(t)
	env := newNetEnv(t)
	ch := channelName(t)

	px := startTCPProxy(t, addr)
	rdbB := newRedis(t, px.addr)
	b := startPod(t, env.proxied(t), rdbB, ch, time.Hour, time.Hour) // không có poll định kỳ nào trong thời gian test

	px.down()
	waitFor(t, 3*time.Second, "B notices redis down", func() bool { return !b.feed.Live() })
	time.Sleep(100 * time.Millisecond) // để lần SyncNow do đổi trạng thái chạy xong trước khi ghi

	k := phoneKey(t, "0912000004")
	createEntry(t, env.direct, k, model.StatusBlacklist) // không publish: writer không có notifier

	time.Sleep(300 * time.Millisecond)
	if has(b, k) {
		t.Fatal("precondition: B must not have the hash before redis comes back (fallback interval is 1h here)")
	}

	px.up(t)
	d := waitFor(t, 5*time.Second, "B resyncs after resubscribe", func() bool { return b.feed.Live() && has(b, k) })
	t.Logf("resynced %s after redis came back", d)
}

// (d) không cấu hình Redis: chạy fallback poll nhanh; Lag nhỏ.
func TestNoRedisFallsBackToFastPoll(t *testing.T) {
	env := newNetEnv(t)
	b := startPod(t, env.proxied(t), nil, "", 30*time.Second, 100*time.Millisecond)

	if b.feed.Live() {
		t.Fatal("without redis the feed must not be live")
	}

	k := phoneKey(t, "0912000005")
	createEntry(t, env.direct, k, model.StatusBlacklist)

	waitFor(t, 500*time.Millisecond, "B sees hash via fallback poll", func() bool { return has(b, k) })

	if lag := b.feed.Lag(); lag > time.Second {
		t.Fatalf("lag %s too high in fallback mode", lag)
	}
}

// ---------- TCP proxy có thể tắt/bật lại trên cùng cổng ----------

type tcpProxy struct {
	addr, target string

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
}

func startTCPProxy(t *testing.T, target string) *tcpProxy {
	t.Helper()

	p := &tcpProxy{target: target, conns: map[net.Conn]struct{}{}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	p.addr = ln.Addr().String()
	p.serve(ln)
	t.Cleanup(p.down)

	return p
}

func (p *tcpProxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			u, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}

			p.mu.Lock()
			p.conns[c], p.conns[u] = struct{}{}, struct{}{}
			p.mu.Unlock()

			go func() { _, _ = io.Copy(u, c); _ = u.Close(); _ = c.Close() }()
			go func() { _, _ = io.Copy(c, u); _ = u.Close(); _ = c.Close() }()
		}
	}()
}

// down đóng listener và mọi kết nối (giống Redis dừng hẳn).
func (p *tcpProxy) down() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}

	for c := range p.conns {
		_ = c.Close()
	}

	clear(p.conns)
}

func (p *tcpProxy) up(t *testing.T) {
	t.Helper()

	var ln net.Listener
	var err error

	for range 50 { // cổng vừa đóng có thể chưa nhả ngay
		if ln, err = net.Listen("tcp", p.addr); err == nil {
			break
		}

		time.Sleep(20 * time.Millisecond)
	}

	if err != nil {
		t.Fatal(errors.Join(errors.New("proxy up"), err))
	}

	p.serve(ln)
}

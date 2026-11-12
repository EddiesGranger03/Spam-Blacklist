package store

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
	"vsf/internal/testutil/pgfault"
)

// Mất kết nối giữa hai câu lệnh, kiểm tra TẤT ĐỊNH và ở MỌI ranh giới.
//
// Mỗi thao tác chạy qua một proxy TCP (internal/testutil/pgfault). Với n = 1, 2, 3, ... proxy làm đứt kết nối đúng ở vòng
// đi về thứ n, cho tới khi thao tác chạy xong mà không bị đứt, nên MỌI chỗ giữa hai câu lệnh của thao tác đều được thử.
// Có hai kiểu đứt:
//   - "before": đứt TRƯỚC khi vòng thứ n tới server (server hủy giao dịch đang mở);
//   - "after": server xử lý trọn vòng thứ n rồi kết nối mới đứt, client không nhận được phản hồi (nếu vòng đó là COMMIT thì
//     dữ liệu đã được lưu nhưng thao tác báo lỗi).
//
// Điều cần giữ ở mọi điểm đứt: thao tác báo LỖI (không báo thành công giả, không treo, không panic) và trạng thái là TOÀN BỘ
// hoặc KHÔNG GÌ (không entry mà Bloom filter không biết, không thao tác quản trị thiếu audit); các thao tác dài (rekey,
// xoay pepper, chuẩn hóa URL, migration) chạy lại được và hoàn tất.

const (
	faultKeyA     = "0123456789abcdef0123456789abcdef-data"
	faultKeyB     = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-data-B"
	faultPepper   = "fedcba9876543210fedcba9876543210-pepper"
	faultAudit    = "network-fault-test-secret-0123456789"
	maxRoundTrips = 60

	// Các kết nối đi qua proxy mang tên này để test chờ được tới khi server xử lý xong (kể cả vòng COMMIT đã tới server nhưng
	// client không nhận phản hồi) trước khi đọc kết quả hoặc dựng lại dữ liệu cho lần thử sau.
	faultAppName = "vsf_netfault"
)

type faultEnv struct {
	t      *testing.T
	dsn    string
	direct *Store // kết nối thẳng, dùng để dựng dữ liệu và đọc kết quả (không bị lỗi)
	proxy  *pgfault.Proxy
}

func newFaultEnv(t *testing.T) *faultEnv {
	t.Helper()

	dsn := freshDatabase(t)
	direct := freshStore(t, dsn)
	direct.SetAuditKey(AuditKeyFrom("", faultAudit))

	if err := direct.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}

	return &faultEnv{t: t, dsn: dsn, direct: direct, proxy: pgfault.Start(t, pgfault.TargetOf(t, dsn))}
}

// proxied mở một Store MỚI đi qua proxy (kết nối mới nên không dính kết nối chết của lần thử trước).
func (e *faultEnv) proxied(sl *seal.Sealer) *Store {
	e.t.Helper()

	s, err := New(context.Background(), e.proxy.DSN(e.t, e.dsn)+"&application_name="+faultAppName, "", 4)
	if err != nil {
		e.t.Fatal(err)
	}

	if sl == nil {
		sl = e.direct.sealer
	}

	s.SetSealer(sl)
	s.SetAuditKey(AuditKeyFrom("", faultAudit))
	e.t.Cleanup(s.Close)

	return s
}

type counts struct{ entries, changes, audits, admins, keys, sessions int }

func (e *faultEnv) counts() counts {
	return counts{
		entries:  countRows(e.t, e.direct, "blacklist_entries"),
		changes:  countRows(e.t, e.direct, "change_log"),
		audits:   countRows(e.t, e.direct, "audit_logs"),
		admins:   countRows(e.t, e.direct, "admins"),
		keys:     countRows(e.t, e.direct, "api_keys"),
		sessions: countRows(e.t, e.direct, "sessions"),
	}
}

func (a counts) minus(b counts) counts {
	return counts{a.entries - b.entries, a.changes - b.changes, a.audits - b.audits, a.admins - b.admins, a.keys - b.keys, a.sessions - b.sessions}
}

type faultMode struct {
	name string
	set  func(p *pgfault.Proxy, n int)
}

var faultModes = []faultMode{
	{"before", func(p *pgfault.Proxy, n int) { p.FailAtRoundTrip(n) }},
	{"after", func(p *pgfault.Proxy, n int) { p.FailAfterRoundTrip(n) }},
}

// sweep chạy op với kết nối bị đứt ở vòng 1, 2, 3, ... (cả hai kiểu) tới khi op chạy xong mà không bị đứt.
// reset đưa dữ liệu về trạng thái ban đầu trước mỗi lần thử; check kiểm tra bất biến sau mỗi lần (đã gỡ lỗi).
// Trả về số điểm đứt đã thử, để test khẳng định thao tác đủ "dài" (không bỏ sót vì quét hụt).
func (e *faultEnv) sweep(name string, sl *seal.Sealer, reset func(), op func(ctx context.Context, s *Store) error,
	check func(base counts, k int, mode string, opErr error, cut bool)) int {
	e.t.Helper()

	tried := 0

	for _, mode := range faultModes {
		completed := false

		for k := 1; k <= maxRoundTrips; k++ {
			reset()

			base := e.counts()
			s := e.proxied(sl)
			cutsBefore := e.proxy.Cuts()

			mode.set(e.proxy, k)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := op(ctx, s)
			timedOut := ctx.Err() != nil

			cancel()
			e.proxy.Heal()
			s.Close()
			e.waitProxiedGone()

			cut := e.proxy.Cuts() > cutsBefore

			if timedOut {
				e.t.Fatalf("%s [%s k=%d]: the operation hung after the connection was cut", name, mode.name, k)
			}

			if cut && err == nil {
				e.t.Errorf("%s [%s k=%d]: the connection was cut but the operation reported SUCCESS", name, mode.name, k)
			}

			if !cut && err != nil {
				e.t.Fatalf("%s [%s k=%d]: failed although nothing was cut: %v", name, mode.name, k, err)
			}

			check(base, k, mode.name, err, cut)

			if !cut {
				completed = true
				break
			}

			tried++
		}

		if !completed {
			e.t.Fatalf("%s [%s]: still being cut after %d round trips; raise maxRoundTrips", name, mode.name, maxRoundTrips)
		}
	}

	return tried
}

// waitProxiedGone chờ tới khi mọi backend của các kết nối đi qua proxy đã thoát (server đã xử lý hết những gì nó nhận được).
func (e *faultEnv) waitProxiedGone() {
	e.t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for {
		var n int
		if err := e.direct.write.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity WHERE application_name = $1`,
			faultAppName).Scan(&n); err != nil {
			e.t.Fatal(err)
		}

		if n == 0 {
			return
		}

		if time.Now().After(deadline) {
			e.t.Fatalf("%d proxied backends are still running after 10s", n)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

func (e *faultEnv) resetAll() { resetTables(e.t, e.direct) }

func (e *faultEnv) seedEntry(note string, score int) model.Entry {
	e.t.Helper()

	en, err := e.direct.CreateEntry(context.Background(), mustKey(e.t, "phone", "exact", "0905000501"),
		model.EntryInput{Category: "spam", RiskScore: score, Note: note}, actor)
	if err != nil {
		e.t.Fatal(err)
	}

	return en
}

func failIf(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()

	if cond {
		t.Errorf(format, args...)
	}
}

// ---- thao tác ghi một giao dịch: toàn bộ hoặc không gì ------------------------------------------------------------

func TestNetworkFaultCreateAndChangeEntries(t *testing.T) {
	e := newFaultEnv(t)
	in := model.EntryInput{Category: "spam", RiskScore: 10, Note: "n"}

	ackLost := 0 // lần thao tác báo lỗi dù dữ liệu đã được lưu (mất phản hồi của COMMIT)

	tried := e.sweep("CreateEntry", nil, e.resetAll,
		func(ctx context.Context, s *Store) error {
			_, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000502"), in, actor)
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			d := e.counts().minus(base)
			failIf(t, d.entries != d.changes || d.changes != d.audits || d.entries > 1,
				"CreateEntry [%s k=%d]: partial state (entries %+d, change_log %+d, audit %+d)", mode, k, d.entries, d.changes, d.audits)
			failIf(t, !cut && d.entries != 1, "CreateEntry [%s k=%d]: the uncut run must create the entry", mode, k)

			if cut && err != nil && d.entries == 1 {
				ackLost++
			}
		})

	if ackLost == 0 {
		t.Fatal("no cut point lost only the COMMIT acknowledgement: the \"after\" mode is not exercising the hardest case")
	}

	if tried < 6 {
		t.Fatalf("CreateEntry has only %d cut points; the sweep looks too short", tried)
	}

	// UpdateEntry
	var id int64

	e.sweep("UpdateEntry", nil, func() { e.resetAll(); id = e.seedEntry("before", 10).ID },
		func(ctx context.Context, s *Store) error {
			_, err := s.UpdateEntry(ctx, id, model.EntryInput{Category: "scam", RiskScore: 99, Note: "after"}, actor)
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			got, gerr := e.direct.GetEntry(context.Background(), id)
			if gerr != nil {
				t.Errorf("UpdateEntry [%s k=%d]: entry lost: %v", mode, k, gerr)
				return
			}

			applied := got.Note == "after" && got.RiskScore == 99 && got.Category == "scam"
			untouched := got.Note == "before" && got.RiskScore == 10 && got.Category == "spam"
			d := e.counts().minus(base)
			want := 0

			if applied {
				want = 1
			}

			failIf(t, applied == untouched, "UpdateEntry [%s k=%d]: half-updated entry %+v", mode, k, got)
			failIf(t, d.changes != want || d.audits != want, "UpdateEntry [%s k=%d]: applied=%v but change_log %+d, audit %+d", mode, k, applied, d.changes, d.audits)
		})

	// DeleteEntry
	e.sweep("DeleteEntry", nil, func() { e.resetAll(); id = e.seedEntry("x", 10).ID },
		func(ctx context.Context, s *Store) error { return s.DeleteEntry(ctx, id, actor) },
		func(base counts, k int, mode string, err error, cut bool) {
			d := e.counts().minus(base)
			gone := d.entries == -1
			want := 0

			if gone {
				want = 1
			}

			failIf(t, d.entries != 0 && !gone, "DeleteEntry [%s k=%d]: entries %+d", mode, k, d.entries)
			failIf(t, d.changes != want || d.audits != want, "DeleteEntry [%s k=%d]: gone=%v but change_log %+d, audit %+d", mode, k, gone, d.changes, d.audits)
		})
}

func TestNetworkFaultAdminAndAPIKeyWrites(t *testing.T) {
	e := newFaultEnv(t)
	ctx0 := context.Background()

	// CreateAdmin
	e.sweep("CreateAdmin", nil, e.resetAll,
		func(ctx context.Context, s *Store) error {
			_, err := s.CreateAdmin(ctx, "net1@example.com", "h", model.RoleViewer, actor)
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			d := e.counts().minus(base)
			failIf(t, d.admins != d.audits || d.admins > 1, "CreateAdmin [%s k=%d]: admins %+d but audit %+d", mode, k, d.admins, d.audits)
		})

	// UpdateAdmin: đổi vai trò, mất phiên và dòng audit phải cùng xảy ra hoặc cùng không
	var adminID int64

	e.sweep("UpdateAdmin", nil, func() {
		e.resetAll()

		a, err := e.direct.CreateAdmin(ctx0, "net2@example.com", "h", model.RoleEditor, actor)
		if err != nil {
			t.Fatal(err)
		}

		adminID = a.ID

		if err := e.direct.CreateSession(ctx0, []byte("net-session"), a.ID, "c", "ip", "ua", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	},
		func(ctx context.Context, s *Store) error {
			return s.UpdateAdmin(ctx, adminID, model.RoleAdmin, false, actor)
		},
		func(base counts, k int, mode string, err error, cut bool) {
			a, _ := e.direct.GetAdminByEmail(ctx0, "net2@example.com")
			changed := a.Role == model.RoleAdmin
			d := e.counts().minus(base)
			sessionEnded := d.sessions == -1

			failIf(t, changed != sessionEnded, "UpdateAdmin [%s k=%d]: role changed=%v but session ended=%v", mode, k, changed, sessionEnded)

			want := 0
			if changed {
				want = 1
			}

			failIf(t, d.audits != want, "UpdateAdmin [%s k=%d]: role changed=%v but audit %+d", mode, k, changed, d.audits)
		})

	// CreateAPIKey và RevokeAPIKey
	e.sweep("CreateAPIKey", nil, e.resetAll,
		func(ctx context.Context, s *Store) error {
			_, err := s.CreateAPIKey(ctx, NewAPIKey{Name: "n", Prefix: "netk0001", KeyHash: []byte("h"), RPSLimit: 5}, actor)
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			d := e.counts().minus(base)
			failIf(t, d.keys != d.audits || d.keys > 1, "CreateAPIKey [%s k=%d]: keys %+d but audit %+d", mode, k, d.keys, d.audits)
		})

	var keyID int64

	e.sweep("RevokeAPIKey", nil, func() {
		e.resetAll()

		k, err := e.direct.CreateAPIKey(ctx0, NewAPIKey{Name: "n", Prefix: "netk0002", KeyHash: []byte("h"), RPSLimit: 5}, actor)
		if err != nil {
			t.Fatal(err)
		}

		keyID = k.ID
	},
		func(ctx context.Context, s *Store) error { return s.RevokeAPIKey(ctx, keyID, actor) },
		func(base counts, k int, mode string, err error, cut bool) {
			key, _ := e.direct.GetAPIKey(ctx0, keyID)
			revoked := key.Status == "revoked"
			d := e.counts().minus(base)
			want := 0

			if revoked {
				want = 1
			}

			failIf(t, d.audits != want, "RevokeAPIKey [%s k=%d]: revoked=%v but audit %+d", mode, k, revoked, d.audits)
		})
}

func TestNetworkFaultImport(t *testing.T) {
	e := newFaultEnv(t)

	rows := func() []ImportRow {
		var out []ImportRow
		for _, p := range []string{"0905000601", "0905000602", "0905000603"} {
			out = append(out, ImportRow{Key: mustKey(t, "phone", "exact", p), Input: model.EntryInput{Category: "spam", RiskScore: 1}})
		}

		return out
	}

	e.sweep("Import", nil, e.resetAll,
		func(ctx context.Context, s *Store) error {
			_, err := s.Import(ctx, &sliceIter{rows: rows()}, actor)
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			d := e.counts().minus(base)
			failIf(t, (d.entries != 0 && d.entries != 3) || d.changes != d.entries,
				"Import [%s k=%d]: partial batch (entries %+d, change_log %+d)", mode, k, d.entries, d.changes)
		})
}

// ---- thao tác dài: bị đứt ở bất kỳ đâu thì chạy lại được và hoàn tất, không mất dòng nào --------------------------

func TestNetworkFaultRekeyIsResumableFromAnyCut(t *testing.T) {
	e := newFaultEnv(t)
	ctx0 := context.Background()
	oldS := e.direct.sealer
	newSealer, err := seal.New(faultKeyB, faultPepper, 2, seal.WithRetiredKeys(map[int16]string{1: faultKeyA}))
	if err != nil {
		t.Fatal(err)
	}

	const n = 6

	e.sweep("Rekey", newSealer, func() {
		e.resetAll()

		for i := 0; i < n; i++ {
			if _, err := e.direct.CreateEntry(ctx0, mustKey(t, "phone", "exact", fmt.Sprintf("090550070%d", i)),
				model.EntryInput{Category: "spam", RiskScore: 1, Note: "n", Source: "s"}, actor); err != nil {
				t.Fatal(err)
			}
		}
	},
		func(ctx context.Context, s *Store) error {
			_, err := s.Rekey(ctx, actor, RekeyOptions{Batch: 2})
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			// 1) không dòng nào mất hoặc hỏng: tất cả vẫn đọc được bằng bộ khóa mới (khóa cũ được giữ lại)
			reader := e.direct
			reader.SetSealer(newSealer)

			list, _, lerr := reader.ListEntries(ctx0, ListFilter{Limit: 100})
			reader.SetSealer(oldS)

			if lerr != nil || len(list) != n {
				t.Errorf("Rekey [%s k=%d]: rows unreadable or lost after the cut: %d rows, err=%v", mode, k, len(list), lerr)
				return
			}

			for _, en := range list {
				failIf(t, en.Note != "n" || en.Source != "s", "Rekey [%s k=%d]: row content changed: %+v", mode, k, en)
			}

			// 2) chạy lại (đã hết lỗi) thì hoàn tất: mọi dòng ở khóa hiện tại
			if cut {
				healed := e.proxied(newSealer)
				defer healed.Close() // trả kết nối để waitProxiedGone của lần thử sau không phải chờ nó

				if _, rerr := healed.Rekey(ctx0, actor, RekeyOptions{Batch: 2}); rerr != nil {
					t.Errorf("Rekey [%s k=%d]: the rerun must finish: %v", mode, k, rerr)
					return
				}

				counts, cerr := healed.KeyVersionCounts(ctx0)
				failIf(t, cerr != nil || counts[2] != n || counts[1] != 0, "Rekey [%s k=%d]: after the rerun every row must be on key 2: %v %v", mode, k, counts, cerr)
			}
		})
}

func TestNetworkFaultPepperRotationIsResumableFromAnyCut(t *testing.T) {
	e := newFaultEnv(t)
	ctx0 := context.Background()
	oldSealer := e.direct.sealer
	newSealer, err := seal.New(faultKeyA, "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn-new-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}

	const n = 6

	phones := make([]string, n)
	for i := range phones {
		phones[i] = fmt.Sprintf("090550080%d", i)
	}

	e.sweep("RotatePepper", newSealer, func() {
		e.resetAll()
		e.direct.SetSealer(oldSealer)

		for _, p := range phones {
			if _, err := e.direct.CreateEntry(ctx0, mustKey(t, "phone", "exact", p), model.EntryInput{Category: "spam", RiskScore: 1}, actor); err != nil {
				t.Fatal(err)
			}
		}
	},
		func(ctx context.Context, s *Store) error {
			_, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: oldSealer.Blind, Batch: 2})
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			defer e.direct.SetSealer(oldSealer)

			failIf(t, countRows(t, e.direct, "blacklist_entries") != n, "RotatePepper [%s k=%d]: a row was lost", mode, k)

			if !cut {
				return
			}

			healed := e.proxied(newSealer)
			defer healed.Close() // trả kết nối để waitProxiedGone của lần thử sau không phải chờ nó

			if _, rerr := healed.RotatePepper(ctx0, actor, PepperRotateOptions{OldBlind: oldSealer.Blind, Batch: 2}); rerr != nil {
				t.Errorf("RotatePepper [%s k=%d]: the rerun must finish: %v", mode, k, rerr)
				return
			}

			// sau khi chạy lại, mọi số tra cứu được bằng pepper mới
			healed.SetSealer(newSealer)

			for _, p := range phones {
				_, cands, _ := normalize.Candidates(normalize.TypePhone, p, "VN")

				if got, ferr := healed.FindMatches(ctx0, cands); ferr != nil || len(got) != 1 {
					t.Errorf("RotatePepper [%s k=%d]: %s not findable after the rerun: %v %v", mode, k, p, got, ferr)
				}
			}
		})
}

func TestNetworkFaultURLMigrationIsResumableFromAnyCut(t *testing.T) {
	e := newFaultEnv(t)
	ctx0 := context.Background()

	var legacy model.Entry

	e.sweep("canonicalizeURLPaths", nil, func() {
		e.resetAll()
		legacy = legacyEntry(t, e.direct, normalize.MatchPrefix, "evil.example/SecurePath", 90, nil)
	},
		func(ctx context.Context, s *Store) error {
			_, err := s.canonicalizeURLPaths(ctx, 10, 10)
			return err
		},
		func(base counts, k int, mode string, err error, cut bool) {
			failIf(t, countRows(t, e.direct, "blacklist_entries") != 1, "URL migration [%s k=%d]: the entry was lost or duplicated", mode, k)

			if !cut {
				return
			}

			healed := e.proxied(nil)
			defer healed.Close()
			if _, rerr := healed.canonicalizeURLPaths(ctx0, 10, 10); rerr != nil {
				t.Errorf("URL migration [%s k=%d]: the rerun must finish: %v", mode, k, rerr)
				return
			}

			found := false

			for _, m := range matchedBy(t, e.direct, "http://evil.example/securepath/x") {
				found = found || m.ID == legacy.ID
			}

			failIf(t, !found, "URL migration [%s k=%d]: after the rerun the entry must block its canonical URL", mode, k)
		})
}

// ---- Migrate và chuyển bảng cũ: mẫu các điểm đứt (mỗi lần cần một database mới nên không quét hết) ---------------

func TestNetworkFaultMigrationRecoversFromACut(t *testing.T) {
	if testing.Short() {
		t.Skip("chậm (mỗi điểm đứt cần một database mới); bỏ qua với -short")
	}

	for _, mode := range faultModes {
		for _, k := range []int{1, 4, 11} {
			dsn := freshDatabase(t)
			proxy := pgfault.Start(t, pgfault.TargetOf(t, dsn))

			broken, err := New(context.Background(), proxy.DSN(t, dsn), "", 4)
			if err != nil {
				t.Fatal(err)
			}

			broken.SetSealer(newTestSealer(t))
			mode.set(proxy, k)

			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			merr := broken.Migrate(ctx)
			timedOut := ctx.Err() != nil

			cancel()
			proxy.Heal()
			broken.Close()

			if timedOut {
				t.Fatalf("[%s k=%d] Migrate hung after the connection was cut", mode.name, k)
			}

			cut := proxy.Cuts() > 0
			if cut && merr == nil {
				t.Errorf("[%s k=%d] a cut Migrate reported success", mode.name, k)
			}

			// Chạy lại trên một kết nối khỏe: phải hoàn tất (kể cả khóa advisory của kết nối đã chết phải được nhả).
			healed := freshStore(t, dsn)

			ctx2, cancel2 := context.WithTimeout(context.Background(), 40*time.Second)
			if err := healed.Migrate(ctx2); err != nil {
				cancel2()
				t.Fatalf("[%s k=%d] Migrate after the cut must succeed: %v", mode.name, k, err)
			}

			cancel2()

			if _, err := healed.CreateEntry(context.Background(), mustKey(t, "phone", "exact", "0905000901"), model.EntryInput{Category: "spam", RiskScore: 1}, actor); err != nil {
				t.Errorf("[%s k=%d] the schema must be complete after the rerun: %v", mode.name, k, err)
			}

			if applied := appliedMigrations(t, healed); len(applied) < 4 {
				t.Errorf("[%s k=%d] migrations recorded: %v", mode.name, k, applied)
			}
		}
	}
}

func TestNetworkFaultLegacyConversionIsAllOrNothing(t *testing.T) {
	if testing.Short() {
		t.Skip("chậm (mỗi điểm đứt cần một database mới); bỏ qua với -short")
	}

	for _, mode := range faultModes {
		for _, k := range []int{3, 9, 20} {
			dsn := freshDatabase(t)
			direct := freshStore(t, dsn)
			ctx0 := context.Background()

			if err := direct.Migrate(ctx0); err != nil {
				t.Fatal(err)
			}

			seedLegacy(t, direct, 30)

			proxy := pgfault.Start(t, pgfault.TargetOf(t, dsn))

			broken, err := New(ctx0, proxy.DSN(t, dsn), "", 4)
			if err != nil {
				t.Fatal(err)
			}

			broken.SetSealer(newTestSealer(t))
			mode.set(proxy, k)

			ctx, cancel := context.WithTimeout(ctx0, 40*time.Second)
			merr := broken.Migrate(ctx)
			timedOut := ctx.Err() != nil

			cancel()
			proxy.Heal()
			broken.Close()

			if timedOut {
				t.Fatalf("[%s k=%d] conversion hung after the connection was cut", mode.name, k)
			}

			if proxy.Cuts() > 0 && merr == nil {
				t.Errorf("[%s k=%d] a cut conversion reported success", mode.name, k)
			}

			// Hoặc còn nguyên bảng cũ (đủ 30 dòng), hoặc đã chuyển xong (đủ 30 dòng); không bao giờ ở giữa.
			var legacyCol, v2 bool
			if err := direct.write.QueryRow(ctx0, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
				WHERE table_name='blacklist_entries' AND column_name='value_normalized'), to_regclass('blacklist_entries_v2') IS NOT NULL`).
				Scan(&legacyCol, &v2); err != nil {
				t.Fatal(err)
			}

			if v2 {
				t.Errorf("[%s k=%d] a half-built blacklist_entries_v2 table was left behind", mode.name, k)
			}

			if n := countRows(t, direct, "blacklist_entries"); n != 30 {
				t.Errorf("[%s k=%d] rows after the cut: %d, want 30 (legacy=%v)", mode.name, k, n, legacyCol)
			}

			// chạy lại (kết nối khỏe) thì hoàn tất
			if err := direct.Migrate(ctx0); err != nil {
				t.Fatalf("[%s k=%d] the conversion must finish on rerun: %v", mode.name, k, err)
			}

			var still bool
			if err := direct.write.QueryRow(ctx0, `SELECT EXISTS (SELECT 1 FROM information_schema.columns
				WHERE table_name='blacklist_entries' AND column_name='value_normalized')`).Scan(&still); err != nil || still {
				t.Errorf("[%s k=%d] the table must be sealed after the rerun", mode.name, k)
			}

			if n := countRows(t, direct, "blacklist_entries"); n != 30 {
				t.Errorf("[%s k=%d] rows after the rerun: %d, want 30", mode.name, k, n)
			}
		}
	}
}

// Mất kết nối GIỮA LÚC đang nhận một kết quả lớn (AllHashes, ListEntries, ExportBatch): trả lỗi, không treo, không trả
// dữ liệu cụt như thể đầy đủ.
func TestNetworkFaultCutWhileStreamingAResult(t *testing.T) {
	e := newFaultEnv(t)
	ctx0 := context.Background()

	for i := 0; i < 400; i++ {
		if _, err := e.direct.CreateEntry(ctx0, mustKey(t, "phone", "exact", fmt.Sprintf("0906%06d", i)),
			model.EntryInput{Category: "spam", RiskScore: 1, Note: strings.Repeat("n", 200)}, actor); err != nil {
			t.Fatal(err)
		}
	}

	ops := map[string]func(ctx context.Context, s *Store) error{
		"AllHashes": func(ctx context.Context, s *Store) error { return s.AllHashes(ctx, func(uint64) {}) },
		"ListEntries": func(ctx context.Context, s *Store) error {
			_, _, err := s.ListEntries(ctx, ListFilter{Limit: 200})
			return err
		},
		"ExportBatch": func(ctx context.Context, s *Store) error { _, err := s.ExportBatch(ctx, "", 0, 400); return err },
	}

	for name, op := range ops {
		// đo kích thước kết quả (không đứt), rồi đứt ở giữa
		probe := e.proxied(nil)
		e.proxy.FailAfterServerBytes(1 << 40)

		if err := op(ctx0, probe); err != nil {
			t.Fatalf("%s must work when nothing is cut: %v", name, err)
		}

		total := e.proxy.ServerBytes()

		e.proxy.Heal()
		probe.Close()
		e.waitProxiedGone()

		if total < 4000 {
			t.Fatalf("%s: the result (%d bytes) is too small to cut in the middle", name, total)
		}

		s := e.proxied(nil)
		e.proxy.FailAfterServerBytes(total / 2)

		ctx, cancel := context.WithTimeout(ctx0, 30*time.Second)
		err := op(ctx, s)
		timedOut := ctx.Err() != nil

		cancel()
		e.proxy.Heal()
		s.Close()
		e.waitProxiedGone()

		if timedOut {
			t.Fatalf("%s hung when the connection was cut while streaming", name)
		}

		if err == nil {
			t.Errorf("%s returned success although the connection was cut halfway through a %d-byte result: a partial result would look complete", name, total)
		}
	}
}

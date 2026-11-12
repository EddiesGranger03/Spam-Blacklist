package store

import (
	"context"
	"os"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

type oneRow struct {
	row  ImportRow
	done bool
}

func (o *oneRow) Next() (ImportRow, bool) {
	if o.done {
		return ImportRow{}, false
	}

	o.done = true

	return o.row, true
}

func (o *oneRow) Err() error { return nil }

// Mất kết nối database giữa chừng: mọi thao tác công khai phải trả LỖI (không panic, không treo, không báo thành công
// giả). Dùng một Store riêng đã đóng pool, nên không ảnh hưởng Store dùng chung của các test khác.
func TestEveryOperationReportsAnErrorWhenTheDatabaseIsGone(t *testing.T) {
	shared := newTestStore(t) // dựng schema và có sẵn khóa mã hóa
	ctx := context.Background()

	dead, err := New(ctx, os.Getenv("TEST_DATABASE_URL"), "", 2)
	if err != nil {
		t.Fatal(err)
	}

	dead.SetSealer(shared.sealer)
	dead.SetAuditKey(AuditKeyFrom("", "connection-loss-test-secret-0123456789"))
	dead.Close()

	key := mustKey(t, normalize.TypePhone, "", "0904000111")
	in := model.EntryInput{Category: "spam", RiskScore: 1}
	row := ImportRow{Key: key, Input: in}
	deadline, cancel := context.WithTimeout(ctx, 20*time.Second)

	defer cancel()

	ops := map[string]func() error{
		"CountAdmins":     func() error { _, e := dead.CountAdmins(deadline); return e },
		"CreateAdmin":     func() error { _, e := dead.CreateAdmin(deadline, "x@y.z", "h", model.RoleViewer, actor); return e },
		"GetAdminByEmail": func() error { _, e := dead.GetAdminByEmail(deadline, "x@y.z"); return e },
		"ListAdmins":      func() error { _, e := dead.ListAdmins(deadline); return e },
		"UpdateAdmin":     func() error { return dead.UpdateAdmin(deadline, 1, model.RoleViewer, false, actor) },
		"CreateSession": func() error {
			return dead.CreateSession(deadline, []byte("x"), 1, "c", "ip", "ua", time.Now().Add(time.Hour))
		},
		"GetSession":    func() error { _, e := dead.GetSession(deadline, []byte("x")); return e },
		"TouchSession":  func() error { return dead.TouchSession(deadline, []byte("x")) },
		"DeleteSession": func() error { return dead.DeleteSession(deadline, []byte("x")) },
		"PurgeSessions": func() error { _, e := dead.PurgeSessions(deadline, time.Minute); return e },
		"ListAudit":     func() error { _, _, e := dead.ListAudit(deadline, 0, 10); return e },
		"WriteAudit":    func() error { return dead.WriteAudit(deadline, actor, "a.b", map[string]any{}) },
		"CreateAPIKey": func() error {
			_, e := dead.CreateAPIKey(deadline, NewAPIKey{Name: "n", Prefix: "p", KeyHash: []byte("h")}, actor)
			return e
		},
		"GetAPIKeyByPrefix": func() error { _, e := dead.GetAPIKeyByPrefix(deadline, "p"); return e },
		"GetAPIKey":         func() error { _, e := dead.GetAPIKey(deadline, 1); return e },
		"ListAPIKeys":       func() error { _, e := dead.ListAPIKeys(deadline); return e },
		"RevokeAPIKey":      func() error { return dead.RevokeAPIKey(deadline, 1, actor) },
		"SetAPIKeyExpiry":   func() error { return dead.SetAPIKeyExpiry(deadline, 1, time.Now()) },
		"TouchAPIKeys":      func() error { return dead.TouchAPIKeys(deadline, []int64{1}) },
		"VerifyAuditChain":  func() error { _, e := dead.VerifyAuditChain(deadline); return e },
		"Head":              func() error { _, _, e := dead.Head(deadline); return e },
		"ChangesSince":      func() error { _, e := dead.ChangesSince(deadline, "0", 0, 10); return e },
		"PurgeChanges":      func() error { _, e := dead.PurgeChanges(deadline, time.Hour); return e },
		"CreateEntry":       func() error { _, e := dead.CreateEntry(deadline, key, in, actor); return e },
		"GetEntry":          func() error { _, e := dead.GetEntry(deadline, 1); return e },
		"UpdateEntry":       func() error { _, e := dead.UpdateEntry(deadline, 1, in, actor); return e },
		"DeleteEntry":       func() error { return dead.DeleteEntry(deadline, 1, actor) },
		"ListEntries":       func() error { _, _, e := dead.ListEntries(deadline, ListFilter{Limit: 5}); return e },
		"FindMatches":       func() error { _, e := dead.FindMatches(deadline, []normalize.Key{key}); return e },
		"AllHashes":         func() error { return dead.AllHashes(deadline, func(uint64) {}) },
		"ExportBatch":       func() error { _, e := dead.ExportBatch(deadline, "", 0, 10); return e },
		"Import":            func() error { _, e := dead.Import(deadline, &oneRow{row: row}, actor); return e },
		"VerifyKeys":        func() error { _, e := dead.VerifyKeys(deadline); return e },
		"KeyVersionCounts":  func() error { _, e := dead.KeyVersionCounts(deadline); return e },
		"Rekey":             func() error { _, e := dead.Rekey(deadline, actor, RekeyOptions{}); return e },
		"Ping":              func() error { return dead.Ping(deadline) },
		"Migrate":           func() error { return dead.Migrate(deadline) },
		"RotatePepper": func() error {
			_, e := dead.RotatePepper(deadline, actor, PepperRotateOptions{OldBlind: func(string, string, string) []byte { return nil }})
			return e
		},
	}

	for name, op := range ops {
		if err := op(); err == nil {
			t.Errorf("%s reported success on a closed database", name)
		}
	}

	// EstimatedCount trả (0, lỗi) hoặc (0, nil) tùy cách viết; điều bắt buộc là không panic và không trả số dương.
	if n, _ := dead.EstimatedCount(deadline); n != 0 {
		t.Errorf("EstimatedCount on a closed database returned %d", n)
	}
}

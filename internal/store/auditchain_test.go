package store

import (
	"bytes"
	"context"
	"testing"
	"time"

	"vsf/internal/model"
)

func TestAuditHash(t *testing.T) {
	key := AuditKeyFrom("", "session-secret")
	id := int64(7)
	base := auditFields{ID: 7, ActorID: &id, ActorEmail: "a@x.io", Action: "entry.create", Detail: `{"a": 1}`,
		IP: "127.0.0.1", CreatedAt: time.Unix(1700000000, 123456000)}

	h := auditHash(key, nil, base)
	if !bytes.Equal(h, auditHash(key, nil, base)) {
		t.Fatal("hash must be deterministic")
	}

	mutations := map[string]func(f *auditFields){
		"action": func(f *auditFields) { f.Action = "entry.delete" },
		"detail": func(f *auditFields) { f.Detail = `{"a": 2}` },
		"email":  func(f *auditFields) { f.ActorEmail = "b@x.io" },
		"ip":     func(f *auditFields) { f.IP = "10.0.0.1" },
		"time":   func(f *auditFields) { f.CreatedAt = f.CreatedAt.Add(time.Microsecond) },
		"actor":  func(f *auditFields) { f.ActorID = nil },
	}
	for name, mut := range mutations {
		f := base
		mut(&f)

		if bytes.Equal(h, auditHash(key, nil, f)) {
			t.Errorf("changing %s did not change the hash", name)
		}
	}

	if bytes.Equal(h, auditHash(key, []byte("prev"), base)) {
		t.Error("previous hash must influence the result")
	}

	if bytes.Equal(h, auditHash(AuditKeyFrom("", "other-secret"), nil, base)) {
		t.Error("different keys must give different hashes")
	}

	// Moving a byte between adjacent fields must not collide.
	a := base
	a.ActorEmail, a.Action = "ab", "c"
	b := base
	b.ActorEmail, b.Action = "a", "bc"

	if bytes.Equal(auditHash(key, nil, a), auditHash(key, nil, b)) {
		t.Error("field boundary shift produced the same hash")
	}
}

// Integration test: needs TEST_DATABASE_URL (see README); skipped otherwise.
func TestVerifyAuditChain_DetectsTampering(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	s.SetAuditKey(AuditKeyFrom("", "test-secret"))

	actor := model.Actor{Email: "admin@x.io", IP: "127.0.0.1"}

	for i := 0; i < 4; i++ {
		if err := s.WriteAudit(ctx, actor, "test.event", map[string]any{"n": i}); err != nil {
			t.Fatal(err)
		}
	}

	res, err := s.VerifyAuditChain(ctx)
	if err != nil || !res.OK || res.Checked != 4 {
		t.Fatalf("fresh chain should verify: %+v err=%v", res, err)
	}

	// 1) edit a row's content
	if _, err := s.write.Exec(ctx, `UPDATE audit_logs SET action='forged' WHERE id=(SELECT id FROM audit_logs ORDER BY id OFFSET 1 LIMIT 1)`); err != nil {
		t.Fatal(err)
	}

	if res, _ = s.VerifyAuditChain(ctx); res.OK || res.BrokenID == 0 {
		t.Fatalf("edit must be detected: %+v", res)
	}

	// 2) delete a row from the middle (also fixes the edit above by removing it)
	if _, err := s.write.Exec(ctx, `DELETE FROM audit_logs WHERE id=(SELECT id FROM audit_logs ORDER BY id OFFSET 1 LIMIT 1)`); err != nil {
		t.Fatal(err)
	}

	if res, _ = s.VerifyAuditChain(ctx); res.OK {
		t.Fatalf("deletion in the middle must be detected: %+v", res)
	}
}

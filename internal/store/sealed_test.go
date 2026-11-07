package store

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cespare/xxhash/v2"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

func newTestSealer(t *testing.T) *seal.Sealer {
	t.Helper()

	sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}

	return sl
}

func TestEntriesAreEncryptedAtRest(t *testing.T) {
	s := newTestStore(t)
	sl := s.sealer
	ctx := context.Background()

	k := mustKey(t, normalize.TypePhone, normalize.MatchExact, "0901234567")
	e, err := s.CreateEntry(ctx, k, model.EntryInput{Category: "spam", RiskScore: 50, Note: "ghi chu rieng", Source: "nguon-A"}, actor)
	if err != nil {
		t.Fatal(err)
	}

	if e.Value != k.Value || e.Note != "ghi chu rieng" || e.Source != "nguon-A" {
		t.Fatalf("returned entry must be decrypted: %+v", e)
	}

	// The plaintext columns are gone.
	var n int
	if err := s.write.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='blacklist_entries' AND column_name IN ('value_normalized','note','source')`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("plaintext columns still exist (%d): %v", n, err)
	}

	var (
		hash                     int64
		blind, valueEnc, noteEnc []byte
	)

	if err := s.write.QueryRow(ctx, `SELECT value_hash, value_blind, value_enc, note_enc FROM blacklist_entries WHERE id=$1`, e.ID).
		Scan(&hash, &blind, &valueEnc, &noteEnc); err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(valueEnc, []byte("901234567")) || bytes.Contains(noteEnc, []byte("ghi chu")) {
		t.Fatal("ciphertext contains plaintext")
	}

	if hash == int64(xxhash.Sum64String("phone|exact|"+k.Value)) {
		t.Fatal("value_hash is still the unkeyed xxhash")
	}

	if hash != seal.Hash64(sl.Blind("phone", "exact", k.Value)) || !bytes.Equal(blind, sl.Blind("phone", "exact", k.Value)) {
		t.Fatal("value_hash/value_blind are not the keyed values")
	}

	// Audit trail carries no plaintext.
	var detail string
	if err := s.write.QueryRow(ctx, `SELECT detail::text FROM audit_logs WHERE action='entry.create' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}

	for _, leak := range []string{k.Value, "ghi chu rieng", "nguon-A"} {
		if strings.Contains(detail, leak) {
			t.Errorf("audit detail leaks %q: %s", leak, detail)
		}
	}

	// Lookups work through the blind index and return decrypted data.
	_, cands, _ := normalize.Candidates(normalize.TypePhone, "0901234567", "VN")

	got, err := s.FindMatches(ctx, cands)
	if err != nil || len(got) != 1 || got[0].Value != k.Value || got[0].Note != "ghi chu rieng" {
		t.Fatalf("FindMatches = %+v, %v", got, err)
	}

	// Update re-encrypts note/source and keeps the row findable.
	up, err := s.UpdateEntry(ctx, e.ID, model.EntryInput{Category: "scam", RiskScore: 80, Note: "moi", Source: "B"}, actor)
	if err != nil || up.Note != "moi" || up.Source != "B" || up.Value != k.Value {
		t.Fatalf("update = %+v, %v", up, err)
	}
}

func TestWithoutSealerIsRefused(t *testing.T) {
	s := newTestStore(t)
	s.sealer = nil

	k := mustKey(t, normalize.TypePhone, normalize.MatchExact, "0911111111")
	if _, err := s.CreateEntry(context.Background(), k, model.EntryInput{Category: "spam", RiskScore: 5}, actor); err == nil {
		t.Fatal("writing without encryption keys must fail, not store plaintext")
	}
}

const legacySchema = `
	DROP TABLE IF EXISTS blacklist_entries CASCADE;
	DROP SEQUENCE IF EXISTS blacklist_entries_id_seq CASCADE;
	CREATE SEQUENCE blacklist_entries_id_seq;
	CREATE TABLE blacklist_entries (
		id BIGINT NOT NULL DEFAULT nextval('blacklist_entries_id_seq'),
		type TEXT NOT NULL, match_type TEXT NOT NULL,
		value_normalized TEXT NOT NULL, value_hash BIGINT NOT NULL,
		category TEXT NOT NULL DEFAULT 'spam', risk_score SMALLINT NOT NULL DEFAULT 50,
		source TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
		expires_at TIMESTAMPTZ, created_by TEXT NOT NULL DEFAULT '',
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	) PARTITION BY HASH (value_hash);
	ALTER SEQUENCE blacklist_entries_id_seq OWNED BY blacklist_entries.id;
	DO $$ BEGIN FOR i IN 0..31 LOOP
		EXECUTE format('CREATE TABLE blacklist_entries_p%s PARTITION OF blacklist_entries FOR VALUES WITH (MODULUS 32, REMAINDER %s)', i, i);
	END LOOP; END $$;
	CREATE UNIQUE INDEX blacklist_entries_uniq ON blacklist_entries (value_hash, type, match_type, value_normalized);
	CREATE INDEX blacklist_entries_id_idx ON blacklist_entries (id);`

func TestConvertLegacyTableToSealed(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if _, err := s.write.Exec(ctx, legacySchema); err != nil {
		t.Fatal(err)
	}

	// Old-style rows: unkeyed xxhash, plaintext values.
	legacy := []struct{ typ, mt, value, note string }{
		{"phone", "exact", "+84901234567", "ghi chu A"},
		{"url", "domain", "evil.example", "ghi chu B"},
		{"url", "prefix", "evil.example/login", ""},
	}

	for _, r := range legacy {
		h := int64(xxhash.Sum64String(r.typ + "|" + r.mt + "|" + r.value))
		if _, err := s.write.Exec(ctx, `INSERT INTO blacklist_entries (type, match_type, value_normalized, value_hash, note, source, created_by)
			VALUES ($1,$2,$3,$4,$5,'src','old-admin')`, r.typ, r.mt, r.value, h, r.note); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := s.write.Exec(ctx, `INSERT INTO audit_logs(actor_email, action, detail)
		VALUES ('a@x.io','entry.create','{"after":{"value":"+84901234567","note":"ghi chu A","source":"src","id":1}}')`); err != nil {
		t.Fatal(err)
	}

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("convert: %v", err)
	}

	got, _, err := s.ListEntries(ctx, ListFilter{Asc: true, Limit: 10})
	if err != nil || len(got) != 3 {
		t.Fatalf("ListEntries after convert = %d rows, %v", len(got), err)
	}

	if got[0].Value != "+84901234567" || got[0].Note != "ghi chu A" || got[0].Source != "src" || got[0].CreatedBy != "old-admin" {
		t.Fatalf("data changed by conversion: %+v", got[0])
	}

	// Lookups use the blind index, including domain/prefix candidates.
	_, cands, _ := normalize.Candidates(normalize.TypeURL, "http://www.evil.example/login/x", "VN")

	m, err := s.FindMatches(ctx, cands)
	if err != nil || len(m) != 2 {
		t.Fatalf("FindMatches after convert = %+v, %v", m, err)
	}

	var plain int
	_ = s.write.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='blacklist_entries' AND column_name='value_normalized'`).Scan(&plain)

	if plain != 0 {
		t.Fatal("plaintext column survived the conversion")
	}

	var detail string
	if err := s.write.QueryRow(ctx, `SELECT detail::text FROM audit_logs WHERE action='entry.create'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(detail, "84901234567") || strings.Contains(detail, "ghi chu A") {
		t.Errorf("old audit row still has plaintext: %s", detail)
	}

	// New rows keep working and the sequence continued from the old ids.
	k := mustKey(t, normalize.TypePhone, normalize.MatchExact, "0922222222")

	e, err := s.CreateEntry(ctx, k, model.EntryInput{Category: "spam", RiskScore: 1}, actor)
	if err != nil || e.ID <= got[2].ID {
		t.Fatalf("CreateEntry after convert: %+v, %v", e, err)
	}

	// A second Migrate is a no-op.
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestScrubAuditDetail(t *testing.T) {
	raw, changed := scrubAuditDetail(`{"before":{"value":"+84901234567","note":"n","source":"s"},"after":{"value":"+84901234567","note":"","source":"s"}}`)
	if !changed || strings.Contains(string(raw), "84901234567") || strings.Contains(string(raw), `"n"`) {
		t.Fatalf("not scrubbed: %s", raw)
	}

	if _, changed := scrubAuditDetail(`{"inserted": 5}`); changed {
		t.Error("detail without entries must be left alone")
	}

	if _, changed := scrubAuditDetail(`not json`); changed {
		t.Error("invalid json must be left alone")
	}
}

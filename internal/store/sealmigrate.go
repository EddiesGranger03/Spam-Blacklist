package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

const sealBatch = 5000

// convertToSealed moves blacklist_entries from the original plaintext layout to
// the encrypted layout, in one transaction:
//
//  1. build blacklist_entries_v2 (partitioned by the keyed value_hash),
//  2. stream every row through the Sealer into it,
//  3. verify row count and decrypt a sample against the plaintext,
//  4. swap the tables and drop the plaintext one,
//  5. scrub plaintext from old, unchained audit_logs rows.
//
// Any failure rolls everything back and leaves the plaintext table untouched.
// It is a no-op once the table is already in the new layout.
func (s *Store) convertToSealed(ctx context.Context) error {
	var legacy bool
	if err := s.write.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'blacklist_entries'
		  AND column_name = 'value_normalized')`).Scan(&legacy); err != nil {
		return err
	}

	if !legacy {
		return nil
	}

	if s.sealer == nil {
		return fmt.Errorf("%w: blacklist_entries still holds plaintext and must be converted", errNoSealer)
	}

	start := time.Now()

	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer func() { _ = tx.Rollback(ctx) }()

	// Block writers for the whole conversion.
	if _, err := tx.Exec(ctx, `LOCK TABLE blacklist_entries IN ACCESS EXCLUSIVE MODE`); err != nil {
		return err
	}

	if err := createSealedTable(ctx, tx); err != nil {
		return err
	}

	total, err := s.copySealed(ctx, tx)
	if err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		CREATE UNIQUE INDEX blacklist_entries_v2_uniq ON blacklist_entries_v2 (value_hash, type, match_type, value_blind);
		CREATE INDEX blacklist_entries_v2_id_idx ON blacklist_entries_v2 (id);`); err != nil {
		return fmt.Errorf("index sealed table: %w", err)
	}

	if err := s.verifySealed(ctx, tx, total); err != nil {
		return err
	}

	if err := swapSealedTable(ctx, tx); err != nil {
		return err
	}

	scrubbed, chained, err := s.scrubAudit(ctx, tx)
	if err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("store: sealed %d entries in %s; audit rows scrubbed=%d, hash-chained rows left untouched=%d\n",
		total, time.Since(start).Round(time.Millisecond), scrubbed, chained)

	return nil
}

func createSealedTable(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
		CREATE TABLE blacklist_entries_v2 (
			id          BIGINT      NOT NULL DEFAULT nextval('blacklist_entries_id_seq'),
			type        TEXT        NOT NULL CHECK (type IN ('phone', 'url')),
			match_type  TEXT        NOT NULL CHECK (match_type IN ('exact', 'domain', 'prefix')),
			value_hash  BIGINT      NOT NULL,
			value_blind BYTEA       NOT NULL,
			value_enc   BYTEA       NOT NULL,
			note_enc    BYTEA       NOT NULL,
			source_enc  BYTEA       NOT NULL,
			key_version SMALLINT    NOT NULL,
			category    TEXT        NOT NULL DEFAULT 'spam',
			risk_score  SMALLINT    NOT NULL DEFAULT 50 CHECK (risk_score BETWEEN 0 AND 100),
			expires_at  TIMESTAMPTZ,
			created_by  TEXT        NOT NULL DEFAULT '',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		) PARTITION BY HASH (value_hash);
		DO $$
		BEGIN
			FOR i IN 0..31 LOOP
				EXECUTE format('CREATE TABLE blacklist_entries_v2_p%s PARTITION OF blacklist_entries_v2
					FOR VALUES WITH (MODULUS 32, REMAINDER %s)', i, i);
			END LOOP;
		END $$;`)

	return err
}

var sealedColumns = []string{"id", "type", "match_type", "value_hash", "value_blind", "value_enc", "note_enc",
	"source_enc", "key_version", "category", "risk_score", "expires_at", "created_by", "created_at", "updated_at"}

// copySealed streams the plaintext table in id order, in keyset-paginated
// batches (a COPY cannot run on a connection that still has rows open).
func (s *Store) copySealed(ctx context.Context, tx pgx.Tx) (int64, error) {
	var (
		after int64
		total int64
	)

	for {
		rows, err := tx.Query(ctx, `SELECT id, type, match_type, value_normalized, category, risk_score,
			source, note, expires_at, created_by, created_at, updated_at
			FROM blacklist_entries WHERE id > $1 ORDER BY id LIMIT $2`, after, sealBatch)
		if err != nil {
			return 0, err
		}

		batch, last, err := s.sealRows(rows)
		if err != nil {
			return 0, err
		}

		if len(batch) == 0 {
			return total, nil
		}

		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"blacklist_entries_v2"}, sealedColumns, pgx.CopyFromRows(batch)); err != nil {
			return 0, fmt.Errorf("copy sealed batch: %w", err)
		}

		after = last
		total += int64(len(batch))
	}
}

func (s *Store) sealRows(rows pgx.Rows) (batch [][]any, last int64, err error) {
	defer rows.Close()

	for rows.Next() {
		var (
			id                                         int64
			typ, mt, value, category, source, note, by string
			score                                      int16
			expires, created, updated                  any
		)

		if err := rows.Scan(&id, &typ, &mt, &value, &category, &score, &source, &note, &expires, &by, &created, &updated); err != nil {
			return nil, 0, err
		}

		k := normalize.MakeKey(normalize.Type(typ), normalize.MatchType(mt), value)

		valueEnc, err := s.sealer.Seal(value, seal.AADValue)
		if err != nil {
			return nil, 0, err
		}

		noteEnc, sourceEnc, err := s.sealNoteSource(note, source)
		if err != nil {
			return nil, 0, err
		}

		batch = append(batch, []any{id, typ, mt, k.Hash, k.Blind, valueEnc, noteEnc, sourceEnc,
			s.sealer.Version(), category, score, expires, by, created, updated})
		last = id
	}

	return batch, last, rows.Err()
}

// verifySealed checks the row count and decrypts a ~1/997 sample, comparing it
// with the plaintext and recomputing its hash and blind index.
func (s *Store) verifySealed(ctx context.Context, tx pgx.Tx, want int64) error {
	var got, old int64
	if err := tx.QueryRow(ctx, `SELECT (SELECT count(*) FROM blacklist_entries_v2),
		(SELECT count(*) FROM blacklist_entries)`).Scan(&got, &old); err != nil {
		return err
	}

	if got != want || old != want {
		return fmt.Errorf("verify: row count mismatch (copied=%d sealed=%d plaintext=%d)", want, got, old)
	}

	rows, err := tx.Query(ctx, `SELECT n.id, n.type, n.match_type, n.value_normalized, n.note, n.source,
			v.value_hash, v.value_blind, v.value_enc, v.note_enc, v.source_enc
		FROM blacklist_entries n JOIN blacklist_entries_v2 v ON v.id = n.id
		WHERE n.id % 997 = 0`)
	if err != nil {
		return err
	}

	defer rows.Close()

	checked := 0

	for rows.Next() {
		var (
			id                           int64
			typ, mt, value, note, source string
			hash                         int64
			blind, valueEnc, noteEnc     []byte
			sourceEnc                    []byte
		)

		if err := rows.Scan(&id, &typ, &mt, &value, &note, &source, &hash, &blind, &valueEnc, &noteEnc, &sourceEnc); err != nil {
			return err
		}

		var e model.Entry
		if err := s.openEntry(&e, valueEnc, noteEnc, sourceEnc); err != nil {
			return fmt.Errorf("verify id %d: %w", id, err)
		}

		k := normalize.MakeKey(normalize.Type(typ), normalize.MatchType(mt), value)

		if e.Value != value || e.Note != note || e.Source != source || hash != k.Hash || string(blind) != string(k.Blind) {
			return fmt.Errorf("verify id %d: sealed copy does not match plaintext", id)
		}

		checked++
	}

	if err := rows.Err(); err != nil {
		return err
	}

	if want >= 5000 && checked == 0 {
		return fmt.Errorf("verify: sample was empty")
	}

	return nil
}

func swapSealedTable(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `
		ALTER SEQUENCE blacklist_entries_id_seq OWNED BY blacklist_entries_v2.id;
		DROP TABLE blacklist_entries;
		ALTER TABLE blacklist_entries_v2 RENAME TO blacklist_entries;
		ALTER INDEX blacklist_entries_v2_uniq RENAME TO blacklist_entries_uniq;
		ALTER INDEX blacklist_entries_v2_id_idx RENAME TO blacklist_entries_id_idx;
		DO $$
		BEGIN
			FOR i IN 0..31 LOOP
				EXECUTE format('ALTER TABLE blacklist_entries_v2_p%s RENAME TO blacklist_entries_p%s', i, i);
			END LOOP;
		END $$;
		DELETE FROM change_log;`)
	if err != nil {
		return fmt.Errorf("swap tables: %w", err)
	}

	return nil
}

// scrubAudit masks plaintext inside the detail of old entry.* audit rows.
// Rows that already carry an entry_hash are left alone (editing them would
// break the chain) and are only counted.
func (s *Store) scrubAudit(ctx context.Context, tx pgx.Tx) (scrubbed, chained int, err error) {
	type row struct {
		id     int64
		detail string
	}

	rows, err := tx.Query(ctx, `SELECT id, detail::text, entry_hash IS NOT NULL
		FROM audit_logs WHERE action LIKE 'entry.%' AND detail::text <> '{}'`)
	if err != nil {
		return 0, 0, err
	}

	var todo []row

	for rows.Next() {
		var (
			r       row
			hasHash bool
		)

		if err := rows.Scan(&r.id, &r.detail, &hasHash); err != nil {
			rows.Close()
			return 0, 0, err
		}

		if hasHash {
			chained++
			continue
		}

		todo = append(todo, r)
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	for _, r := range todo {
		raw, changed := scrubAuditDetail(r.detail)
		if !changed {
			continue
		}

		if _, err := tx.Exec(ctx, `UPDATE audit_logs SET detail=$2 WHERE id=$1`, r.id, raw); err != nil {
			return 0, 0, err
		}

		scrubbed++
	}

	return scrubbed, chained, nil
}

// scrubAuditDetail masks value/note/source in the before/after objects of an
// audit detail document. It reports whether anything changed.
func scrubAuditDetail(detail string) ([]byte, bool) {
	var doc map[string]any
	if err := json.Unmarshal([]byte(detail), &doc); err != nil {
		return nil, false
	}

	changed := false

	for _, side := range []string{"before", "after"} {
		m, ok := doc[side].(map[string]any)
		if !ok {
			continue
		}

		if v, ok := m["value"].(string); ok && !strings.Contains(v, "***") {
			m["value"], changed = seal.Mask(v), true
		}

		for _, f := range []string{"note", "source"} {
			if v, ok := m[f].(string); ok && v != "" && v != "[encrypted]" {
				m[f], changed = "[encrypted]", true
			}
		}
	}

	if !changed {
		return nil, false
	}

	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, false
	}

	return raw, true
}

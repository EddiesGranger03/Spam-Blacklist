package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

type ImportRow struct {
	Key   normalize.Key
	Input model.EntryInput
}

type RowIterator interface {
	Next() (ImportRow, bool)
	Err() error
}

type ImportResult struct {
	Inserted int64
	Updated  int64
}

type copySource struct {
	s   *Store
	it  RowIterator
	cur ImportRow
	ord int64
	err error
}

func (c *copySource) Next() bool {
	r, ok := c.it.Next()
	c.cur, c.ord = r, c.ord+1

	return ok
}

// Values encrypts each row as it streams into the staging table, so plaintext
// values and notes never reach Postgres, not even its temp files.
func (c *copySource) Values() ([]any, error) {
	r := c.cur

	valueEnc, err := c.s.sealer.Seal(r.Key.Value, seal.AADValue)
	if err != nil {
		return nil, err
	}

	noteEnc, sourceEnc, err := c.s.sealNoteSource(r.Input.Note, r.Input.Source)
	if err != nil {
		return nil, err
	}

	return []any{c.ord, string(r.Key.Type), string(r.Key.MatchType), r.Key.Hash, r.Key.Blind,
		valueEnc, noteEnc, sourceEnc, c.s.sealer.Version(),
		r.Input.Category, int16(r.Input.RiskScore), r.Input.ExpiresAt}, nil
}

func (c *copySource) Err() error { return c.it.Err() }

func (s *Store) Import(ctx context.Context, it RowIterator, actor model.Actor) (ImportResult, error) {
	var res ImportResult

	if s.sealer == nil {
		return res, errNoSealer
	}

	tx, err := s.write.Begin(ctx)
	if err != nil {
		return res, err
	}

	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE import_stage (
		ord BIGINT, type TEXT, match_type TEXT, value_hash BIGINT, value_blind BYTEA,
		value_enc BYTEA, note_enc BYTEA, source_enc BYTEA, key_version SMALLINT,
		category TEXT, risk_score SMALLINT, expires_at TIMESTAMPTZ
	) ON COMMIT DROP`); err != nil {
		return res, err
	}

	cols := []string{"ord", "type", "match_type", "value_hash", "value_blind",
		"value_enc", "note_enc", "source_enc", "key_version", "category", "risk_score", "expires_at"}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"import_stage"}, cols, &copySource{s: s, it: it}); err != nil {
		return res, err
	}

	var distinct, existing int64
	err = tx.QueryRow(ctx, `WITH d AS (
			SELECT DISTINCT value_hash, type, match_type, value_blind FROM import_stage)
		SELECT (SELECT count(*) FROM d),
		       (SELECT count(*) FROM d JOIN blacklist_entries e
		          USING (value_hash, type, match_type, value_blind))`).Scan(&distinct, &existing)
	if err != nil {
		return res, err
	}

	res.Inserted, res.Updated = distinct-existing, existing

	if _, err := tx.Exec(ctx, `INSERT INTO blacklist_entries
			(type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version,
			 category, risk_score, expires_at, created_by)
		SELECT DISTINCT ON (value_hash, type, match_type, value_blind)
			type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version,
			category, risk_score, expires_at, $1::text
		FROM import_stage
		ORDER BY value_hash, type, match_type, value_blind, ord DESC
		ON CONFLICT (value_hash, type, match_type, value_blind) DO UPDATE SET
			category = EXCLUDED.category, risk_score = EXCLUDED.risk_score, source_enc = EXCLUDED.source_enc,
			note_enc = EXCLUDED.note_enc, expires_at = EXCLUDED.expires_at, key_version = EXCLUDED.key_version,
			updated_at = now()`,
		actor.Email); err != nil {
		return res, err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO change_log(value_hash) SELECT DISTINCT value_hash FROM import_stage`); err != nil {
		return res, err
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.import", 0, map[string]any{
		"inserted": res.Inserted, "updated": res.Updated, "at": time.Now().UTC()}); err != nil {
		return res, err
	}

	return res, tx.Commit(ctx)
}

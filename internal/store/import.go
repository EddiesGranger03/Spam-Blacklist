package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"vsf/internal/model"
	"vsf/internal/normalize"
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
	it  RowIterator
	cur ImportRow
	ord int64
}

func (c *copySource) Next() bool {
	r, ok := c.it.Next()
	c.cur, c.ord = r, c.ord+1
	return ok
}

func (c *copySource) Values() ([]any, error) {
	r := c.cur
	return []any{c.ord, string(r.Key.Type), string(r.Key.MatchType), r.Key.Value, r.Key.Hash,
		r.Input.Category, int16(r.Input.RiskScore), r.Input.Source, r.Input.Note, r.Input.ExpiresAt}, nil
}

func (c *copySource) Err() error { return c.it.Err() }

func (s *Store) Import(ctx context.Context, it RowIterator, actor model.Actor) (ImportResult, error) {
	var res ImportResult
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return res, err
	}

	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE import_stage (
		ord BIGINT, type TEXT, match_type TEXT, value_normalized TEXT, value_hash BIGINT,
		category TEXT, risk_score SMALLINT, source TEXT, note TEXT, expires_at TIMESTAMPTZ
	) ON COMMIT DROP`); err != nil {
		return res, err
	}

	cols := []string{"ord", "type", "match_type", "value_normalized", "value_hash",
		"category", "risk_score", "source", "note", "expires_at"}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"import_stage"}, cols, &copySource{it: it}); err != nil {
		return res, err
	}

	var distinct, existing int64
	err = tx.QueryRow(ctx, `WITH d AS (
			SELECT DISTINCT value_hash, type, match_type, value_normalized FROM import_stage)
		SELECT (SELECT count(*) FROM d),
		       (SELECT count(*) FROM d JOIN blacklist_entries e
		          USING (value_hash, type, match_type, value_normalized))`).Scan(&distinct, &existing)
	if err != nil {
		return res, err
	}

	res.Inserted, res.Updated = distinct-existing, existing

	if _, err := tx.Exec(ctx, `INSERT INTO blacklist_entries
			(type, match_type, value_normalized, value_hash, category, risk_score, source, note, expires_at, created_by)
		SELECT DISTINCT ON (value_hash, type, match_type, value_normalized)
			type, match_type, value_normalized, value_hash, category, risk_score, source, note, expires_at, $1::text
		FROM import_stage
		ORDER BY value_hash, type, match_type, value_normalized, ord DESC
		ON CONFLICT (value_hash, type, match_type, value_normalized) DO UPDATE SET
			category = EXCLUDED.category, risk_score = EXCLUDED.risk_score, source = EXCLUDED.source,
			note = EXCLUDED.note, expires_at = EXCLUDED.expires_at, updated_at = now()`,
		actor.Email); err != nil {
		return res, err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO change_log(value_hash) SELECT DISTINCT value_hash FROM import_stage`); err != nil {
		return res, err
	}

	if err := writeAudit(ctx, tx, actor, "entry.import", 0, map[string]any{
		"inserted": res.Inserted, "updated": res.Updated, "at": time.Now().UTC()}); err != nil {
		return res, err
	}

	return res, tx.Commit(ctx)
}

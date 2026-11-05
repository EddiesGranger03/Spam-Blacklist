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
)

const entryCols = `id, type, match_type, value_normalized, category, risk_score, source, note,
	expires_at, created_by, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

func scanEntry(row rowScanner) (model.Entry, error) {
	var e model.Entry
	var score int16
	err := row.Scan(&e.ID, &e.Type, &e.MatchType, &e.Value, &e.Category, &score, &e.Source, &e.Note,
		&e.ExpiresAt, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt)

	e.RiskScore = int(score)
	return e, err
}

func scanEntryHash(row rowScanner) (model.Entry, int64, error) {
	var e model.Entry
	var score int16
	var hash int64
	err := row.Scan(&e.ID, &e.Type, &e.MatchType, &e.Value, &e.Category, &score, &e.Source, &e.Note,
		&e.ExpiresAt, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt, &hash)

	e.RiskScore = int(score)
	return e, hash, err
}

func logChange(ctx context.Context, tx pgx.Tx, hashes ...int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO change_log(value_hash) SELECT unnest($1::bigint[])`, hashes)
	return err
}

func writeAudit(ctx context.Context, tx pgx.Tx, a model.Actor, action string, entryID int64, detail any) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}

	var eid, aid any

	if entryID != 0 {
		eid = entryID
	}

	if a.ID != 0 {
		aid = a.ID
	}

	_, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor_id, actor_email, action, entry_id, detail, ip)
		VALUES ($1,$2,$3,$4,$5,$6)`, aid, a.Email, action, eid, raw, a.IP)
	return err
}

func (s *Store) CreateEntry(ctx context.Context, key normalize.Key, in model.EntryInput, actor model.Actor) (model.Entry, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Entry{}, err
	}

	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `INSERT INTO blacklist_entries
		(type, match_type, value_normalized, value_hash, category, risk_score, source, note, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+entryCols,
		string(key.Type), string(key.MatchType), key.Value, key.Hash,
		in.Category, int16(in.RiskScore), in.Source, in.Note, in.ExpiresAt, actor.Email)
	e, err := scanEntry(row)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Entry{}, ErrDuplicate
		}

		return model.Entry{}, err
	}

	if err := logChange(ctx, tx, key.Hash); err != nil {
		return model.Entry{}, err
	}

	if err := writeAudit(ctx, tx, actor, "entry.create", e.ID, map[string]any{"after": e}); err != nil {
		return model.Entry{}, err
	}

	return e, tx.Commit(ctx)
}

func (s *Store) GetEntry(ctx context.Context, id int64) (model.Entry, error) {
	e, err := scanEntry(s.write.QueryRow(ctx, `SELECT `+entryCols+` FROM blacklist_entries WHERE id=$1`, id))
	return e, mapNotFound(err)
}

func (s *Store) UpdateEntry(ctx context.Context, id int64, in model.EntryInput, actor model.Actor) (model.Entry, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Entry{}, err
	}

	defer tx.Rollback(ctx)

	before, hash, err := scanEntryHash(tx.QueryRow(ctx,
		`SELECT `+entryCols+`, value_hash FROM blacklist_entries WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return model.Entry{}, mapNotFound(err)
	}

	after, err := scanEntry(tx.QueryRow(ctx, `UPDATE blacklist_entries
		SET category=$3, risk_score=$4, source=$5, note=$6, expires_at=$7, updated_at=now()
		WHERE value_hash=$2 AND id=$1 RETURNING `+entryCols,
		id, hash, in.Category, int16(in.RiskScore), in.Source, in.Note, in.ExpiresAt))
	if err != nil {
		return model.Entry{}, mapNotFound(err)
	}

	if err := logChange(ctx, tx, hash); err != nil {
		return model.Entry{}, err
	}

	if err := writeAudit(ctx, tx, actor, "entry.update", id, map[string]any{"before": before, "after": after}); err != nil {
		return model.Entry{}, err
	}

	return after, tx.Commit(ctx)
}

func (s *Store) DeleteEntry(ctx context.Context, id int64, actor model.Actor) error {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	e, hash, err := scanEntryHash(tx.QueryRow(ctx,
		`DELETE FROM blacklist_entries WHERE id=$1 RETURNING `+entryCols+`, value_hash`, id))
	if err != nil {
		return mapNotFound(err)
	}

	if err := logChange(ctx, tx, hash); err != nil {
		return err
	}

	if err := writeAudit(ctx, tx, actor, "entry.delete", id, map[string]any{"before": e}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

type ListFilter struct {
	Type     string
	Category string
	Cursor   int64
	Limit    int
	Search   []normalize.Key
	Asc      bool
}

func (s *Store) ListEntries(ctx context.Context, f ListFilter) (entries []model.Entry, nextCursor int64, err error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}

	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}

	if f.Type != "" {
		add("type = $%d", f.Type)
	}

	if f.Category != "" {
		add("category = $%d", f.Category)
	}

	op, dir := "<", "DESC"

	if f.Asc {
		op, dir = ">", "ASC"
	}

	if f.Cursor > 0 {
		add("id"+op+"$%d", f.Cursor)
	}

	if f.Search != nil {
		hashes := make([]int64, len(f.Search))
		values := make([]string, len(f.Search))

		for i, k := range f.Search {
			hashes[i], values[i] = k.Hash, k.Value
		}

		add("value_hash = ANY($%d)", hashes)
		add("value_normalized = ANY($%d)", values)
	}

	q := `SELECT ` + entryCols + ` FROM blacklist_entries`

	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}

	args = append(args, f.Limit+1)

	q += fmt.Sprintf(" ORDER BY id %s LIMIT $%d", dir, len(args))

	rows, err := s.write.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}

	defer rows.Close()
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, 0, err
		}

		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	if len(entries) > f.Limit {
		entries = entries[:f.Limit]
		nextCursor = entries[len(entries)-1].ID
	}

	return entries, nextCursor, nil
}

func (s *Store) FindMatches(ctx context.Context, keys []normalize.Key) ([]model.Entry, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	hashes := make([]int64, len(keys))
	types := make([]string, len(keys))
	mts := make([]string, len(keys))
	vals := make([]string, len(keys))

	for i, k := range keys {
		hashes[i], types[i], mts[i], vals[i] = k.Hash, string(k.Type), string(k.MatchType), k.Value
	}

	rows, err := s.read.Query(ctx, `SELECT `+entryCols+`
		FROM blacklist_entries e
		JOIN unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) AS c(h, t, mt, v)
		  ON e.value_hash = c.h AND e.type = c.t AND e.match_type = c.mt AND e.value_normalized = c.v
		WHERE e.expires_at IS NULL OR e.expires_at > now()`, hashes, types, mts, vals)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Entry

	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, e)
	}

	return out, rows.Err()
}

func (s *Store) AllHashes(ctx context.Context, emit func(uint64)) error {
	rows, err := s.read.Query(ctx, `SELECT value_hash FROM blacklist_entries`)
	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var h int64
		if err := rows.Scan(&h); err != nil {
			return err
		}

		emit(uint64(h))
	}

	return rows.Err()
}

func (s *Store) EstimatedCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.read.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(reltuples,0)),0)::bigint
		FROM pg_class WHERE relname LIKE 'blacklist_entries_p%' AND relkind='r'`).Scan(&n)
	return n, err
}

func (s *Store) ExportBatch(ctx context.Context, typ string, afterID int64, limit int) ([]model.Entry, error) {
	rows, err := s.write.Query(ctx, `SELECT `+entryCols+` FROM blacklist_entries
		WHERE id > $1 AND ($2 = '' OR type = $2) ORDER BY id LIMIT $3`, afterID, typ, limit)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Entry

	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, e)
	}

	return out, rows.Err()
}

func ParseExpiry(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}

	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, nil
		}
	}

	return nil, fmt.Errorf("%w: invalid expires_at %q (use YYYY-MM-DD or RFC3339)", normalize.ErrInvalid, s)
}

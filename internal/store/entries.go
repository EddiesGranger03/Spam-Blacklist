package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

const entryCols = `id, type, match_type, value_enc, category, risk_score, source_enc, note_enc,
	expires_at, created_by, created_at, updated_at`

type rowScanner interface{ Scan(dest ...any) error }

// scanEntry reads one row selected with entryCols (plus any extra columns,
// scanned into extra) and decrypts the sealed fields.
func (s *Store) scanEntry(row rowScanner, extra ...any) (model.Entry, error) {
	var (
		e                         model.Entry
		score                     int16
		valueEnc, srcEnc, noteEnc []byte
	)

	dest := append([]any{&e.ID, &e.Type, &e.MatchType, &valueEnc, &e.Category, &score, &srcEnc, &noteEnc,
		&e.ExpiresAt, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt}, extra...)
	if err := row.Scan(dest...); err != nil {
		return model.Entry{}, err
	}

	e.RiskScore = int(score)

	if err := s.openEntry(&e, valueEnc, noteEnc, srcEnc); err != nil {
		return model.Entry{}, fmt.Errorf("entry %d: %w", e.ID, err)
	}

	return e, nil
}

func (s *Store) scanEntryHash(row rowScanner) (model.Entry, int64, error) {
	var hash int64
	e, err := s.scanEntry(row, &hash)

	return e, hash, err
}

func logChange(ctx context.Context, tx pgx.Tx, hashes ...int64) error {
	_, err := tx.Exec(ctx, `INSERT INTO change_log(value_hash) SELECT unnest($1::bigint[])`, hashes)
	return err
}

func (s *Store) CreateEntry(ctx context.Context, key normalize.Key, in model.EntryInput, actor model.Actor) (model.Entry, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Entry{}, err
	}

	defer tx.Rollback(ctx)

	if s.sealer == nil {
		return model.Entry{}, errNoSealer
	}

	valueEnc, err := s.sealer.Seal(key.Value, seal.AADValue)
	if err != nil {
		return model.Entry{}, err
	}

	noteEnc, sourceEnc, err := s.sealNoteSource(in.Note, in.Source)
	if err != nil {
		return model.Entry{}, err
	}

	row := tx.QueryRow(ctx, `INSERT INTO blacklist_entries
		(type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version,
		 category, risk_score, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+entryCols,
		string(key.Type), string(key.MatchType), key.Hash, key.Blind, valueEnc, noteEnc, sourceEnc,
		s.sealer.Version(), in.Category, int16(in.RiskScore), in.ExpiresAt, actor.Email)
	e, err := s.scanEntry(row)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Entry{}, ErrDuplicate
		}

		return model.Entry{}, err
	}

	if err := logChange(ctx, tx, key.Hash); err != nil {
		return model.Entry{}, err
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.create", e.ID, map[string]any{"after": s.auditView(e)}); err != nil {
		return model.Entry{}, err
	}

	return e, tx.Commit(ctx)
}

func (s *Store) GetEntry(ctx context.Context, id int64) (model.Entry, error) {
	e, err := s.scanEntry(s.write.QueryRow(ctx, `SELECT `+entryCols+` FROM blacklist_entries WHERE id=$1`, id))
	return e, mapNotFound(err)
}

func (s *Store) UpdateEntry(ctx context.Context, id int64, in model.EntryInput, actor model.Actor) (model.Entry, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Entry{}, err
	}

	defer tx.Rollback(ctx)

	before, hash, err := s.scanEntryHash(tx.QueryRow(ctx,
		`SELECT `+entryCols+`, value_hash FROM blacklist_entries WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return model.Entry{}, mapNotFound(err)
	}

	noteEnc, sourceEnc, err := s.sealNoteSource(in.Note, in.Source)
	if err != nil {
		return model.Entry{}, err
	}

	after, err := s.scanEntry(tx.QueryRow(ctx, `UPDATE blacklist_entries
		SET category=$3, risk_score=$4, source_enc=$5, note_enc=$6, expires_at=$7, key_version=$8, updated_at=now()
		WHERE value_hash=$2 AND id=$1 RETURNING `+entryCols,
		id, hash, in.Category, int16(in.RiskScore), sourceEnc, noteEnc, in.ExpiresAt, s.sealer.Version()))
	if err != nil {
		return model.Entry{}, mapNotFound(err)
	}

	if err := logChange(ctx, tx, hash); err != nil {
		return model.Entry{}, err
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.update", id, map[string]any{"before": s.auditView(before), "after": s.auditView(after)}); err != nil {
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

	e, hash, err := s.scanEntryHash(tx.QueryRow(ctx,
		`DELETE FROM blacklist_entries WHERE id=$1 RETURNING `+entryCols+`, value_hash`, id))
	if err != nil {
		return mapNotFound(err)
	}

	if err := logChange(ctx, tx, hash); err != nil {
		return err
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.delete", id, map[string]any{"before": s.auditView(e)}); err != nil {
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
		blinds := make([][]byte, len(f.Search))

		for i, k := range f.Search {
			hashes[i], blinds[i] = k.Hash, k.Blind
		}

		add("value_hash = ANY($%d)", hashes)
		add("value_blind = ANY($%d)", blinds)
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
		e, err := s.scanEntry(rows)
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
	blinds := make([][]byte, len(keys))

	for i, k := range keys {
		hashes[i], types[i], mts[i], blinds[i] = k.Hash, string(k.Type), string(k.MatchType), k.Blind
	}

	rows, err := s.read.Query(ctx, `SELECT `+entryCols+`
		FROM blacklist_entries e
		JOIN unnest($1::bigint[], $2::text[], $3::text[], $4::bytea[]) AS c(h, t, mt, b)
		  ON e.value_hash = c.h AND e.type = c.t AND e.match_type = c.mt AND e.value_blind = c.b
		WHERE e.expires_at IS NULL OR e.expires_at > now()`, hashes, types, mts, blinds)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Entry

	for rows.Next() {
		e, err := s.scanEntry(rows)
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
		e, err := s.scanEntry(rows)
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

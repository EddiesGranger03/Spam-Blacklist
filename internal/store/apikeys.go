package store

import (
	"context"
	"time"

	"vsf/internal/model"
)

const apiKeyCols = `id, name, prefix, key_hash, status, rps_limit, daily_quota, expires_at, rotated_from,
	created_by, created_at, last_used_at, revoked_at`

func scanAPIKey(row rowScanner) (model.APIKey, error) {
	var k model.APIKey
	err := row.Scan(&k.ID, &k.Name, &k.Prefix, &k.KeyHash, &k.Status, &k.RPSLimit, &k.DailyQuota,
		&k.ExpiresAt, &k.RotatedFrom, &k.CreatedBy, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	return k, err
}

type NewAPIKey struct {
	Name        string
	Prefix      string
	KeyHash     []byte
	RPSLimit    int
	DailyQuota  int64
	ExpiresAt   *time.Time
	RotatedFrom *int64
}

func (s *Store) CreateAPIKey(ctx context.Context, n NewAPIKey, actor model.Actor) (model.APIKey, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.APIKey{}, err
	}

	defer tx.Rollback(ctx)
	k, err := scanAPIKey(tx.QueryRow(ctx, `INSERT INTO api_keys
		(name, prefix, key_hash, rps_limit, daily_quota, expires_at, rotated_from, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING `+apiKeyCols,
		n.Name, n.Prefix, n.KeyHash, n.RPSLimit, n.DailyQuota, n.ExpiresAt, n.RotatedFrom, actor.Email))
	if err != nil {
		if isUniqueViolation(err) {
			return model.APIKey{}, ErrDuplicate
		}

		return model.APIKey{}, err
	}

	if err := s.writeAudit(ctx, tx, actor, "apikey.create", 0, map[string]any{
		"id": k.ID, "name": k.Name, "prefix": k.Prefix, "rotated_from": k.RotatedFrom}); err != nil {
		return model.APIKey{}, err
	}

	return k, tx.Commit(ctx)
}

func (s *Store) GetAPIKeyByPrefix(ctx context.Context, prefix string) (model.APIKey, error) {
	k, err := scanAPIKey(s.write.QueryRow(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE prefix=$1`, prefix))
	return k, mapNotFound(err)
}

func (s *Store) GetAPIKey(ctx context.Context, id int64) (model.APIKey, error) {
	k, err := scanAPIKey(s.write.QueryRow(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE id=$1`, id))
	return k, mapNotFound(err)
}

func (s *Store) ListAPIKeys(ctx context.Context) ([]model.APIKey, error) {
	rows, err := s.write.Query(ctx, `SELECT `+apiKeyCols+` FROM api_keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.APIKey

	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, k)
	}

	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(ctx context.Context, id int64, actor model.Actor) error {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE api_keys SET status='revoked', revoked_at=now() WHERE id=$1 AND status='active'`, id)
	if err != nil {
		return err
	}

	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	if err := s.writeAudit(ctx, tx, actor, "apikey.revoke", 0, map[string]any{"id": id}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *Store) SetAPIKeyExpiry(ctx context.Context, id int64, at time.Time) error {
	_, err := s.write.Exec(ctx, `UPDATE api_keys SET expires_at=$2 WHERE id=$1`, id, at)
	return err
}

func (s *Store) TouchAPIKeys(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	_, err := s.write.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE id = ANY($1)`, ids)
	return err
}

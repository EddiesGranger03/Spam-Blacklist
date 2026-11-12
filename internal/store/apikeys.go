package store

import (
	"context"
	"time"

	"vsf/internal/model"
)

// #nosec G101 -- chỉ là danh sách tên cột SQL trong câu lệnh, không phải bí mật (false positive)
const apiKeyCols = `id, name, prefix, key_hash, status, rps_limit, max_batch, daily_quota, expires_at, rotated_from,
	created_by, created_at, last_used_at, revoked_at`

// scanAPIKey đọc một dòng API key từ kết quả truy vấn.
func scanAPIKey(row rowScanner) (model.APIKey, error) {
	var k model.APIKey
	err := row.Scan(&k.ID, &k.Name, &k.Prefix, &k.KeyHash, &k.Status, &k.RPSLimit, &k.MaxBatch, &k.DailyQuota,
		&k.ExpiresAt, &k.RotatedFrom, &k.CreatedBy, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt)
	return k, err
}

type NewAPIKey struct {
	Name        string
	Prefix      string
	KeyHash     []byte
	RPSLimit    int
	MaxBatch    int
	DailyQuota  int64
	ExpiresAt   *time.Time
	RotatedFrom *int64
}

// CreateAPIKey tạo API key mới (chỉ lưu hash), đồng thời ghi audit.
func (s *Store) CreateAPIKey(ctx context.Context, n NewAPIKey, actor model.Actor) (model.APIKey, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.APIKey{}, err
	}

	defer tx.Rollback(ctx)
	k, err := scanAPIKey(tx.QueryRow(ctx, `INSERT INTO api_keys
		(name, prefix, key_hash, rps_limit, max_batch, daily_quota, expires_at, rotated_from, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING `+apiKeyCols,
		n.Name, n.Prefix, n.KeyHash, n.RPSLimit, n.MaxBatch, n.DailyQuota, n.ExpiresAt, n.RotatedFrom, actor.Email))
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

// GetAPIKeyByPrefix tìm API key theo tiền tố hiển thị, dùng khi xác thực.
func (s *Store) GetAPIKeyByPrefix(ctx context.Context, prefix string) (model.APIKey, error) {
	k, err := scanAPIKey(s.write.QueryRow(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE prefix=$1`, prefix))
	return k, mapNotFound(err)
}

// GetAPIKey lấy một API key theo ID.
func (s *Store) GetAPIKey(ctx context.Context, id int64) (model.APIKey, error) {
	k, err := scanAPIKey(s.write.QueryRow(ctx, `SELECT `+apiKeyCols+` FROM api_keys WHERE id=$1`, id))
	return k, mapNotFound(err)
}

// ListAPIKeys liệt kê các API key.
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

// RevokeAPIKey thu hồi một API key (đánh dấu vô hiệu).
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

// SetAPIKeyExpiry đặt ngày hết hạn cho một API key.
func (s *Store) SetAPIKeyExpiry(ctx context.Context, id int64, at time.Time) error {
	_, err := s.write.Exec(ctx, `UPDATE api_keys SET expires_at=$2 WHERE id=$1`, id, at)
	return err
}

// TouchAPIKeys cập nhật thời điểm dùng gần nhất cho các API key vừa được sử dụng.
func (s *Store) TouchAPIKeys(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}

	_, err := s.write.Exec(ctx, `UPDATE api_keys SET last_used_at=now() WHERE id = ANY($1)`, ids)
	return err
}

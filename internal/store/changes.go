package store

import (
	"context"
	"time"

	"vsf/internal/model"
)

func (s *Store) Head(ctx context.Context) (xid string, seq int64, err error) {
	err = s.read.QueryRow(ctx, `SELECT xid::text, seq FROM change_log
		WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
		ORDER BY xid DESC, seq DESC LIMIT 1`).Scan(&xid, &seq)
	if err != nil {
		if mapNotFound(err) == ErrNotFound {
			return "0", 0, nil
		}

		return "", 0, err
	}

	return xid, seq, nil
}

func (s *Store) ChangesSince(ctx context.Context, afterXID string, afterSeq int64, limit int) ([]model.Change, error) {
	rows, err := s.read.Query(ctx, `SELECT seq, xid::text, value_hash FROM change_log
		WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
		  AND (xid, seq) > ($1::text::xid8, $2::bigint)
		ORDER BY xid, seq LIMIT $3`, afterXID, afterSeq, limit)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Change

	for rows.Next() {
		var c model.Change
		if err := rows.Scan(&c.Seq, &c.XID, &c.Hash); err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, rows.Err()
}

func (s *Store) PurgeChanges(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.write.Exec(ctx, `DELETE FROM change_log WHERE created_at < now() - make_interval(secs => $1::double precision)`,
		olderThan.Seconds())
	return tag.RowsAffected(), err
}

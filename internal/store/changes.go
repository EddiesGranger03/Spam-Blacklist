package store

import (
	"context"
	"time"

	"vsf/internal/model"
)

// Head trả về xid và seq của dòng change_log an toàn gần nhất (điểm bắt đầu của changefeed).
func (s *Store) Head(ctx context.Context) (xid string, seq int64, err error) {
	err = s.read.QueryRow(ctx, `SELECT xid::text, seq FROM change_log
		WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
		ORDER BY change_log.xid DESC, change_log.seq DESC LIMIT 1`).Scan(&xid, &seq)
	if err != nil {
		if mapNotFound(err) == ErrNotFound {
			return "0", 0, nil
		}

		return "", 0, err
	}

	return xid, seq, nil
}

// ChangesSince trả về mọi thay đổi đã commit sau (afterXID, afterSeq), theo thứ tự (xid, seq).
//
// Các dòng có xid nhỏ hơn xmin của database thì là cố định: không transaction nào còn có thể commit dòng nằm trước chúng.
// Các dòng có xid lớn hơn hoặc bằng xmin (Change.Pending) cũng đã commit và nhìn thấy được, nhưng một transaction cũ
// vẫn đang mở có thể còn commit một dòng nằm TRƯỚC chúng, nên người gọi không được đẩy con trỏ qua một dòng Pending.
// Vẫn có thể dùng hash của dòng đó ngay (thêm vào Bloom filter là idempotent), và đó là lý do trả về các dòng này:
// trước đây các dòng này bị ẩn cho đến khi xmin tiến lên, nên một transaction mở lâu ở đâu đó làm entry mới không vào được Bloom filter.
//
// ORDER BY phải ghi rõ cột của bảng (change_log.xid): danh sách chọn còn có cột đầu ra tên "xid" (xid::text),
// và ORDER BY xid trần sẽ trỏ vào CỘT ĐÓ, tức sắp xếp theo chữ ("100" < "99"). Lỗi này làm bỏ sót dòng ở ranh giới trang
// khi xid thêm một chữ số, và buộc bitmap scan cùng sắp xếp top-N trên mọi dòng sau con trỏ ở mỗi trang,
// thay vì duyệt index (xid, seq).
//
// Cột Pending được tính trong cùng câu lệnh (một snapshot) với các dòng, nên nhất quán trong một lần gọi.
// Vì thứ tự xid là đơn điệu, mọi dòng không Pending luôn đứng trước mọi dòng Pending trong kết quả.
func (s *Store) ChangesSince(ctx context.Context, afterXID string, afterSeq int64, limit int) ([]model.Change, error) {
	rows, err := s.read.Query(ctx, `SELECT seq, xid::text, value_hash,
			xid >= pg_snapshot_xmin(pg_current_snapshot()) AS pending
		FROM change_log
		WHERE (xid, seq) > ($1::text::xid8, $2::bigint)
		ORDER BY change_log.xid, change_log.seq LIMIT $3`, afterXID, afterSeq, limit)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Change

	for rows.Next() {
		var c model.Change
		if err := rows.Scan(&c.Seq, &c.XID, &c.Hash, &c.Pending); err != nil {
			return nil, err
		}

		out = append(out, c)
	}

	return out, rows.Err()
}

// PurgeChanges xóa các dòng change_log cũ hơn khoảng thời gian đã cho và trả về số dòng đã xóa.
func (s *Store) PurgeChanges(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := s.write.Exec(ctx, `DELETE FROM change_log WHERE created_at < now() - make_interval(secs => $1::double precision)`,
		olderThan.Seconds())
	return tag.RowsAffected(), err
}

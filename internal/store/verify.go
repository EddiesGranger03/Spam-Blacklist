package store

import (
	"context"
	"math"
)

// Truy vấn phục vụ bộ kiểm tra âm tính giả của filter (package verify). Cả hai chỉ đọc từ read pool.

// sampleOversample: lấy dư so với n để bù các dòng WHITELIST/hết hạn bị lọc bỏ và sai số của ước lượng reltuples;
// phần dư được bỏ ngẫu nhiên ở phía Go. sampleHardCap chặn trường hợp reltuples lệch nặng (ví dụ bảng chưa ANALYZE).
const (
	sampleOversample = 3
	sampleHardCap    = 20
)

// SampleActiveBlacklistHashes trả về tối đa khoảng sampleOversample*n value_hash ngẫu nhiên của các dòng
// status='BLACKLIST' chưa hết hạn (có thể trùng nếu nhiều dòng cùng hash; người gọi tự khử trùng).
//
// Dùng TABLESAMPLE SYSTEM (chọn ngẫu nhiên theo TRANG dữ liệu, mỗi partition bị lấy mẫu với cùng tỉ lệ) thay vì
// ORDER BY random(): random() phải đọc và sắp xếp toàn bộ bảng (trăm triệu dòng), còn SYSTEM chỉ đọc ~p% số trang.
// Tỉ lệ p tính từ pg_class.reltuples (ước lượng do autovacuum/ANALYZE duy trì, đọc không tốn gì) sao cho kỳ vọng
// ~3n dòng: với 1000 mẫu trên 100 triệu dòng (~60 dòng/trang) là ~50 trang, vài trăm KB I/O mỗi chu kỳ.
// Không dùng LIMIT nhỏ vì Append duyệt partition tuần tự, LIMIT sẽ dồn mẫu vào các partition đầu; chỉ có LIMIT trần
// sampleHardCap*n để an toàn. Lấy mẫu theo trang có tương quan trong trang (các dòng chèn cùng lúc nằm cạnh nhau),
// chấp nhận được vì mục tiêu là phát hiện filter hỏng diện rộng/lệch đồng bộ, và hash vốn rải ngẫu nhiên.
func (s *Store) SampleActiveBlacklistHashes(ctx context.Context, n int) ([]int64, error) {
	if n <= 0 {
		return nil, nil
	}

	var est float64
	if err := s.read.QueryRow(ctx, `SELECT COALESCE(sum(GREATEST(c.reltuples, 0)), 0)::float8
		FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
		WHERE i.inhparent = 'blacklist_entries'::regclass`).Scan(&est); err != nil {
		return nil, err
	}

	pct := 100.0
	if est > 0 {
		pct = math.Min(100, math.Max(0.0001, float64(sampleOversample*n)/est*100))
	}

	rows, err := s.read.Query(ctx, `SELECT value_hash FROM blacklist_entries TABLESAMPLE SYSTEM ($1)
		WHERE status = 'BLACKLIST' AND (expires_at IS NULL OR expires_at > now())
		LIMIT $2`, pct, sampleHardCap*n)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	out := make([]int64, 0, sampleOversample*n)
	for rows.Next() {
		var h int64
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}

		out = append(out, h)
	}

	return out, rows.Err()
}

// ActiveBlacklistVersions trả về, với mỗi hash trong hashes còn ít nhất một dòng BLACKLIST chưa hết hạn, một chuỗi
// "phiên bản" gồm id:xmin của các dòng đó. xmin đổi mỗi khi dòng bị UPDATE/xóa-chèn lại, nên hai lần đọc cho cùng
// chuỗi nghĩa là không có ghi nào lên các dòng này giữa hai lần đọc. Dùng index (value_hash, ...) + partition pruning.
func (s *Store) ActiveBlacklistVersions(ctx context.Context, hashes []int64) (map[int64]string, error) {
	out := map[int64]string{}
	if len(hashes) == 0 {
		return out, nil
	}

	rows, err := s.read.Query(ctx, `SELECT value_hash, string_agg(id::text || ':' || xmin::text, ',' ORDER BY id)
		FROM blacklist_entries
		WHERE value_hash = ANY($1) AND status = 'BLACKLIST' AND (expires_at IS NULL OR expires_at > now())
		GROUP BY value_hash`, hashes)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	for rows.Next() {
		var (
			h int64
			v string
		)

		if err := rows.Scan(&h, &v); err != nil {
			return nil, err
		}

		out[h] = v
	}

	return out, rows.Err()
}

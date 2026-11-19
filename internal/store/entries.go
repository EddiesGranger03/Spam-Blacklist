package store

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

// entryCols kết thúc bằng key_version: cột này cho biết khóa dữ liệu nào đã mã hóa value_enc, note_enc và source_enc của dòng,
// và scanEntry cần nó để chọn đúng khóa. Nơi nào chọn thêm cột thì nối chúng vào sau entryCols.
const entryCols = `id, type, match_type, value_enc, category, risk_score, source_enc, note_enc,
	expires_at, created_by, created_at, updated_at, key_version, status`

type rowScanner interface{ Scan(dest ...any) error }

// scanEntry đọc một dòng được chọn bằng entryCols (cộng thêm các cột phụ nếu có, quét vào extra)
// và giải mã các trường đã mã hóa.
func (s *Store) scanEntry(row rowScanner, extra ...any) (model.Entry, error) {
	var (
		e                         model.Entry
		score                     int16
		version                   int16
		valueEnc, srcEnc, noteEnc []byte
	)

	dest := append([]any{&e.ID, &e.Type, &e.MatchType, &valueEnc, &e.Category, &score, &srcEnc, &noteEnc,
		&e.ExpiresAt, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt, &version, &e.Status}, extra...)
	if err := row.Scan(dest...); err != nil {
		return model.Entry{}, err
	}

	e.RiskScore = int(score)

	if err := s.openEntry(&e, version, valueEnc, noteEnc, srcEnc); err != nil {
		return model.Entry{}, fmt.Errorf("entry %d: %w", e.ID, err)
	}

	return e, nil
}

// scanEntryHash đọc một entry kèm value_hash từ một dòng kết quả truy vấn.
func (s *Store) scanEntryHash(row rowScanner) (model.Entry, int64, error) {
	var hash int64
	e, err := s.scanEntry(row, &hash)

	return e, hash, err
}

// opForStatus: entry BLACKLIST thì hash cần nằm trong filter (add); entry WHITELIST thì không (remove).
func opForStatus(status string) int16 {
	if status == model.StatusWhitelist {
		return model.OpRemove
	}

	return model.OpAdd
}

// CreateEntry tạo một entry blacklist mới (mã hóa dữ liệu, tính chỉ mục) và ghi change_log.
func (s *Store) CreateEntry(ctx context.Context, key normalize.Key, in model.EntryInput, actor model.Actor) (model.Entry, error) {
	// Store tự kiểm tra risk_score (cột SMALLINT) thay vì tin người gọi đã Validate.
	score, err := riskScore16(in.RiskScore)
	if err != nil {
		return model.Entry{}, err
	}

	status := in.Status
	if status == "" {
		status = model.StatusBlacklist
	}

	if status != model.StatusBlacklist && status != model.StatusWhitelist {
		return model.Entry{}, fmt.Errorf("%w: status must be BLACKLIST or WHITELIST", normalize.ErrInvalid)
	}

	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Entry{}, err
	}

	defer tx.Rollback(ctx)

	var batch changeBatch

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
		 category, risk_score, expires_at, created_by, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING `+entryCols,
		string(key.Type), string(key.MatchType), key.Hash, key.Blind, valueEnc, noteEnc, sourceEnc,
		s.sealer.Version(), in.Category, score, in.ExpiresAt, actor.Email, status)
	e, err := s.scanEntry(row)
	if err != nil {
		if isUniqueViolation(err) {
			return model.Entry{}, ErrDuplicate
		}

		return model.Entry{}, err
	}

	// WHITELIST: không thêm vào filter (op remove) nhưng vẫn ghi dòng để epoch đổi, vì một luật BLACKLIST domain/prefix
	// có thể đã được cache cho chính giá trị này.
	if err := logChange(ctx, tx, key.Hash, opForStatus(status), &batch); err != nil {
		return model.Entry{}, err
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.create", e.ID, map[string]any{"after": s.auditView(e)}); err != nil {
		return model.Entry{}, err
	}

	return e, s.commitAndNotify(ctx, tx, &batch)
}

// GetEntry lấy một entry theo ID; trả ErrNotFound nếu không có.
func (s *Store) GetEntry(ctx context.Context, id int64) (model.Entry, error) {
	e, err := s.scanEntry(s.write.QueryRow(ctx, `SELECT `+entryCols+` FROM blacklist_entries WHERE id=$1`, id))
	return e, mapNotFound(err)
}

// UpdateEntry cập nhật metadata và (tùy chọn) status của một entry, không đổi giá trị.
func (s *Store) UpdateEntry(ctx context.Context, id int64, in model.EntryInput, actor model.Actor) (model.Entry, error) {
	return s.UpdateEntryKey(ctx, id, in, nil, actor)
}

// UpdateEntryKey như UpdateEntry nhưng cho phép đổi cả giá trị: newKey (đã chuẩn hóa bằng normalize.NormalizeEntry,
// cùng type và match_type với entry hiện tại) thay cho giá trị cũ; nil = giữ nguyên giá trị.
//
// value_hash là khóa partition nên đổi giá trị = chuyển dòng sang partition khác: DELETE dòng cũ + INSERT dòng mới
// với cùng id (và created_at/created_by) trong MỘT transaction, nên không bao giờ thấy dòng biến mất hay nhân đôi.
// Trùng với entry khác -> ErrDuplicate (handler trả 409), transaction rollback, dòng cũ còn nguyên.
//
// change_log: hash cũ ghi op remove + hash mới ghi op add (BLACKLIST) hoặc remove (WHITELIST). Khi giữ nguyên giá trị:
// một dòng theo status mới (BLACKLIST->add, WHITELIST->remove). Luôn có ít nhất một dòng để epoch đổi.
func (s *Store) UpdateEntryKey(ctx context.Context, id int64, in model.EntryInput, newKey *normalize.Key, actor model.Actor) (model.Entry, error) {
	// Store tự kiểm tra risk_score (cột SMALLINT) thay vì tin người gọi đã Validate.
	score, err := riskScore16(in.RiskScore)
	if err != nil {
		return model.Entry{}, err
	}

	if in.Status != "" && in.Status != model.StatusBlacklist && in.Status != model.StatusWhitelist {
		return model.Entry{}, fmt.Errorf("%w: status must be BLACKLIST or WHITELIST", normalize.ErrInvalid)
	}

	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Entry{}, err
	}

	defer tx.Rollback(ctx)

	var batch changeBatch

	before, hash, err := s.scanEntryHash(tx.QueryRow(ctx,
		`SELECT `+entryCols+`, value_hash FROM blacklist_entries WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return model.Entry{}, mapNotFound(err)
	}

	status := in.Status
	if status == "" {
		status = before.Status
	}

	noteEnc, sourceEnc, err := s.sealNoteSource(in.Note, in.Source)
	if err != nil {
		return model.Entry{}, err
	}

	if newKey != nil && (string(newKey.Type) != before.Type || string(newKey.MatchType) != before.MatchType) {
		return model.Entry{}, fmt.Errorf("%w: type and match_type cannot be changed", normalize.ErrInvalid)
	}

	// key_version xác định khóa cho CẢ BA bản mã của dòng, nên ghi phiên bản hiện tại mà để value_enc ở khóa cũ
	// sẽ làm dòng không đọc được khi khóa cũ bị gỡ bỏ (C4). Giá trị đã được giải mã ở trên, nên mã hóa lại bằng khóa hiện tại:
	// một lần cập nhật cũng chuyển dòng sang khóa mới.
	value := before.Value
	moved := newKey != nil && newKey.Value != before.Value

	if moved {
		value = newKey.Value
	}

	valueEnc, err := s.sealer.Seal(value, seal.AADValue)
	if err != nil {
		return model.Entry{}, err
	}

	var after model.Entry

	if !moved {
		after, err = s.scanEntry(tx.QueryRow(ctx, `UPDATE blacklist_entries
			SET category=$3, risk_score=$4, source_enc=$5, note_enc=$6, expires_at=$7, key_version=$8, value_enc=$9,
			    status=$10, updated_at=now()
			WHERE value_hash=$2 AND id=$1 RETURNING `+entryCols,
			id, hash, in.Category, score, sourceEnc, noteEnc, in.ExpiresAt, s.sealer.Version(), valueEnc, status))
		if err != nil {
			return model.Entry{}, mapNotFound(err)
		}

		if err := logChange(ctx, tx, hash, opForStatus(status), &batch); err != nil {
			return model.Entry{}, err
		}
	} else {
		tag, err := tx.Exec(ctx, `DELETE FROM blacklist_entries WHERE id=$1 AND value_hash=$2`, id, hash)
		if err != nil {
			return model.Entry{}, err
		}

		if tag.RowsAffected() != 1 {
			return model.Entry{}, ErrNotFound
		}

		after, err = s.scanEntry(tx.QueryRow(ctx, `INSERT INTO blacklist_entries
			(id, type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version,
			 category, risk_score, expires_at, created_by, created_at, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING `+entryCols,
			id, before.Type, before.MatchType, newKey.Hash, newKey.Blind, valueEnc, noteEnc, sourceEnc, s.sealer.Version(),
			in.Category, score, in.ExpiresAt, before.CreatedBy, before.CreatedAt, status))
		if err != nil {
			if isUniqueViolation(err) {
				return model.Entry{}, ErrDuplicate
			}

			return model.Entry{}, err
		}

		if err := logChange(ctx, tx, hash, model.OpRemove, &batch); err != nil {
			return model.Entry{}, err
		}

		if err := logChange(ctx, tx, newKey.Hash, opForStatus(status), &batch); err != nil {
			return model.Entry{}, err
		}
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.update", id, map[string]any{"before": s.auditView(before), "after": s.auditView(after)}); err != nil {
		return model.Entry{}, err
	}

	return after, s.commitAndNotify(ctx, tx, &batch)
}

// DeleteEntry xóa một entry và ghi change_log cho hash của nó.
func (s *Store) DeleteEntry(ctx context.Context, id int64, actor model.Actor) error {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	var batch changeBatch

	e, hash, err := s.scanEntryHash(tx.QueryRow(ctx,
		`DELETE FROM blacklist_entries WHERE id=$1 RETURNING `+entryCols+`, value_hash`, id))
	if err != nil {
		return mapNotFound(err)
	}

	if err := logChange(ctx, tx, hash, model.OpRemove, &batch); err != nil {
		return err
	}

	if err := s.writeAudit(ctx, tx, actor, "entry.delete", id, map[string]any{"before": s.auditView(e)}); err != nil {
		return err
	}

	return s.commitAndNotify(ctx, tx, &batch)
}

type ListFilter struct {
	Type     string
	Category string
	Status   string // "" = mọi status
	Cursor   int64
	Limit    int
	Search   []normalize.Key
	Asc      bool
}

// ListEntries liệt kê entry theo bộ lọc và trang (keyset).
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

	if f.Status != "" {
		add("status = $%d", f.Status)
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

// FindMatches tìm các entry khớp với danh sách khóa đã băm, bỏ qua entry đã hết hạn; dùng khi Bloom báo có thể có.
func (s *Store) FindMatches(ctx context.Context, keys []normalize.Key) ([]model.Entry, error) {
	return s.findMatches(ctx, s.read, keys)
}

// FindMatchesPrimary như FindMatches nhưng đọc primary: checker dùng khi replica có thể đang trễ sau một thay đổi
// đã được báo qua Pub/Sub (F6). Không có replica thì tương đương FindMatches.
func (s *Store) FindMatchesPrimary(ctx context.Context, keys []normalize.Key) ([]model.Entry, error) {
	return s.findMatches(ctx, s.write, keys)
}

func (s *Store) findMatches(ctx context.Context, db *pgxpool.Pool, keys []normalize.Key) ([]model.Entry, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	// Vì sao dùng ANY thay vì join unnest(...): dạng join làm Postgres lập kế hoạch lại qua cả 32 partition ở mỗi lần gọi
	// (kế hoạch generic đã cache luôn tốn hơn nên không bao giờ được chọn). Đo được khoảng 1-2 ms lập kế hoạch cho ~0,1 ms thực thi,
	// khiến tra cứu DB bị giới hạn ở ~2,5k/s. Với ANY, partition được cắt ngay lúc lập kế hoạch và tra cứu nhanh hơn 4-9 lần.
	// ANY so từng cột độc lập, nên việc khớp chính xác từng ứng viên được kiểm tra lại bên dưới.
	type candidate struct {
		hash    int64
		typ, mt string
		blind   string
	}

	hashes := make([]int64, len(keys))
	types := make([]string, len(keys))
	mts := make([]string, len(keys))
	blinds := make([][]byte, len(keys))
	want := make(map[candidate]struct{}, len(keys))

	for i, k := range keys {
		hashes[i], types[i], mts[i], blinds[i] = k.Hash, string(k.Type), string(k.MatchType), k.Blind
		want[candidate{k.Hash, string(k.Type), string(k.MatchType), string(k.Blind)}] = struct{}{}
	}

	rows, err := db.Query(ctx, `SELECT `+entryCols+`, value_hash, value_blind
		FROM blacklist_entries
		WHERE value_hash = ANY($1::bigint[]) AND value_blind = ANY($4::bytea[])
		  AND type = ANY($2::text[]) AND match_type = ANY($3::text[])
		  AND (expires_at IS NULL OR expires_at > now())`, hashes, types, mts, blinds)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Entry

	for rows.Next() {
		var (
			hash  int64
			blind []byte
		)

		e, err := s.scanEntry(rows, &hash, &blind)
		if err != nil {
			return nil, err
		}

		if _, ok := want[candidate{hash, e.Type, e.MatchType, string(blind)}]; !ok {
			continue
		}

		out = append(out, e)
	}

	return out, rows.Err()
}

// AllHashes gọi emit với mọi value_hash trong bảng, dùng để dựng lại Bloom filter.
func (s *Store) AllHashes(ctx context.Context, emit func(uint64)) error {
	rows, err := s.read.Query(ctx, `SELECT value_hash FROM blacklist_entries WHERE status = 'BLACKLIST'`)
	if err != nil {
		return err
	}

	defer rows.Close()
	for rows.Next() {
		var h int64
		if err := rows.Scan(&h); err != nil {
			return err
		}

		emit(uint64(h)) // #nosec G115 -- chủ ý: cùng bit pattern với hash đã lưu trong BIGINT
	}

	return rows.Err()
}

// EstimatedCount ước lượng số dòng từ thống kê của PostgreSQL (nhanh, không quét bảng).
func (s *Store) EstimatedCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.read.QueryRow(ctx, `SELECT COALESCE(SUM(GREATEST(reltuples,0)),0)::bigint
		FROM pg_class WHERE relname LIKE 'blacklist_entries_p%' AND relkind='r'`).Scan(&n)
	return n, err
}

// ExportBatch lấy một lô entry để xuất CSV, theo thứ tự id và sau một id cho trước.
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

// ParseExpiry đọc ngày hết hạn từ chuỗi (YYYY-MM-DD hoặc RFC3339); chuỗi rỗng trả về nil.
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

// riskScore16 kiểm tra risk_score nằm trong 0..100 rồi đổi sang int16 để ghi vào cột SMALLINT.
func riskScore16(score int) (int16, error) {
	if score < 0 || score > 100 {
		return 0, fmt.Errorf("%w: risk_score phải từ 0 đến 100, nhận được %d", normalize.ErrInvalid, score)
	}

	return int16(score), nil // #nosec G115 -- score đã được kiểm tra 0..100 ngay phía trên
}

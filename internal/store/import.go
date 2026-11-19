package store

import (
	"context"
	"fmt"
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

// ImportResult tổng hợp những gì đã COMMIT cho tới nay. Rows đếm số dòng đầu vào của các lô đã commit (trước khi khử trùng),
// Batches đếm số transaction đã commit.
type ImportResult struct {
	Inserted int64
	Updated  int64
	Rows     int64
	Batches  int
}

// ImportOptions chỉnh tham số cho ImportWith. Giá trị zero dùng mặc định.
type ImportOptions struct {
	BatchRows  int // rows per transaction; 0 = defaultImportBatchRows
	BatchBytes int // approximate sealed bytes per transaction; 0 = defaultImportBatchBytes

	// Progress, nếu được đặt, được gọi sau mỗi lô đã commit với tổng số đang chạy. Lúc hàm này chạy không có transaction nào đang mở.
	Progress func(ImportResult)
}

// Cỡ lô được chọn theo đo đạc (500k dòng tổng hợp, một lô = 6,3 s): 10k dòng/lô mất 12,5 s, 25k là 8,0 s,
// 50k là 8,2 s, 100k là 7,3 s, 250k là 6,5 s. Mỗi lô tốn một chi phí cố định (bảng tạm, khử trùng/đếm, commit), nên lô quá nhỏ
// thì chậm, còn tới vài trăm nghìn dòng vẫn giữ transaction trong vài giây, và đó là điều quan trọng
// (bản cũ giữ một transaction mở suốt cả lần import).
const (
	defaultImportBatchRows  = 100_000
	defaultImportBatchBytes = 32 << 20 // sealed notes can be 2 KB each, so rows alone would not bound memory
)

var importStageCols = []string{"ord", "type", "match_type", "value_hash", "value_blind",
	"value_enc", "note_enc", "source_enc", "key_version", "category", "risk_score", "expires_at"}

// Import nạp dòng với cỡ lô mặc định. Xem ImportWith.
func (s *Store) Import(ctx context.Context, it RowIterator, actor model.Actor) (ImportResult, error) {
	return s.ImportWith(ctx, it, actor, ImportOptions{})
}

// ImportWith nạp dòng bằng nhiều transaction ngắn thay vì một transaction dài.
//
// Lý do: bản cũ giữ một transaction duy nhất mở cho cả file (đọc CSV, sao chép, gộp, tối đa 2 giờ theo giới hạn job).
// Điều này giữ xmin của database lại suốt thời gian đó, nên Postgres không dọn được dòng chết ở bất kỳ đâu, không có tiến độ nào hiện ra,
// và lỗi ở giờ thứ hai làm mất hết. Bây giờ mỗi lô được đọc, kiểm tra và mã hóa trong bộ nhớ trước, rồi mới ghi trong một transaction ngắn
// (bảng tạm, upsert và các dòng change_log mà changefeed phụ thuộc, tất cả trong cùng transaction), nên transaction chỉ kéo dài vài giây.
//
// Những điều người gọi cần biết:
//   - Nếu lỗi xảy ra, các lô đã commit trước đó được giữ nguyên; kết quả trả về cho biết có bao nhiêu lô. Chạy lại đúng file đó là an toàn,
//     vì upsert cho cùng kết quả với các dòng đã nạp (chúng chỉ được đếm là Updated ở lần sau).
//   - Entry hiện ra (và vào Bloom filter) theo từng lô, không phải đồng loạt ở cuối.
//   - Một giá trị lặp lại trong cùng một lô được gộp (dòng sau thắng, như trước); một giá trị lặp qua hai lô thì được đếm là Inserted lần đầu và Updated lần sau.
//     Các lô chạy theo thứ tự file, nên dòng sau vẫn thắng.
//   - Audit: "entry.import.start" được ghi trước khi nạp bất cứ thứ gì, và "entry.import" (trạng thái done/failed kèm tổng số) ghi ở cuối,
//     nên ngay cả khi crash giữa chừng vẫn để lại dấu vết.
func (s *Store) ImportWith(ctx context.Context, it RowIterator, actor model.Actor, opts ImportOptions) (res ImportResult, err error) {
	if s.sealer == nil {
		return res, errNoSealer
	}

	maxRows, maxBytes := opts.BatchRows, opts.BatchBytes
	if maxRows <= 0 {
		maxRows = defaultImportBatchRows
	}

	if maxBytes <= 0 {
		maxBytes = defaultImportBatchBytes
	}

	if err := s.WriteAudit(ctx, actor, "entry.import.start", map[string]any{"at": time.Now().UTC()}); err != nil {
		return res, fmt.Errorf("audit start: %w", err)
	}

	defer func() {
		// ctx của người gọi có thể chính là lý do import thất bại, nên dòng audit kết thúc không được dùng nó.
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()

		detail := map[string]any{"status": "done", "inserted": res.Inserted, "updated": res.Updated,
			"rows": res.Rows, "batches": res.Batches, "at": time.Now().UTC()}
		if err != nil {
			detail["status"], detail["error"] = "failed", truncate(err.Error(), 200)
		}

		if aerr := s.WriteAudit(actx, actor, "entry.import", detail); aerr != nil && err == nil {
			err = fmt.Errorf("import committed %d rows but the closing audit row failed: %w", res.Rows, aerr)
		}
	}()

	var ord int64

	for {
		batch, eof, rerr := s.readImportBatch(it, &ord, maxRows, maxBytes)
		if rerr != nil {
			return res, rerr
		}

		if len(batch) > 0 {
			br, berr := s.importBatch(ctx, batch, actor)
			if berr != nil {
				return res, fmt.Errorf("batch %d failed after %d rows were committed: %w", res.Batches+1, res.Rows, berr)
			}

			res.Inserted += br.Inserted
			res.Updated += br.Updated
			res.Rows += int64(len(batch))
			res.Batches++

			if opts.Progress != nil {
				opts.Progress(res)
			}
		}

		if eof {
			return res, nil
		}
	}
}

// readImportBatch lấy dòng từ iterator và mã hóa chúng, KHÔNG chạm tới database, cho tới khi lô đầy hoặc hết đầu vào.
// Nếu iterator báo lỗi thì lô đang dở bị bỏ.
func (s *Store) readImportBatch(it RowIterator, ord *int64, maxRows, maxBytes int) (rows [][]any, eof bool, err error) {
	size := 0

	for len(rows) < maxRows && size < maxBytes {
		r, ok := it.Next()
		if !ok {
			if ierr := it.Err(); ierr != nil {
				return nil, true, ierr
			}

			return rows, true, nil
		}

		valueEnc, err := s.sealer.Seal(r.Key.Value, seal.AADValue)
		if err != nil {
			return nil, false, err
		}

		noteEnc, sourceEnc, err := s.sealNoteSource(r.Input.Note, r.Input.Source)
		if err != nil {
			return nil, false, err
		}

		score, err := riskScore16(r.Input.RiskScore)
		if err != nil {
			return nil, false, err
		}

		*ord++
		rows = append(rows, []any{*ord, string(r.Key.Type), string(r.Key.MatchType), r.Key.Hash, r.Key.Blind,
			valueEnc, noteEnc, sourceEnc, s.sealer.Version(),
			r.Input.Category, score, r.Input.ExpiresAt})

		size += len(valueEnc) + len(noteEnc) + len(sourceEnc) + len(r.Key.Blind) + 128
	}

	return rows, false, nil
}

// importBatch ghi một lô đã chuẩn bị trong một transaction ngắn.
func (s *Store) importBatch(ctx context.Context, rows [][]any, actor model.Actor) (ImportResult, error) {
	var res ImportResult

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

	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"import_stage"}, importStageCols, pgx.CopyFromRows(rows)); err != nil {
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
			value_enc = EXCLUDED.value_enc, -- key_version names the key of ALL three ciphertexts (C4)
			updated_at = now()`,
		actor.Email); err != nil {
		return res, err
	}

	// Phải nằm trong cùng transaction với upsert: changefeed chỉ biết hash mới từ đây.
	// Import có thể ghi hàng triệu dòng: chỉ lấy seq lớn nhất để gửi tín hiệu "đánh thức", không gửi từng hash.
	var seqMax int64
	if err := tx.QueryRow(ctx, `WITH ins AS (INSERT INTO change_log(value_hash) SELECT DISTINCT value_hash FROM import_stage RETURNING seq)
		SELECT coalesce(max(seq), 0) FROM ins`).Scan(&seqMax); err != nil {
		return res, err
	}

	if err := tx.Commit(ctx); err != nil {
		return res, err
	}

	s.notify(ctx, seqMax, nil)

	return res, nil
}

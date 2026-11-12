package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

// Xoay khóa mã hóa (C4). Mỗi dòng mang key_version, cho biết khóa nào đã mã hóa CẢ BA bản mã của nó (value_enc, note_enc, source_enc).
// Khi đọc, hệ thống chọn khóa theo số này, nên sau khi đổi DATA_KEY các dòng cũ vẫn đọc được miễn khóa cũ còn khai báo là DATA_KEY_V<n>;
// dòng mới và dòng được sửa được mã hóa bằng khóa hiện tại;
// Rekey chuyển các dòng cũ còn lại sang khóa mới; VerifyKeys ngăn server khởi động khi cấu hình không đọc được dữ liệu
// (sai DATA_KEY, thiếu DATA_KEY_V<n>, hoặc khác DATA_PEPPER).

// KeyCheck tóm tắt những gì VerifyKeys đã kiểm tra.
type KeyCheck struct {
	Sampled  int
	Versions map[int16]int // sampled rows per key version
}

const (
	keyCheckSample  = 25 // rows per probe: the oldest, the newest, and a few random spots
	keyCheckRandoms = 3
)

type sampledRow struct {
	id                           int64
	typ, mt                      string
	hash                         int64
	blind                        []byte
	valueEnc, noteEnc, sourceEnc []byte
	version                      int16
}

// sampleRows lấy mẫu các dòng theo truy vấn đã cho, trả về bản mã và key_version để kiểm tra khóa.
func (s *Store) sampleRows(ctx context.Context, query string, args ...any) ([]sampledRow, error) {
	rows, err := s.write.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var out []sampledRow

	for rows.Next() {
		var r sampledRow
		if err := rows.Scan(&r.id, &r.typ, &r.mt, &r.hash, &r.blind, &r.valueEnc, &r.noteEnc, &r.sourceEnc, &r.version); err != nil {
			return nil, err
		}

		out = append(out, r)
	}

	return out, rows.Err()
}

const sampleCols = `SELECT id, type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version FROM blacklist_entries`

// VerifyKeys kiểm tra các khóa đã cấu hình dựa trên một mẫu dữ liệu đã lưu, và trả lỗi nói rõ cần sửa gì.
// Hàm lấy mẫu (bảng có thể hàng trăm triệu dòng): các dòng cũ nhất, mới nhất và vài vị trí ngẫu nhiên,
// vì đó là nơi thể hiện ranh giới khi xoay khóa. Với mỗi dòng được lấy mẫu, hàm kiểm tra:
//
//   - có khóa cho key_version của dòng, nếu không thì yêu cầu đặt DATA_KEY_V<n>;
//   - cả ba bản mã giải mã được bằng khóa đó, nếu không thì khóa không phải khóa đã mã hóa dữ liệu;
//   - chỉ mục tra cứu tính lại từ giá trị đã giải mã phải khớp value_hash/value_blind đã lưu, nếu không thì
//     DATA_PEPPER khác pepper đã tạo chỉ mục. Trường hợp này im lặng và tệ nhất: mọi lần tra cứu sẽ trượt,
//     nên các giá trị đang bị chặn sẽ bị báo là an toàn.
//
// Bảng rỗng thì coi là đạt.
func (s *Store) VerifyKeys(ctx context.Context) (KeyCheck, error) {
	check := KeyCheck{Versions: map[int16]int{}}

	if s.sealer == nil {
		return check, errNoSealer
	}

	var lo, hi *int64
	if err := s.write.QueryRow(ctx, `SELECT min(id), max(id) FROM blacklist_entries`).Scan(&lo, &hi); err != nil {
		return check, err
	}

	if lo == nil || hi == nil {
		return check, nil
	}

	byID := map[int64]sampledRow{}

	add := func(rows []sampledRow, err error) error {
		if err != nil {
			return err
		}

		for _, r := range rows {
			byID[r.id] = r
		}

		return nil
	}

	if err := add(s.sampleRows(ctx, sampleCols+` ORDER BY id LIMIT $1`, keyCheckSample)); err != nil {
		return check, err
	}

	if err := add(s.sampleRows(ctx, sampleCols+` ORDER BY id DESC LIMIT $1`, keyCheckSample)); err != nil {
		return check, err
	}

	for i := 0; i < keyCheckRandoms; i++ {
		start := *lo + rand.Int63n(*hi-*lo+1)  // #nosec G404 -- chọn vị trí mẫu để kiểm tra khóa, không cần ngẫu nhiên an toàn
		if err := add(s.sampleRows(ctx, sampleCols+` WHERE id >= $1 ORDER BY id LIMIT $2`, start, keyCheckSample)); err != nil {
			return check, err
		}
	}

	var problems []error

	seen := map[string]bool{}
	report := func(kind string, err error) {
		if !seen[kind] {
			seen[kind] = true
			problems = append(problems, err)
		}
	}

	ids := make([]int64, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}

	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	for _, id := range ids {
		r := byID[id]
		check.Sampled++
		check.Versions[r.version]++

		if !s.sealer.HasVersion(r.version) {
			report(fmt.Sprintf("version-%d", r.version), fmt.Errorf(
				"entry %d is sealed under key version %d but no key is configured for it: set DATA_KEY_V%d to the key that "+
					"was DATA_KEY when it was written (%w)", r.id, r.version, r.version, seal.ErrUnknownKeyVersion))

			continue
		}

		value, err := s.sealer.OpenVersion(r.version, r.valueEnc, seal.AADValue)
		if err == nil {
			_, err = s.sealer.OpenVersion(r.version, r.noteEnc, seal.AADNote)
		}

		if err == nil {
			_, err = s.sealer.OpenVersion(r.version, r.sourceEnc, seal.AADSource)
		}

		if err != nil {
			report(fmt.Sprintf("decrypt-%d", r.version), fmt.Errorf(
				"entry %d (key version %d) cannot be decrypted: the key configured for version %d is not the one that "+
					"sealed it, so DATA_KEY (or DATA_KEY_V%d) is wrong: %w", r.id, r.version, r.version, r.version, err))

			continue
		}

		k := normalize.MakeKey(normalize.Type(r.typ), normalize.MatchType(r.mt), value)
		if k.Hash != r.hash || !bytes.Equal(k.Blind, r.blind) {
			report("pepper", fmt.Errorf("entry %d: the lookup index recomputed from its value does not match the stored one, "+
				"so DATA_PEPPER is not the one that built this data; with it every lookup would miss and blacklisted values "+
				"would be reported as safe", r.id))
		}
	}

	return check, errors.Join(problems...)
}

// KeyVersionCounts trả về số dòng được mã hóa dưới mỗi phiên bản khóa. Hàm quét toàn bảng nên chỉ dành cho báo cáo
// trạng thái của công cụ rekey, không dùng khi khởi động.
func (s *Store) KeyVersionCounts(ctx context.Context) (map[int16]int64, error) {
	rows, err := s.write.Query(ctx, `SELECT key_version, count(*) FROM blacklist_entries GROUP BY key_version`)
	if err != nil {
		return nil, err
	}

	defer rows.Close()

	out := map[int16]int64{}

	for rows.Next() {
		var (
			v int16
			n int64
		)

		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}

		out[v] = n
	}

	return out, rows.Err()
}

// RekeyOptions chỉnh tham số cho Rekey. Giá trị zero dùng mặc định.
type RekeyOptions struct {
	Batch    int  // rows per statement; 0 = defaultRekeyBatch
	DryRun   bool // read and decrypt everything that would be rewritten, but write nothing
	Progress func(RekeyResult)

	afterScan func() // test hook: runs between reading a batch and writing it
}

// RekeyResult totals what Rekey has done so far.
type RekeyResult struct {
	Scanned   int64
	Rewritten int64
	Skipped   int64 // rows an edit changed between the read and the write: already on the current key, nothing to do
	Batches   int
	From      map[int16]int64 // rows found per old key version
}

const defaultRekeyBatch = 5000

// Rekey mã hóa lại mọi dòng chưa được mã hóa bằng khóa hiện tại, để có thể bỏ khóa cũ. An toàn khi chạy lúc server đang chạy
// và có thể chạy lại sau khi bị gián đoạn:
//
//   - mỗi lô là một câu lệnh ngắn, chỉ chạm tới value_enc, note_enc, source_enc và key_version: bản rõ,
//     hash và chỉ mục blind giữ nguyên, nên không cần ghi change_log, không xóa cache, không cập nhật Bloom;
//     (vì không đổi nội dung nên không cần làm các bước đó)
//   - việc ghi được bảo vệ bởi điều kiện "key_version vẫn bằng giá trị cũ", nên dòng mà admin vừa sửa
//     (lần sửa đã mã hóa lại bằng khóa hiện tại) sẽ bị bỏ qua thay vì bị ghi đè;
//   - dòng được mã hóa dưới một phiên bản khóa chưa cấu hình sẽ dừng việc chạy với lỗi nêu rõ DATA_KEY_V<n>, trước khi
//     đoán mò bất cứ điều gì.
//
// Lần chạy thật ghi một dòng audit lúc bắt đầu và một dòng lúc kết thúc (trạng thái done hoặc failed, kèm tổng số).
func (s *Store) Rekey(ctx context.Context, actor model.Actor, opts RekeyOptions) (res RekeyResult, err error) {
	res.From = map[int16]int64{}

	if s.sealer == nil {
		return res, errNoSealer
	}

	batch := opts.Batch
	if batch <= 0 {
		batch = defaultRekeyBatch
	}

	if !opts.DryRun {
		if err := s.WriteAudit(ctx, actor, "entry.rekey.start", map[string]any{
			"to_version": s.sealer.Version(), "at": time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("audit start: %w", err)
		}

		defer func() {
			actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()

			detail := map[string]any{"status": "done", "to_version": s.sealer.Version(), "scanned": res.Scanned,
				"rewritten": res.Rewritten, "skipped": res.Skipped, "batches": res.Batches, "from": res.From, "at": time.Now().UTC()}
			if err != nil {
				detail["status"], detail["error"] = "failed", truncate(err.Error(), 200)
			}

			if aerr := s.WriteAudit(actx, actor, "entry.rekey", detail); aerr != nil && err == nil {
				err = fmt.Errorf("rekey finished but the closing audit row failed: %w", aerr)
			}
		}()
	}

	current := s.sealer.Version()

	var after int64

	for {
		rows, qerr := s.write.Query(ctx, `SELECT id, value_hash, value_enc, note_enc, source_enc, key_version FROM blacklist_entries
			WHERE key_version <> $1 AND id > $2 ORDER BY id LIMIT $3`, current, after, batch)
		if qerr != nil {
			return res, qerr
		}

		var (
			ids, hashes                  []int64
			oldVersions                  []int16
			valueEnc, noteEnc, sourceEnc [][]byte
			n                            int
		)

		for rows.Next() {
			var (
				id, hash         int64
				version          int16
				vEnc, nEnc, sEnc []byte
			)

			if err := rows.Scan(&id, &hash, &vEnc, &nEnc, &sEnc, &version); err != nil {
				rows.Close()
				return res, err
			}

			n++
			after = id
			res.Scanned++
			res.From[version]++

			value, err := s.sealer.OpenVersion(version, vEnc, seal.AADValue)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d (key version %d): %w", id, version, err)
			}

			note, err := s.sealer.OpenVersion(version, nEnc, seal.AADNote)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d (key version %d): %w", id, version, err)
			}

			source, err := s.sealer.OpenVersion(version, sEnc, seal.AADSource)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d (key version %d): %w", id, version, err)
			}

			if opts.DryRun {
				continue
			}

			nv, err := s.sealer.Seal(value, seal.AADValue)
			if err != nil {
				rows.Close()
				return res, err
			}

			nn, ns, err := s.sealNoteSource(note, source)
			if err != nil {
				rows.Close()
				return res, err
			}

			ids, hashes, oldVersions = append(ids, id), append(hashes, hash), append(oldVersions, version)
			valueEnc, noteEnc, sourceEnc = append(valueEnc, nv), append(noteEnc, nn), append(sourceEnc, ns)
		}

		rows.Close()

		if err := rows.Err(); err != nil {
			return res, err
		}

		if opts.afterScan != nil {
			opts.afterScan()
		}

		if len(ids) > 0 {
			tag, err := s.write.Exec(ctx, `UPDATE blacklist_entries e SET value_enc = u.ve, note_enc = u.ne, source_enc = u.se, key_version = $1
				FROM unnest($2::bigint[], $3::bigint[], $4::smallint[], $5::bytea[], $6::bytea[], $7::bytea[]) AS u(id, hash, ov, ve, ne, se)
				WHERE e.id = u.id AND e.value_hash = u.hash AND e.key_version = u.ov`,
				current, ids, hashes, oldVersions, valueEnc, noteEnc, sourceEnc)
			if err != nil {
				return res, err
			}

			done := tag.RowsAffected()
			res.Rewritten += done
			res.Skipped += int64(len(ids)) - done
		}

		res.Batches++

		if opts.Progress != nil {
			opts.Progress(res)
		}

		if n < batch {
			return res, nil
		}
	}
}

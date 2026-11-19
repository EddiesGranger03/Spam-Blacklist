package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"vsf/internal/model"
	"vsf/internal/seal"
)

// Xoay pepper. DATA_PEPPER tạo chỉ mục blind: value_blind = HMAC(pepper, type|match_type|value) và
// value_hash = 8 byte đầu của nó (khóa partition và khóa Bloom filter). Đổi pepper nghĩa là đổi cả hai cột của MỌI dòng,
// nên khác với xoay DATA_KEY, không thể làm dần: server đang chạy với một pepper sẽ không
// tìm thấy dòng được lưu dưới pepper kia (một số đang bị chặn sẽ bị báo là an toàn).
//
// Vì vậy RotatePepper là thao tác OFFLINE: mọi instance phải dừng khi nó chạy, rồi khởi động lại với
// DATA_PEPPER mới.
//
// Filter trong RAM KHÔNG tự dựng lại khi khởi động: pod nạp snapshot lưu trong filter_snapshots (G1). Snapshot dựng
// dưới pepper cũ vẫn đúng checksum nhưng chứa hash cũ, nạp vào thì mọi số BLACKLIST bị báo an toàn. Hai lớp chặn:
// (1) mỗi snapshot mang "hash domain" (seal.Sealer.FilterDomain, suy ra từ pepper, không lộ pepper) và Syncer chỉ
// cài snapshot cùng domain với pepper đang chạy; (2) lần chạy thật ở đây XÓA mọi snapshot khác domain của pepper mới
// ngay từ đầu, nên lần khởi động kế tiếp không có snapshot dùng được và leader quét bảng dựng bản mới. Trong khoảng đó được phép ngắt và chạy lại:
// một dòng chỉ được ghi lại nếu chỉ mục blind là của pepper CŨ, và bị bỏ qua khi đã là của pepper MỚI. Một
// dòng không khớp cả hai sẽ dừng việc chạy (sai pepper cũ, hoặc dữ liệu hỏng) trước khi chạm tới thứ gì khác.

// PepperRotateOptions tunes RotatePepper.
type PepperRotateOptions struct {
	// OldBlind tính chỉ mục blind dưới pepper CŨ (seal.Sealer.Blind của một sealer được dựng bằng pepper đó).
	// Sealer riêng của store cung cấp pepper MỚI.
	OldBlind func(typ, matchType, value string) []byte
	Batch    int  // rows per statement; 0 = 5000
	DryRun   bool // decrypt and check every row, write nothing
	Progress func(PepperRotateResult)
}

// PepperRotateResult totals what RotatePepper has done so far.
type PepperRotateResult struct {
	Scanned          int64
	Rewritten        int64 // rows moved to the new pepper (in a dry run: rows that would be)
	AlreadyNew       int64 // rows already under the new pepper (a re-run after an interruption)
	Skipped          int64 // rows an edit changed between the read and the write
	SnapshotsDropped int64 // filter snapshots of the old hash domain deleted (G1)
	Batches          int
}

// RotatePepper chuyển mọi dòng từ pepper cũ sang pepper hiện tại của store. Xem các quy tắc vận hành ở phần comment phía trên.
// Lần chạy thật ghi một dòng audit lúc bắt đầu và một dòng lúc kết thúc.
func (s *Store) RotatePepper(ctx context.Context, actor model.Actor, opts PepperRotateOptions) (res PepperRotateResult, err error) {
	if s.sealer == nil {
		return res, errNoSealer
	}

	if opts.OldBlind == nil {
		return res, errors.New("RotatePepper: OldBlind is required")
	}

	batch := opts.Batch
	if batch <= 0 {
		batch = 5000
	}

	if !opts.DryRun {
		if err := s.WriteAudit(ctx, actor, "entry.pepper_rotate.start", map[string]any{"at": time.Now().UTC()}); err != nil {
			return res, fmt.Errorf("audit start: %w", err)
		}

		// G1: snapshots of any other domain hold value_hash under the old pepper. Delete them before touching a row, so
		// that even an interrupted run never leaves a snapshot a restarted pod could install (the Syncer's domain
		// check would refuse it too; this also frees the space). Chunks go with them (ON DELETE CASCADE).
		tag, derr := s.write.Exec(ctx, `DELETE FROM filter_snapshots WHERE domain_id <> $1`, s.Snapshots().domainArg())
		if derr != nil {
			return res, fmt.Errorf("drop old filter snapshots: %w", derr)
		}

		res.SnapshotsDropped = tag.RowsAffected()

		defer func() {
			actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			defer cancel()

			detail := map[string]any{"status": "done", "scanned": res.Scanned, "rewritten": res.Rewritten,
				"already_new": res.AlreadyNew, "skipped": res.Skipped, "snapshots_dropped": res.SnapshotsDropped, "batches": res.Batches, "at": time.Now().UTC()}
			if err != nil {
				detail["status"], detail["error"] = "failed", truncate(err.Error(), 200)
			}

			if aerr := s.WriteAudit(actx, actor, "entry.pepper_rotate", detail); aerr != nil && err == nil {
				err = fmt.Errorf("pepper rotation finished but the closing audit row failed: %w", aerr)
			}
		}()
	}

	var after int64

	for {
		rows, qerr := s.write.Query(ctx, `SELECT id, type, match_type, value_hash, value_blind, value_enc, key_version
			FROM blacklist_entries WHERE id > $1 ORDER BY id LIMIT $2`, after, batch)
		if qerr != nil {
			return res, qerr
		}

		var (
			ids, oldHashes, newHashes []int64
			oldBlinds, newBlinds      [][]byte
			n                         int
		)

		for rows.Next() {
			var (
				id, hash   int64
				typ, mt    string
				blind, enc []byte
				version    int16
			)

			if err := rows.Scan(&id, &typ, &mt, &hash, &blind, &enc, &version); err != nil {
				rows.Close()
				return res, err
			}

			n++
			after = id
			res.Scanned++

			value, err := s.sealer.OpenVersion(version, enc, seal.AADValue)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d (key version %d): %w", id, version, err)
			}

			newBlind := s.sealer.Blind(typ, mt, value)

			switch {
			case bytes.Equal(blind, newBlind):
				res.AlreadyNew++

			case bytes.Equal(blind, opts.OldBlind(typ, mt, value)):
				if opts.DryRun {
					res.Rewritten++
					continue
				}

				ids, oldHashes, newHashes = append(ids, id), append(oldHashes, hash), append(newHashes, seal.Hash64(newBlind))
				oldBlinds, newBlinds = append(oldBlinds, blind), append(newBlinds, newBlind)

			default:
				rows.Close()

				return res, fmt.Errorf("entry %d: its blind index matches neither the old nor the new DATA_PEPPER; "+
					"check which pepper the data was written with (nothing further was changed)", id)
			}
		}

		rows.Close()

		if err := rows.Err(); err != nil {
			return res, err
		}

		if len(ids) > 0 {
			// Đổi value_hash sẽ chuyển dòng sang partition hash khác; PostgreSQL tự làm việc đó trong câu UPDATE.
			tag, err := s.write.Exec(ctx, `UPDATE blacklist_entries e SET value_hash = u.nh, value_blind = u.nb
				FROM unnest($1::bigint[], $2::bigint[], $3::bigint[], $4::bytea[], $5::bytea[]) AS u(id, oh, nh, ob, nb)
				WHERE e.id = u.id AND e.value_hash = u.oh AND e.value_blind = u.ob`,
				ids, oldHashes, newHashes, oldBlinds, newBlinds)
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

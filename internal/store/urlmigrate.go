package store

import (
	"context"
	"fmt"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

// urlPathMigrationVersion đánh dấu trong schema_migrations rằng các entry url đã được chuyển sang dạng path chuẩn
// do M9 đưa ra, và được mở rộng thêm: dấu gạch ngược, tham số path kiểu ";param" và cách viết IPv4 kiểu cũ.
// Tên đổi từ 005_url_path_canonical để DB đã chạy phiên bản đầu sẽ chạy lại một lần (idempotent).
const urlPathMigrationVersion = "007_url_canonical_v3"

const (
	urlMigrationScanPage   = 5000 // rows read per page while looking for entries that need to change
	urlMigrationApplyChunk = 2000 // changed rows written per transaction (short transactions, same lesson as C2)
	urlMigrationMaxMerges  = 100  // how many merged pairs the audit row lists
)

type urlMerge struct {
	Kept    int64 `json:"kept"`
	Removed int64 `json:"removed"`
}

type urlPathMigrationResult struct {
	Scanned int // url entries with match_type prefix/exact that were examined
	Changed int // entries whose stored key had to change (includes the ones that were merged)
	Merged  int // of those, entries that collided with an existing entry and were merged into it
	Skipped int // entries whose stored value no longer parses under today's rules; left untouched
	Merges  []urlMerge
}

type urlRowMove struct {
	id       int64
	mt       normalize.MatchType
	oldHash  int64
	newKey   normalize.Key
	newValue []byte // sealed canonical value
	// key_version xác định khóa của CẢ BA bản mã (C4), nên dòng được chuyển phải mã hóa lại toàn bộ bằng khóa hiện tại;
	// chỉ ghi value_enc rồi đóng dấu phiên bản mới sẽ làm note/source không đọc được khi khóa cũ bị gỡ bỏ.
	newNote, newSource []byte
}

// runURLPathMigration là điểm vào khi khởi động: chạy canonicalizeURLPaths đúng một lần, và ghi cả việc đã chạy
// lẫn một dòng audit kèm tổng số, trong cùng một transaction.
func (s *Store) runURLPathMigration(ctx context.Context) error {
	if s.sealer == nil {
		return nil // values cannot be read without the keys; it will run when they are configured
	}

	var done bool
	if err := s.write.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)`,
		urlPathMigrationVersion).Scan(&done); err != nil {
		return err
	}

	if done {
		return nil
	}

	start := time.Now()

	res, err := s.canonicalizeURLPaths(ctx, urlMigrationScanPage, urlMigrationApplyChunk)
	if err != nil {
		return fmt.Errorf("url path migration: %w", err)
	}

	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	if err := s.writeAudit(ctx, tx, model.Actor{Email: "migration"}, "migrate.url_path_canonical", 0, map[string]any{
		"scanned": res.Scanned, "changed": res.Changed, "merged": res.Merged, "skipped": res.Skipped,
		"merges": res.Merges, "at": time.Now().UTC()}); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING`,
		urlPathMigrationVersion); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	fmt.Printf("store: url path migration: scanned=%d changed=%d merged=%d skipped=%d in %s\n",
		res.Scanned, res.Changed, res.Merged, res.Skipped, time.Since(start).Round(time.Millisecond))

	return nil
}

// canonicalizeURLPaths chuyển các entry url (prefix và exact) lưu theo luật path cũ sang dạng chuẩn.
//
// Vì sao cần: entry như vậy mang value_hash và value_blind tính từ path cũ còn giữ hoa/thường.
// Khi ParseURL đã chuẩn hóa path, Candidates tính ra khóa khác, nên nếu không có bước này thì chính việc đổi luật
// làm mọi entry có chữ hoa ngừng khớp. Entry domain và phone không bị ảnh hưởng và không bị đọc.
//
// Với mỗi entry có giá trị chuẩn khác giá trị hiện tại: ghi hash mới, chỉ mục blind mới và bản mã mới (dòng tự chuyển
// partition), cùng một dòng change_log cho hash mới trong cùng transaction, vì các instance đang chạy chỉ biết hash
// qua change_log. Nếu đã có entry khác giữ khóa chuẩn (hai entry cũ chỉ khác hoa/thường), hai entry được gộp: entry có
// risk_score cao hơn được giữ (hòa thì giữ id nhỏ hơn), và expiry của nó là expiry bảo vệ nhiều nhất của cả hai
// (không hết hạn thắng mọi ngày; còn lại thì lấy ngày muộn hơn).
//
// Hàm idempotent và chạy tiếp được: entry đã chuẩn thì bỏ qua, và mỗi lần ghi kiểm tra lại dòng dưới khóa,
// nên sửa hoặc xóa của admin xảy ra song song với lần quét vẫn được tôn trọng.
func (s *Store) canonicalizeURLPaths(ctx context.Context, scanPage, applyChunk int) (urlPathMigrationResult, error) {
	var res urlPathMigrationResult

	if s.sealer == nil {
		return res, errNoSealer
	}

	var after int64

	for {
		rows, err := s.write.Query(ctx, `SELECT id, match_type, value_hash, value_enc, note_enc, source_enc, key_version FROM blacklist_entries
			WHERE type = 'url' AND match_type IN ('prefix', 'exact', 'domain') AND id > $1 ORDER BY id LIMIT $2`, after, scanPage)
		if err != nil {
			return res, err
		}

		var moves []urlRowMove

		n := 0

		for rows.Next() {
			var (
				id                     int64
				mt                     string
				hash                   int64
				version                int16
				valueEn, noteEn, srcEn []byte
			)

			if err := rows.Scan(&id, &mt, &hash, &valueEn, &noteEn, &srcEn, &version); err != nil {
				rows.Close()
				return res, err
			}

			n++
			after = id
			res.Scanned++

			value, err := s.sealer.OpenVersion(version, valueEn, seal.AADValue)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d: %w", id, err)
			}

			canonical, err := normalize.CanonicalURLValue(normalize.MatchType(mt), value)
			if err != nil {
				res.Skipped++ // no longer parses under today's rules: leave it exactly as it is
				continue
			}

			if canonical == value {
				continue
			}

			sealed, err := s.sealer.Seal(canonical, seal.AADValue)
			if err != nil {
				rows.Close()
				return res, err
			}

			note, err := s.sealer.OpenVersion(version, noteEn, seal.AADNote)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d: %w", id, err)
			}

			source, err := s.sealer.OpenVersion(version, srcEn, seal.AADSource)
			if err != nil {
				rows.Close()
				return res, fmt.Errorf("entry %d: %w", id, err)
			}

			noteSealed, sourceSealed, err := s.sealNoteSource(note, source)
			if err != nil {
				rows.Close()
				return res, err
			}

			moves = append(moves, urlRowMove{id: id, mt: normalize.MatchType(mt), oldHash: hash,
				newKey: normalize.MakeKey(normalize.TypeURL, normalize.MatchType(mt), canonical), newValue: sealed,
				newNote: noteSealed, newSource: sourceSealed})
		}

		rows.Close()

		if err := rows.Err(); err != nil {
			return res, err
		}

		for i := 0; i < len(moves); i += applyChunk {
			end := min(i+applyChunk, len(moves))
			if err := s.applyURLMoves(ctx, moves[i:end], &res); err != nil {
				return res, err
			}
		}

		if n < scanPage {
			return res, nil
		}
	}
}

// protectiveExpiry trả về expiry bảo vệ lâu nhất: không hết hạn nếu một trong hai entry không bao giờ hết hạn, còn lại lấy ngày muộn hơn.
func protectiveExpiry(a, b *time.Time) *time.Time {
	if a == nil || b == nil {
		return nil
	}

	if b.After(*a) {
		return b
	}

	return a
}

// applyURLMoves ghi một đoạn thay đổi khóa trong một transaction ngắn, bằng một số ít câu lệnh theo tập hợp
// (không phải vài câu cho mỗi dòng: đo được khoảng 770 entry/giây, quá chậm với một migration chặn khởi động).
//
// Các lần chuyển cùng kết thúc tại một khóa chuẩn được xử lý trong bộ nhớ cùng dòng (nếu có) đang giữ khóa đó:
// risk_score cao nhất được giữ (hòa thì id nhỏ nhất), và expiry là expiry bảo vệ nhiều nhất trong số đó
// (không hết hạn thắng mọi ngày; còn lại lấy ngày muộn nhất). Các dòng thua bị xóa trước khi dòng thắng được ghi lại,
// vì chỉ mục unique sẽ từ chối hai dòng trên một khóa. Quy tắc này là thứ tự toàn phần, nên tách một nhóm qua nhiều đoạn
// cho cùng kết quả như xử lý một lần.
func (s *Store) applyURLMoves(ctx context.Context, moves []urlRowMove, res *urlPathMigrationResult) error {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)

	// 1. Khóa các dòng đã được quét; dòng đã bị xóa hoặc đổi từ lúc quét sẽ được bỏ qua.
	ids, oldHashes := make([]int64, len(moves)), make([]int64, len(moves))
	for i, m := range moves {
		ids[i], oldHashes[i] = m.id, m.oldHash
	}

	type rowState struct {
		risk int16
		exp  *time.Time
	}

	current := make(map[int64]rowState, len(moves))

	rows, err := tx.Query(ctx, `SELECT e.id, e.risk_score, e.expires_at FROM blacklist_entries e
		JOIN unnest($1::bigint[], $2::bigint[]) AS u(id, hash) ON e.id = u.id AND e.value_hash = u.hash
		FOR UPDATE OF e`, ids, oldHashes)
	if err != nil {
		return err
	}

	for rows.Next() {
		var (
			id int64
			st rowState
		)

		if err := rows.Scan(&id, &st.risk, &st.exp); err != nil {
			rows.Close()
			return err
		}

		current[id] = st
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return err
	}

	// 2. Nhóm các lần chuyển còn lại theo khóa chuẩn mà chúng sẽ đi tới.
	type groupKey struct {
		hash int64
		mt   string
		bl   string
	}

	type cand struct {
		id    int64
		risk  int16
		exp   *time.Time
		hash  int64 // key the row has right now
		mover *urlRowMove
	}

	groups := map[groupKey][]cand{}

	var order []groupKey

	for i := range moves {
		m := &moves[i]

		st, ok := current[m.id]
		if !ok {
			continue
		}

		k := groupKey{m.newKey.Hash, string(m.mt), string(m.newKey.Blind)}
		if _, seen := groups[k]; !seen {
			order = append(order, k)
		}

		groups[k] = append(groups[k], cand{id: m.id, risk: st.risk, exp: st.exp, hash: m.oldHash, mover: m})
	}

	if len(order) == 0 {
		return tx.Commit(ctx)
	}

	// 3. Các dòng đã nằm sẵn trên những khóa chuẩn đó (nửa còn lại của một va chạm).
	hs, bs, mts := make([]int64, len(order)), make([][]byte, len(order)), make([]string, len(order))
	for i, k := range order {
		hs[i], bs[i], mts[i] = k.hash, []byte(k.bl), k.mt
	}

	rows, err = tx.Query(ctx, `SELECT id, value_hash, value_blind, match_type, risk_score, expires_at FROM blacklist_entries
		WHERE type = 'url' AND value_hash = ANY($1::bigint[]) AND value_blind = ANY($2::bytea[]) AND match_type = ANY($3::text[])
		FOR UPDATE`, hs, bs, mts)
	if err != nil {
		return err
	}

	for rows.Next() {
		var (
			c     cand
			blind []byte
			mt    string
		)

		if err := rows.Scan(&c.id, &c.hash, &blind, &mt, &c.risk, &c.exp); err != nil {
			rows.Close()
			return err
		}

		// Ba mảng được ghép theo từng cột, nên phải xác nhận cả bộ ba (hash, match_type, blind).
		k := groupKey{c.hash, mt, string(blind)}
		if _, ok := groups[k]; ok {
			groups[k] = append(groups[k], c) // mover == nil marks the row that was already there
		}
	}

	rows.Close()

	if err := rows.Err(); err != nil {
		return err
	}

	// 4. Decide who survives each group.
	var (
		delIDs, delHashes  []int64
		mvID, mvOld, mvNew []int64
		mvBlind, mvEnc     [][]byte
		mvNote, mvSource   [][]byte
		mvHas              []bool
		mvExp              []time.Time
		tgID, tgHash       []int64
		tgHas              []bool
		tgExp              []time.Time
		newHashes          []int64
		changed, merged    int
		merges             []urlMerge
	)

	for _, k := range order {
		cands := groups[k]
		win := 0
		exp := cands[0].exp

		for i, c := range cands {
			if c.risk > cands[win].risk || (c.risk == cands[win].risk && c.id < cands[win].id) {
				win = i
			}

			if i > 0 {
				exp = protectiveExpiry(exp, c.exp)
			}

			if c.mover != nil {
				changed++
			}
		}

		for i, c := range cands {
			if i == win {
				continue
			}

			delIDs, delHashes = append(delIDs, c.id), append(delHashes, c.hash)
			merges = append(merges, urlMerge{Kept: cands[win].id, Removed: c.id})
			merged++
		}

		w := cands[win]
		has, when := exp != nil, time.Time{}

		if exp != nil {
			when = *exp
		}

		if w.mover != nil {
			mvID, mvOld, mvNew = append(mvID, w.id), append(mvOld, w.mover.oldHash), append(mvNew, w.mover.newKey.Hash)
			mvBlind, mvEnc = append(mvBlind, w.mover.newKey.Blind), append(mvEnc, w.mover.newValue)
			mvNote, mvSource = append(mvNote, w.mover.newNote), append(mvSource, w.mover.newSource)
			mvHas, mvExp = append(mvHas, has), append(mvExp, when)
		} else {
			tgID, tgHash, tgHas, tgExp = append(tgID, w.id), append(tgHash, w.hash), append(tgHas, has), append(tgExp, when)
		}

		newHashes = append(newHashes, k.hash)
	}

	// 5. Áp dụng: xóa các dòng thua trước (chỉ mục unique cho phép một dòng mỗi khóa), rồi ghi dòng thắng, rồi ghi change_log.
	if len(delIDs) > 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM blacklist_entries e USING unnest($1::bigint[], $2::bigint[]) AS u(id, hash)
			WHERE e.id = u.id AND e.value_hash = u.hash`, delIDs, delHashes); err != nil {
			return err
		}
	}

	if len(mvID) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE blacklist_entries e SET value_hash = u.nh, value_blind = u.nb, value_enc = u.ne,
				note_enc = u.nn, source_enc = u.ns,
				key_version = $7, expires_at = CASE WHEN u.has THEN u.exp END, updated_at = now()
			FROM unnest($1::bigint[], $2::bigint[], $3::bigint[], $4::bytea[], $5::bytea[], $6::boolean[], $8::timestamptz[],
					$9::bytea[], $10::bytea[])
				AS u(id, oh, nh, nb, ne, has, exp, nn, ns)
			WHERE e.id = u.id AND e.value_hash = u.oh`,
			mvID, mvOld, mvNew, mvBlind, mvEnc, mvHas, s.sealer.Version(), mvExp, mvNote, mvSource); err != nil {
			return err
		}
	}

	if len(tgID) > 0 {
		if _, err := tx.Exec(ctx, `UPDATE blacklist_entries e SET expires_at = CASE WHEN u.has THEN u.exp END, updated_at = now()
			FROM unnest($1::bigint[], $2::bigint[], $3::boolean[], $4::timestamptz[]) AS u(id, hash, has, exp)
			WHERE e.id = u.id AND e.value_hash = u.hash`, tgID, tgHash, tgHas, tgExp); err != nil {
			return err
		}
	}

	// Changefeed (và qua nó là Bloom filter và epoch cache của mọi instance) chỉ biết các khóa chuẩn từ bước này trở đi.
	if _, err := tx.Exec(ctx, `INSERT INTO change_log(value_hash) SELECT unnest($1::bigint[])`, newHashes); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return err
	}

	res.Changed += changed
	res.Merged += merged

	for _, mg := range merges {
		if len(res.Merges) < urlMigrationMaxMerges {
			res.Merges = append(res.Merges, mg)
		}
	}

	return nil
}

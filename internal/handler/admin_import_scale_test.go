package handler

import (
	"bufio"
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vsf/internal/model"
)

// TestImportOneMillionRowsReportsExactCounts (checklist mục 9a): import file ~1,05 triệu dòng qua đúng đường của job
// (CSV iterator -> Store.ImportWith -> SyncNow) và kiểm tra ba con số báo cáo "mới / cập nhật / lỗi".
//
// Cấu trúc file: 50.000 khối, mỗi khối 21 dòng = 17 số mới + 3 dòng lặp lại số đã có TRONG CÙNG khối + 1 dòng sai.
// Mỗi khối có đúng 20 dòng hợp lệ và dòng sai không vào lô, nên 100.000 dòng hợp lệ của một lô trùng khít với ranh giới khối:
// dòng lặp luôn nằm cùng lô với bản gốc (khác lô thì Store cố ý đếm là Updated, xem ImportWith). Kỳ vọng:
//   - lần 1: Inserted = 850.000, Updated = 0, Rejected = 50.000, tổng dòng đọc = 1.050.000
//   - lần 2 (cùng file): Inserted = 0, Updated = 850.000, Rejected = 50.000
//
// Chậm (vài chục giây, lâu hơn khi bật -race) nên bỏ qua với -short.
func TestImportOneMillionRowsReportsExactCounts(t *testing.T) {
	skipUnlessScale(t)

	const (
		blocks      = 50_000
		uniquePer   = 17
		dupPer      = 3
		wantUnique  = blocks * uniquePer // 850.000
		wantReject  = blocks             // 50.000
		wantLines   = blocks * (uniquePer + dupPer + 1)
		phoneSpace  = 100_000_000 // "09" + 8 chữ số
		wantUniqueI = int64(wantUnique)
	)

	a := newApp(t)

	// Dải số ngẫu nhiên liên tục để tránh va chạm với dữ liệu các test khác trong cùng database.
	base := rand.IntN(phoneSpace - wantUnique - 1)
	actor := model.Actor{Email: fmt.Sprintf("import1m-%d@test.local", time.Now().UnixNano())}
	cleanupImported(t, a, actor.Email)
	phone := func(n int) string { return fmt.Sprintf("09%08d", n) }

	writeFile := func() string {
		path := filepath.Join(t.TempDir(), "million.csv")

		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}

		w := bufio.NewWriterSize(f, 1<<20)
		_, _ = w.WriteString("value,category,risk_score\n")

		for b := 0; b < blocks; b++ {
			first := base + b*uniquePer

			for i := 0; i < uniquePer; i++ {
				_, _ = fmt.Fprintf(w, "%s,scam,80\n", phone(first+i))
			}

			for i := 0; i < dupPer; i++ { // lặp lại số đã có trong cùng khối
				_, _ = fmt.Fprintf(w, "%s,scam,80\n", phone(first+i))
			}

			_, _ = fmt.Fprintf(w, "not-a-phone-%d,scam,80\n", b)
		}

		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}

		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		return path
	}

	run := func(label string) importView {
		t.Helper()

		job := &importJob{ID: "scale-" + label, Actor: actor, Started: time.Now(), State: "running"}
		start := time.Now()
		a.h.runImport(job, writeFile(), "phone") // runImport tự xóa file khi xong
		v := job.view()
		t.Logf("%s: state=%s rows=%d inserted=%d updated=%d rejected=%d (%s) err=%q",
			label, v.State, v.Rows, v.Inserted, v.Updated, v.Rejected, time.Since(start).Round(time.Second), v.Err)

		if v.State != "done" || v.Err != "" {
			t.Fatalf("%s: job không hoàn tất: state=%s err=%s", label, v.State, v.Err)
		}

		return v
	}

	// ---- lần 1: toàn bộ là số mới ----
	v := run("first")

	if v.Inserted != wantUniqueI || v.Updated != 0 {
		t.Errorf("lần 1: Inserted/Updated = %d/%d, muốn %d/0", v.Inserted, v.Updated, wantUniqueI)
	}

	if v.Rejected != wantReject {
		t.Errorf("lần 1: Rejected = %d, muốn %d", v.Rejected, wantReject)
	}

	if v.Rows != wantLines {
		t.Errorf("lần 1: số dòng đã đọc = %d, muốn %d", v.Rows, wantLines)
	}

	// Header là dòng 1; dòng sai đầu tiên là dòng dữ liệu thứ 21, tức dòng 22 của file. Chỉ giữ 20 lỗi đầu.
	if len(v.Errors) != 20 || !strings.HasPrefix(v.Errors[0], "dòng 22:") {
		t.Errorf("danh sách lỗi mẫu phải có đúng 20 dòng, dòng đầu là dòng 22 của file; được %d dòng, đầu=%q",
			len(v.Errors), firstOf(v.Errors))
	}

	// DB thật sự có đúng ngần ấy entry của lần import này, và audit ghi đúng tổng.
	ctx := context.Background()

	var n int64
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries WHERE created_by = $1`, actor.Email).Scan(&n); err != nil {
		t.Fatal(err)
	}

	if n != wantUniqueI {
		t.Errorf("DB có %d entry của lần import, muốn %d", n, wantUniqueI)
	}

	var detail string
	if err := a.pool.QueryRow(ctx, `SELECT detail::text FROM audit_logs WHERE action = 'entry.import' AND actor_email = $1
		ORDER BY id DESC LIMIT 1`, actor.Email).Scan(&detail); err != nil {
		t.Fatalf("audit entry.import: %v", err)
	}

	if !strings.Contains(detail, `"status": "done"`) || !strings.Contains(detail, fmt.Sprintf(`"inserted": %d`, wantUniqueI)) {
		t.Errorf("audit kết thúc sai: %s", detail)
	}

	// Mẫu vài số ở đầu, giữa, cuối đã vào Bloom và bị chặn (SyncNow chạy trước khi job báo xong).
	for _, off := range []int{0, 1, wantUnique / 2, wantUnique - 1} {
		a.waitBlacklisted("", "phone", phone(base+off), true)
	}

	// ---- lần 2: cùng file, toàn bộ là cập nhật ----
	v2 := run("second")

	if v2.Inserted != 0 || v2.Updated != wantUniqueI {
		t.Errorf("lần 2: Inserted/Updated = %d/%d, muốn 0/%d", v2.Inserted, v2.Updated, wantUniqueI)
	}

	if v2.Rejected != wantReject {
		t.Errorf("lần 2: Rejected = %d, muốn %d", v2.Rejected, wantReject)
	}

	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries WHERE created_by = $1`, actor.Email).Scan(&n); err != nil {
		t.Fatal(err)
	}

	if n != wantUniqueI {
		t.Errorf("sau lần 2 DB phải vẫn có %d entry (không nhân đôi), được %d", wantUniqueI, n)
	}
}

// skipUnlessScale bỏ qua test import quy mô lớn khi chạy -short hoặc với race detector.
// Với race, bài 1 triệu dòng mất ~410 giây (so với ~46 giây thường), nên không đưa vào lần chạy race.
func skipUnlessScale(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("import quy mô lớn: bỏ qua với -short")
	}

	if raceEnabled {
		t.Skip("import quy mô lớn: bỏ qua khi bật race detector (chậm gấp ~9 lần); chạy không có -race")
	}
}

// cleanupImported xóa các entry (và dòng change_log tương ứng) mà test này đã nạp, để lại database dùng chung như cũ.
// Nếu không dọn, hơn 1 triệu dòng còn lại làm các test khác chậm: bản export cả bảng của TestAppImportAndExport vượt
// timeout 20 giây của client test, và số điện thoại ngẫu nhiên của các test khác dễ trùng. Dòng audit được giữ lại
// (chuỗi hash audit không được xóa). Chỉ chạm tới dữ liệu có created_by là email riêng của test này.
func cleanupImported(t *testing.T, a *testApp, email string) {
	t.Helper()

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		if _, err := a.pool.Exec(ctx, `DELETE FROM change_log WHERE value_hash IN
			(SELECT value_hash FROM blacklist_entries WHERE created_by = $1)`, email); err != nil {
			t.Errorf("dọn change_log: %v", err)
		}

		if _, err := a.pool.Exec(ctx, `DELETE FROM blacklist_entries WHERE created_by = $1`, email); err != nil {
			t.Errorf("dọn blacklist_entries: %v", err)
		}
	})
}

func firstOf(s []string) string {
	if len(s) == 0 {
		return ""
	}

	return s[0]
}

// TestImportCrossBatchDuplicatesAtScale: số lặp lại GIỮA các lô (khác lô với bản gốc) được đếm là "mới" ở lần đầu rồi "cập nhật"
// ở lô sau, và dòng sau thắng qua các lô (ngữ nghĩa đã chốt trong Store.ImportWith). Chạy qua đúng đường của job với cỡ lô mặc định.
//
// Các lô cắt theo 100.000 dòng HỢP LỆ (dòng sai không vào lô). File có 250.000 dòng hợp lệ + 1.000 dòng sai:
//   - lô 1 (100.000 dòng): N0..N99.999, risk 50                                     -> mới 100.000
//   - lô 2 (100.000 dòng): 99.000 số mới + lặp N0..N999 (risk 99, khác lô 1)          -> mới 99.000, cập nhật 1.000
//   - lô 3 (50.000 dòng):  lặp N0..N499 (risk 77) + lặp N100.000..N100.499 (risk 77) + 49.000 số mới
//     (lặp lại bản gốc ở lô 1 và lô 2)                                              -> mới 49.000, cập nhật 1.000
//
// Tổng: mới 248.000, cập nhật 2.000, lỗi 1.000. Database có đúng 248.000 entry. Dòng sau thắng: risk 77 cho 1.000 entry,
// risk 99 cho 500 entry (N500..N999), risk 50 cho 246.500 entry còn lại.
// Chạy lại cùng file: mọi số đều đã có nên Updated = tổng số số khác nhau MỖI LÔ = 100.000 + 100.000 + 50.000 = 250.000,
// lớn hơn 248.000 entry thật vì một số xuất hiện ở nhiều lô và được đếm ở từng lô: đó là ngữ nghĩa đã chốt, test này khóa lại.
func TestImportCrossBatchDuplicatesAtScale(t *testing.T) {
	skipUnlessScale(t)

	const (
		batch1, batch2, batch3 = 100_000, 100_000, 50_000
		newInBatch2            = 99_000
		newInBatch3            = 49_000
		uniqueTotal            = batch1 + newInBatch2 + newInBatch3 // 248.000
		invalidEvery           = 250
		wantInvalid            = (batch1 + batch2 + batch3) / invalidEvery // 1.000
		phoneSpace             = 100_000_000
	)

	a := newApp(t)
	base := rand.IntN(phoneSpace - uniqueTotal - 1)
	actor := model.Actor{Email: fmt.Sprintf("crossbatch-%d@test.local", time.Now().UnixNano())}
	cleanupImported(t, a, actor.Email)
	phone := func(i int) string { return fmt.Sprintf("09%08d", base+i) }

	writeFile := func() string {
		path := filepath.Join(t.TempDir(), "crossbatch.csv")

		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}

		w := bufio.NewWriterSize(f, 1<<20)
		_, _ = w.WriteString("value,category,risk_score\n")

		valid := 0
		emit := func(idx, risk int) {
			_, _ = fmt.Fprintf(w, "%s,scam,%d\n", phone(idx), risk)
			valid++

			if valid%invalidEvery == 0 {
				_, _ = fmt.Fprintf(w, "not-a-phone-%d,scam,50\n", valid)
			}
		}

		for i := 0; i < batch1; i++ { // lô 1
			emit(i, 50)
		}

		for i := 0; i < 1000; i++ { // lô 2: lặp N0..N999 (đã có ở lô 1)
			emit(i, 99)
		}

		for i := 0; i < newInBatch2; i++ { // lô 2: số mới
			emit(batch1+i, 50)
		}

		for i := 0; i < 500; i++ { // lô 3: lặp N0..N499 (có ở lô 1 và 2)
			emit(i, 77)
		}

		for i := 0; i < 500; i++ { // lô 3: lặp N100.000..N100.499 (có ở lô 2)
			emit(batch1+i, 77)
		}

		for i := 0; i < newInBatch3; i++ { // lô 3: số mới
			emit(batch1+newInBatch2+i, 50)
		}

		if valid != batch1+batch2+batch3 {
			t.Fatalf("bộ sinh file sai: %d dòng hợp lệ", valid)
		}

		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}

		if err := f.Close(); err != nil {
			t.Fatal(err)
		}

		return path
	}

	run := func(label string) importView {
		t.Helper()

		job := &importJob{ID: "cross-" + label, Actor: actor, Started: time.Now(), State: "running"}
		a.h.runImport(job, writeFile(), "phone")
		v := job.view()
		t.Logf("%s: state=%s rows=%d inserted=%d updated=%d rejected=%d err=%q", label, v.State, v.Rows, v.Inserted, v.Updated, v.Rejected, v.Err)

		if v.State != "done" || v.Err != "" {
			t.Fatalf("%s: job không hoàn tất: state=%s err=%s", label, v.State, v.Err)
		}

		return v
	}

	v := run("first")

	if v.Inserted != uniqueTotal || v.Updated != 2000 {
		t.Errorf("lần 1: Inserted/Updated = %d/%d, muốn %d/2000", v.Inserted, v.Updated, uniqueTotal)
	}

	if v.Rejected != wantInvalid {
		t.Errorf("lần 1: Rejected = %d, muốn %d", v.Rejected, wantInvalid)
	}

	ctx := context.Background()

	var n int64
	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries WHERE created_by = $1`, actor.Email).Scan(&n); err != nil {
		t.Fatal(err)
	}

	if n != uniqueTotal {
		t.Errorf("DB có %d entry, muốn %d (số lặp qua các lô không được nhân đôi)", n, uniqueTotal)
	}

	// Dòng sau thắng qua các lô: đếm entry theo risk_score cuối cùng.
	got := map[int]int64{}

	rows, err := a.pool.Query(ctx, `SELECT risk_score, count(*) FROM blacklist_entries WHERE created_by = $1 GROUP BY risk_score`, actor.Email)
	if err != nil {
		t.Fatal(err)
	}

	for rows.Next() {
		var risk int
		var c int64

		if err := rows.Scan(&risk, &c); err != nil {
			t.Fatal(err)
		}

		got[risk] = c
	}

	rows.Close()

	if got[77] != 1000 || got[99] != 500 || got[50] != uniqueTotal-1500 || len(got) != 3 {
		t.Errorf("risk cuối cùng theo thứ tự file sai: %v, muốn 77:1000 99:500 50:%d", got, uniqueTotal-1500)
	}

	// ---- chạy lại cùng file ----
	v2 := run("second")

	if v2.Inserted != 0 || v2.Updated != batch1+batch2+batch3 {
		t.Errorf("lần 2: Inserted/Updated = %d/%d, muốn 0/%d (mỗi lô đếm số khác nhau của chính nó)",
			v2.Inserted, v2.Updated, batch1+batch2+batch3)
	}

	if v2.Rejected != wantInvalid {
		t.Errorf("lần 2: Rejected = %d, muốn %d", v2.Rejected, wantInvalid)
	}

	if err := a.pool.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries WHERE created_by = $1`, actor.Email).Scan(&n); err != nil {
		t.Fatal(err)
	}

	if n != uniqueTotal {
		t.Errorf("sau lần 2 DB vẫn phải có %d entry, được %d", uniqueTotal, n)
	}
}

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// importRows tạo các dòng nhập từ from đến to-1 với điểm rủi ro cho trước.
func importRows(t *testing.T, from, to, score int) []ImportRow {
	t.Helper()

	var out []ImportRow

	for i := from; i <= to; i++ {
		out = append(out, ImportRow{
			Key:   mustKey(t, normalize.TypePhone, "", fmt.Sprintf("0902%06d", i)),
			Input: model.EntryInput{Category: "scam", RiskScore: score},
		})
	}

	return out
}

// openTransactions đếm các client backend khác đang có transaction mở.
func openTransactions(t *testing.T, s *Store) int {
	t.Helper()

	var n int
	err := s.write.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
		WHERE datname = current_database() AND backend_type = 'client backend'
		  AND pid <> pg_backend_pid() AND xact_start IS NOT NULL`).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}

	return n
}

// visible kiểm tra một dòng nhập đã nhìn thấy được trong database (tra cứu theo giá trị) hay chưa.
func visible(t *testing.T, s *Store, r ImportRow) bool {
	t.Helper()

	got, err := s.FindMatches(context.Background(), []normalize.Key{r.Key})
	if err != nil {
		t.Fatal(err)
	}

	return len(got) > 0
}

// auditDetail giải mã JSON của một dòng audit (Postgres in jsonb có khoảng trắng, nên không so sánh chuỗi thô).
func auditDetail(t *testing.T, raw string) map[string]any {
	t.Helper()

	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("audit detail không phải JSON: %v (%s)", err, raw)
	}

	return m
}

// auditActions trả về các action và chi tiết của các dòng audit, theo thứ tự id.
func auditActions(t *testing.T, s *Store) (actions []string, details []string) {
	t.Helper()

	logs, _, err := s.ListAudit(context.Background(), 0, 200)
	if err != nil {
		t.Fatal(err)
	}

	for _, l := range logs {
		actions = append(actions, l.Action)
		details = append(details, l.Detail)
	}

	return actions, details
}

// C2: import phải commit theo các lô ngắn và không giữ transaction nào giữa chúng, và những gì một lô đã commit
// phải nhìn thấy được ngay (không chỉ khi cả file đã xong).
func TestImportCommitsInShortBatches(t *testing.T) {
	s := newTestStore(t)
	s.SetAuditKey(AuditKeyFrom("", "test-secret"))
	ctx := context.Background()
	rows := importRows(t, 1, 7, 70)
	calls := 0

	res, err := s.ImportWith(ctx, &sliceIter{rows: rows}, actor, ImportOptions{BatchRows: 3, Progress: func(r ImportResult) {
		calls++

		if n := openTransactions(t, s); n != 0 {
			t.Errorf("giữa hai batch không được còn transaction nào mở, thấy %d", n)
		}

		if !visible(t, s, rows[0]) {
			t.Error("dòng của batch đã commit phải nhìn thấy được ngay")
		}

		if calls == 1 && visible(t, s, rows[3]) {
			t.Error("dòng của batch 2 không được hiện ra trước khi batch 2 commit")
		}
	}})
	if err != nil {
		t.Fatal(err)
	}

	if res.Inserted != 7 || res.Updated != 0 || res.Rows != 7 || res.Batches != 3 || calls != 3 {
		t.Fatalf("res=%+v calls=%d, want inserted=7 updated=0 rows=7 batches=3 calls=3", res, calls)
	}

	ch, err := s.ChangesSince(ctx, "0", 0, 100)
	if err != nil || len(ch) != 7 {
		t.Fatalf("mỗi batch phải ghi change_log cùng transaction: got %d changes, err=%v", len(ch), err)
	}

	actions, details := auditActions(t, s)
	if len(actions) != 2 || actions[0] != "entry.import" || actions[1] != "entry.import.start" {
		t.Fatalf("audit phải có start và kết thúc, got %v", actions)
	}

	if d := auditDetail(t, details[0]); d["status"] != "done" || d["batches"] != float64(3) || d["rows"] != float64(7) {
		t.Fatalf("audit kết thúc thiếu trạng thái/tổng: %v", d)
	}

	if v, err := s.VerifyAuditChain(ctx); err != nil || !v.OK {
		t.Fatalf("chuỗi audit phải còn nguyên: %+v %v", v, err)
	}
}

// Lỗi giữa chừng: các batch đã commit được giữ lại, kết quả trả về nói đúng đã commit bao nhiêu, và audit ghi failed.
func TestImportMidwayFailureKeepsCommittedBatches(t *testing.T) {
	s := newTestStore(t)
	s.SetAuditKey(AuditKeyFrom("", "test-secret"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rows := importRows(t, 1, 7, 70)

	res, err := s.ImportWith(ctx, &sliceIter{rows: rows}, actor,
		ImportOptions{BatchRows: 3, Progress: func(ImportResult) { cancel() }}) // hủy ngay sau batch 1
	if err == nil {
		t.Fatal("batch 2 phải lỗi vì ctx đã bị hủy")
	}

	if res.Batches != 1 || res.Rows != 3 || res.Inserted != 3 {
		t.Fatalf("kết quả phải phản ánh đúng phần đã commit: %+v", res)
	}

	for i, want := range []bool{true, true, true, false, false, false, false} {
		if got := visible(t, s, rows[i]); got != want {
			t.Errorf("dòng %d: visible=%v, want %v", i, got, want)
		}
	}

	actions, details := auditActions(t, s)
	if len(actions) != 2 || actions[0] != "entry.import" {
		t.Fatalf("lỗi vẫn phải có audit kết thúc, got %v", actions)
	}

	if d := auditDetail(t, details[0]); d["status"] != "failed" || d["rows"] != float64(3) || d["error"] == nil {
		t.Fatalf("audit kết thúc phải ghi failed, số dòng đã commit và lý do: %v", d)
	}

	if v, err := s.VerifyAuditChain(context.Background()); err != nil || !v.OK {
		t.Fatalf("chuỗi audit phải còn nguyên: %+v %v", v, err)
	}
}

// Ngữ nghĩa đã chốt: trùng trong một batch thì gộp (dòng sau thắng); trùng giữa hai batch thì lần đầu là thêm mới,
// lần sau là cập nhật; chạy lại đúng file là an toàn.
func TestImportCrossBatchDuplicatesAndRerun(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a := importRows(t, 1, 1, 10)[0]
	b := importRows(t, 2, 2, 10)[0]
	a2 := a
	a2.Input = model.EntryInput{Category: "scam", RiskScore: 99}
	rows := []ImportRow{a, b, a2}

	res, err := s.ImportWith(ctx, &sliceIter{rows: rows}, actor, ImportOptions{BatchRows: 2})
	if err != nil {
		t.Fatal(err)
	}

	if res.Inserted != 2 || res.Updated != 1 {
		t.Fatalf("A,B ở batch 1 thêm mới, A ở batch 2 là cập nhật: %+v", res)
	}

	got, _ := s.FindMatches(ctx, []normalize.Key{a.Key})
	if len(got) != 1 || got[0].RiskScore != 99 {
		t.Fatalf("dòng sau phải thắng qua các batch: %+v", got)
	}

	res, err = s.ImportWith(ctx, &sliceIter{rows: rows}, actor, ImportOptions{BatchRows: 2})
	if err != nil || res.Inserted != 0 || res.Updated != 3 {
		t.Fatalf("chạy lại: muốn inserted=0 updated=3, got %+v err=%v", res, err)
	}

	got, _ = s.FindMatches(ctx, []normalize.Key{a.Key})
	if len(got) != 1 || got[0].RiskScore != 99 {
		t.Fatalf("chạy lại không được đổi kết quả cuối: %+v", got)
	}
}

type failingIter struct {
	rows      []ImportRow
	i         int
	failAfter int
	err       error
}

// Next trả về dòng tiếp theo của iterator giả, và báo lỗi ở vị trí đã cấu hình.
func (f *failingIter) Next() (ImportRow, bool) {
	if f.i >= f.failAfter || f.i >= len(f.rows) {
		return ImportRow{}, false
	}

	f.i++

	return f.rows[f.i-1], true
}

// Err trả về lỗi của iterator giả (nil nếu không có).
func (f *failingIter) Err() error {
	if f.i >= f.failAfter {
		return f.err
	}

	return nil
}

// Iterator báo lỗi: batch đang đọc dở bị bỏ, batch đã commit giữ nguyên, lỗi được trả về.
func TestImportIteratorErrorDiscardsPartialBatch(t *testing.T) {
	s := newTestStore(t)
	boom := errors.New("đọc file lỗi")
	rows := importRows(t, 1, 5, 70)

	res, err := s.ImportWith(context.Background(), &failingIter{rows: rows, failAfter: 5, err: boom}, actor,
		ImportOptions{BatchRows: 2})
	if !errors.Is(err, boom) {
		t.Fatalf("phải trả lỗi của iterator, got %v", err)
	}

	if res.Rows != 4 || res.Batches != 2 {
		t.Fatalf("2 batch đầy đủ đã commit, batch dở bị bỏ: %+v", res)
	}

	if !visible(t, s, rows[3]) || visible(t, s, rows[4]) {
		t.Fatal("dòng 4 phải có, dòng 5 (thuộc batch đọc dở) không được có")
	}
}

// TestImportEmptyInputStillAudited kiểm tra import file rỗng vẫn ghi đủ audit bắt đầu và kết thúc.
func TestImportEmptyInputStillAudited(t *testing.T) {
	s := newTestStore(t)

	res, err := s.ImportWith(context.Background(), &sliceIter{}, actor, ImportOptions{})
	if err != nil || res.Rows != 0 || res.Batches != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}

	if actions, _ := auditActions(t, s); len(actions) != 2 {
		t.Fatalf("import rỗng vẫn phải có audit start và kết thúc, got %v", actions)
	}
}

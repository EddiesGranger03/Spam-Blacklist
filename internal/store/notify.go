package store

import (
	"context"

	"github.com/jackc/pgx/v5"

	"vsf/internal/model"
)

// ChangeNotifier nhận các thay đổi change_log của một transaction SAU KHI transaction đó commit thành công
// (ví dụ: publish lên Redis Pub/Sub để pod khác áp ngay). Nó chỉ là tín hiệu tăng tốc: change_log vẫn là nguồn sự thật,
// nên NotifyChanges không được trả lỗi về request — lỗi chỉ được log/đếm metric ở phía cài đặt.
// changes == nil nghĩa là "chỉ đánh thức" (ví dụ import lớn: không gửi từng hash).
type ChangeNotifier interface {
	NotifyChanges(ctx context.Context, seqMax int64, changes []model.Change)
}

// SetChangeNotifier gắn notifier. Gọi một lần lúc khởi động, trước khi phục vụ request.
func (s *Store) SetChangeNotifier(n ChangeNotifier) { s.notifier = n }

// changeBatch gom các dòng change_log mà một transaction ghi, để publish sau commit.
type changeBatch struct {
	seqMax  int64
	changes []model.Change
}

// logChange ghi một dòng change_log (hash + op) trong transaction đã cho. op: model.OpAdd (hash phải có trong filter)
// hoặc model.OpRemove (hash không còn thuộc entry BLACKLIST nào). Mọi thay đổi entry đều phải gọi hàm này
// để epoch đổi và cache kết quả cũ bị vô hiệu. Dòng vừa ghi được gom vào b (nếu khác nil) để publish sau commit.
func logChange(ctx context.Context, tx pgx.Tx, hash int64, op int16, b *changeBatch) error {
	var seq int64
	if err := tx.QueryRow(ctx, `INSERT INTO change_log(value_hash, op) VALUES ($1, $2) RETURNING seq`, hash, op).Scan(&seq); err != nil {
		return err
	}

	if b != nil {
		b.seqMax = max(b.seqMax, seq)
		b.changes = append(b.changes, model.Change{Seq: seq, Hash: hash, Op: op})
	}

	return nil
}

// commitAndNotify commit tx rồi (chỉ khi commit thành công) báo các thay đổi đã gom cho notifier.
// Publish nằm SAU commit: pod nhận tín hiệu sẽ đọc change_log và phải thấy được các dòng này.
func (s *Store) commitAndNotify(ctx context.Context, tx pgx.Tx, b *changeBatch) error {
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	if len(b.changes) > 0 {
		s.notify(ctx, b.seqMax, b.changes)
	}

	return nil
}

// notify gọi notifier (nếu có). Context tách khỏi việc hủy của request: request đã thành công, tín hiệu vẫn nên đi.
func (s *Store) notify(ctx context.Context, seqMax int64, changes []model.Change) {
	if s.notifier == nil {
		return
	}

	s.notifier.NotifyChanges(context.WithoutCancel(ctx), seqMax, changes)
}

package store

import (
	"context"
	"strings"
	"time"

	"vsf/internal/model"
)

const adminCols = `id, email, password_hash, role, disabled, created_at`

// scanAdmin đọc một dòng admin từ kết quả truy vấn thành model.Admin.
func scanAdmin(row rowScanner) (model.Admin, error) {
	var a model.Admin
	var role string
	err := row.Scan(&a.ID, &a.Email, &a.PasswordHash, &role, &a.Disabled, &a.CreatedAt)
	a.Role = model.Role(role)
	return a, err
}

// CountAdmins đếm số tài khoản admin hiện có (dùng để nhận biết lần khởi động đầu).
func (s *Store) CountAdmins(ctx context.Context) (n int, err error) {
	err = s.write.QueryRow(ctx, `SELECT count(*) FROM admins`).Scan(&n)
	return
}

// CreateAdmin tạo tài khoản admin mới với email và hash mật khẩu đã cho, đồng thời ghi audit.
func (s *Store) CreateAdmin(ctx context.Context, email, passwordHash string, role model.Role, actor model.Actor) (model.Admin, error) {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return model.Admin{}, err
	}

	defer tx.Rollback(ctx)
	a, err := scanAdmin(tx.QueryRow(ctx, `INSERT INTO admins(email, password_hash, role)
		VALUES ($1,$2,$3) RETURNING `+adminCols, strings.ToLower(strings.TrimSpace(email)), passwordHash, string(role)))
	if err != nil {
		if isUniqueViolation(err) {
			return model.Admin{}, ErrDuplicate
		}

		return model.Admin{}, err
	}

	if err := s.writeAudit(ctx, tx, actor, "user.create", 0, map[string]any{"email": a.Email, "role": a.Role}); err != nil {
		return model.Admin{}, err
	}

	return a, tx.Commit(ctx)
}

// GetAdminByEmail tìm admin theo email; trả ErrNotFound nếu không có.
func (s *Store) GetAdminByEmail(ctx context.Context, email string) (model.Admin, error) {
	a, err := scanAdmin(s.write.QueryRow(ctx, `SELECT `+adminCols+` FROM admins WHERE email=$1`,
		strings.ToLower(strings.TrimSpace(email))))
	return a, mapNotFound(err)
}

// ListAdmins liệt kê toàn bộ tài khoản admin.
func (s *Store) ListAdmins(ctx context.Context) ([]model.Admin, error) {
	rows, err := s.write.Query(ctx, `SELECT `+adminCols+` FROM admins ORDER BY id`)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	var out []model.Admin

	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}

		out = append(out, a)
	}

	return out, rows.Err()
}

// UpdateAdmin cập nhật vai trò, trạng thái khóa hoặc mật khẩu của một admin, đồng thời ghi audit.
func (s *Store) UpdateAdmin(ctx context.Context, id int64, role model.Role, disabled bool, actor model.Actor) error {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)
	// Đọc giá trị cũ ngay trong câu UPDATE (khóa dòng) để biết có thật sự đổi gì không.
	var oldRole string

	var oldDisabled bool

	err = tx.QueryRow(ctx, `WITH old AS (SELECT role, disabled FROM admins WHERE id=$1 FOR UPDATE)
		UPDATE admins a SET role=$2, disabled=$3 FROM old WHERE a.id=$1 RETURNING old.role, old.disabled`,
		id, string(role), disabled).Scan(&oldRole, &oldDisabled)
	if err != nil {
		return mapNotFound(err)
	}

	// Đổi vai trò hoặc khóa tài khoản phải có hiệu lực ngay nên kết thúc mọi phiên. Lưu lại đúng giá trị cũ thì không
	// đổi gì, và không được đăng xuất người đó (nhất là khi admin bấm lưu chính mình).
	if oldRole != string(role) || oldDisabled != disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE admin_id=$1`, id); err != nil {
			return err
		}
	}

	if err := s.writeAudit(ctx, tx, actor, "user.update", 0, map[string]any{"admin_id": id, "role": role, "disabled": disabled}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// CreateSession lưu một phiên đăng nhập mới (chỉ lưu hash của token).
func (s *Store) CreateSession(ctx context.Context, idHash []byte, adminID int64, csrf, ip, ua string, expires time.Time) error {
	_, err := s.write.Exec(ctx, `INSERT INTO sessions(id_hash, admin_id, csrf_token, ip, user_agent, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`, idHash, adminID, csrf, ip, truncate(ua, 300), expires)
	return err
}

// GetSession tìm phiên đăng nhập còn hiệu lực theo hash của token.
func (s *Store) GetSession(ctx context.Context, idHash []byte) (model.Session, error) {
	var ss model.Session
	var role string
	err := s.write.QueryRow(ctx, `SELECT s.id_hash, s.admin_id, a.email, a.role, a.disabled, s.csrf_token,
			s.created_at, s.last_seen_at, s.expires_at
		FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.id_hash=$1`, idHash).
		Scan(&ss.IDHash, &ss.AdminID, &ss.Email, &role, &ss.Disabled, &ss.CSRFToken,
			&ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt)

	ss.Role = model.Role(role)
	return ss, mapNotFound(err)
}

// TouchSession cập nhật thời điểm hoạt động gần nhất của phiên (gia hạn idle timeout).
func (s *Store) TouchSession(ctx context.Context, idHash []byte) error {
	_, err := s.write.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE id_hash=$1`, idHash)
	return err
}

// DeleteSession xóa một phiên đăng nhập (đăng xuất).
func (s *Store) DeleteSession(ctx context.Context, idHash []byte) error {
	_, err := s.write.Exec(ctx, `DELETE FROM sessions WHERE id_hash=$1`, idHash)
	return err
}

// PurgeSessions xóa các phiên đã hết hạn khỏi bảng sessions.
func (s *Store) PurgeSessions(ctx context.Context, idle time.Duration) (int64, error) {
	tag, err := s.write.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now()
		OR last_seen_at < now() - make_interval(secs => $1::double precision)`, idle.Seconds())
	return tag.RowsAffected(), err
}

// ListAudit liệt kê nhật ký audit theo trang, mới nhất trước.
func (s *Store) ListAudit(ctx context.Context, before int64, limit int) ([]model.AuditLog, int64, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := s.write.Query(ctx, `SELECT id, actor_id, actor_email, action, entry_id, detail::text, ip, created_at
		FROM audit_logs WHERE ($1 = 0 OR id < $1) ORDER BY id DESC LIMIT $2`, before, limit+1)
	if err != nil {
		return nil, 0, err
	}

	defer rows.Close()
	var out []model.AuditLog

	for rows.Next() {
		var l model.AuditLog
		if err := rows.Scan(&l.ID, &l.ActorID, &l.ActorEmail, &l.Action, &l.EntryID, &l.Detail, &l.IP, &l.CreatedAt); err != nil {
			return nil, 0, err
		}

		out = append(out, l)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	var next int64

	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].ID
	}

	return out, next, nil
}

// WriteAudit ghi một dòng audit trong transaction riêng của nó.
func (s *Store) WriteAudit(ctx context.Context, a model.Actor, action string, detail any) error {
	tx, err := s.write.Begin(ctx)
	if err != nil {
		return err
	}

	defer tx.Rollback(ctx)
	if err := s.writeAudit(ctx, tx, a, action, 0, detail); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// truncate cắt chuỗi về tối đa n ký tự byte, dùng để giới hạn độ dài trước khi ghi log/audit.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}

	return s
}

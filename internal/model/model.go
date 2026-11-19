package model

import (
	"fmt"
	"slices"
	"time"

	"vsf/internal/normalize"
)

var Categories = []string{"spam", "scam", "phishing", "malware", "telemarketing", "other"}

// Entry status. A WHITELIST entry is an explicit exception that wins over BLACKLIST rules.
const (
	StatusBlacklist = "BLACKLIST"
	StatusWhitelist = "WHITELIST"
)

// ChangeOp: what the filter must do with a change_log hash.
const (
	OpAdd    int16 = 1 // hash may now be present: add it to the filter
	OpRemove int16 = 2 // hash no longer belongs to a BLACKLIST entry: remove it from the filter
)

type Entry struct {
	ID        int64      `json:"id"`
	Type      string     `json:"type"`
	MatchType string     `json:"match_type"`
	Value     string     `json:"value"`
	Status    string     `json:"status"`
	Category  string     `json:"category"`
	RiskScore int        `json:"risk_score"`
	Source    string     `json:"source"`
	Note      string     `json:"note"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

type EntryInput struct {
	// Status: "" means BLACKLIST on create and "keep the current status" on update.
	Status    string
	Category  string
	RiskScore int
	Source    string
	Note      string
	ExpiresAt *time.Time
}

// Validate kiểm tra dữ liệu nhập của một entry (loại, kiểu khớp, rủi ro, danh mục, ...).
func (in *EntryInput) Validate() error {
	if in.Status != "" && in.Status != StatusBlacklist && in.Status != StatusWhitelist {
		return fmt.Errorf("%w: status must be BLACKLIST or WHITELIST", normalize.ErrInvalid)
	}

	if in.Category == "" {
		in.Category = "spam"
	}

	if !slices.Contains(Categories, in.Category) {
		return fmt.Errorf("%w: unknown category %q", normalize.ErrInvalid, in.Category)
	}

	if in.RiskScore < 0 || in.RiskScore > 100 {
		return fmt.Errorf("%w: risk_score must be between 0 and 100", normalize.ErrInvalid)
	}

	if len(in.Source) > 200 {
		return fmt.Errorf("%w: source is too long (max 200)", normalize.ErrInvalid)
	}

	if len(in.Note) > 2000 {
		return fmt.Errorf("%w: note is too long (max 2000)", normalize.ErrInvalid)
	}

	return nil
}

type Role string

const (
	RoleViewer Role = "viewer"
	RoleEditor Role = "editor"
	RoleAdmin  Role = "admin"
)

// Level trả về mức quyền dạng số của vai trò (0 là không hợp lệ).
func (r Role) Level() int {
	switch r {
	case RoleViewer:
		return 1

	case RoleEditor:
		return 2

	case RoleAdmin:
		return 3
	}

	return 0
}

// AtLeast cho biết vai trò có ít nhất quyền của min hay không.
func (r Role) AtLeast(min Role) bool { return r.Level() >= min.Level() && r.Level() > 0 }

// ValidRole cho biết vai trò có hợp lệ (có mức quyền lớn hơn 0) hay không.
func ValidRole(r Role) bool { return r.Level() > 0 }

type Actor struct {
	ID    int64
	Email string
	IP    string
}

type Admin struct {
	ID           int64     `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	Disabled     bool      `json:"disabled"`
	CreatedAt    time.Time `json:"created_at"`
}

type Session struct {
	IDHash     []byte
	AdminID    int64
	Email      string
	Role       Role
	Disabled   bool
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

type APIKey struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Prefix      string     `json:"prefix"`
	KeyHash     []byte     `json:"-"`
	Status      string     `json:"status"`
	RPSLimit    int        `json:"rps_limit"`
	MaxBatch    int        `json:"max_batch"` // 0 = burst bằng rps_limit; >0 = cho phép 1 lần gọi tới ngần ấy mục
	DailyQuota  int64      `json:"daily_quota"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RotatedFrom *int64     `json:"rotated_from,omitempty"`
	CreatedBy   string     `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
}

type AuditLog struct {
	ID         int64     `json:"id"`
	ActorID    *int64    `json:"actor_id,omitempty"`
	ActorEmail string    `json:"actor_email"`
	Action     string    `json:"action"`
	EntryID    *int64    `json:"entry_id,omitempty"`
	Detail     string    `json:"detail"`
	IP         string    `json:"ip"`
	CreatedAt  time.Time `json:"created_at"`
}

type Change struct {
	Seq  int64
	XID  string
	Hash int64
	// Op: OpAdd (1) adds the hash, OpRemove (2) removes it (change_log.op). 0 = legacy row without op, treated as add.
	Op int16

	// Pending: dòng đã commit và nhìn thấy được, nhưng xid của nó chưa nhỏ hơn xmin của database
	// (có transaction cũ hơn vẫn đang mở), nên changefeed không được đẩy con trỏ qua nó:
	// một transaction commit sau có thể vẫn tạo ra dòng đứng trước dòng này. Hash vẫn an toàn để thêm vào Bloom filter ngay.
	// Giá trị zero (false) nghĩa là "an toàn".
	Pending bool
}

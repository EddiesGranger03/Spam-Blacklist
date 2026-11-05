package model

import (
	"fmt"
	"slices"
	"time"

	"vsf/internal/normalize"
)

var Categories = []string{"spam", "scam", "phishing", "malware", "telemarketing", "other"}

type Entry struct {
	ID        int64      `json:"id"`
	Type      string     `json:"type"`
	MatchType string     `json:"match_type"`
	Value     string     `json:"value"`
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
	Category  string
	RiskScore int
	Source    string
	Note      string
	ExpiresAt *time.Time
}

func (in *EntryInput) Validate() error {
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

func (r Role) AtLeast(min Role) bool { return r.Level() >= min.Level() && r.Level() > 0 }

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
}

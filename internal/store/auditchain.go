package store

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"vsf/internal/model"
)

// auditLockID serialises audit writes so the chain has a single, gap-free order.
const auditLockID = 727275

// AuditKeyFrom returns the HMAC key for the audit chain: the dedicated key if
// configured, otherwise one derived from the session secret.
func AuditKeyFrom(auditKey, sessionSecret string) []byte {
	if auditKey != "" {
		return []byte(auditKey)
	}

	sum := sha256.Sum256([]byte("vsf-audit-chain-v1|" + sessionSecret))
	return sum[:]
}

// SetAuditKey enables hash chaining for audit rows written from now on.
func (s *Store) SetAuditKey(key []byte) { s.auditKey = key }

type auditFields struct {
	ID         int64
	ActorID    *int64
	ActorEmail string
	Action     string
	EntryID    *int64
	Detail     string // jsonb rendered as text, exactly as stored
	IP         string
	CreatedAt  time.Time
}

func optInt(v *int64) []byte {
	if v == nil {
		return []byte("-")
	}

	return []byte(strconv.FormatInt(*v, 10))
}

// auditHash is HMAC-SHA256 over prev and every field. Each part is length
// prefixed so field boundaries cannot be shifted to forge a collision.
func auditHash(key, prev []byte, f auditFields) []byte {
	m := hmac.New(sha256.New, key)

	part := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		m.Write(n[:])
		m.Write(b)
	}

	part(prev)
	part([]byte(strconv.FormatInt(f.ID, 10)))
	part(optInt(f.ActorID))
	part([]byte(f.ActorEmail))
	part([]byte(f.Action))
	part(optInt(f.EntryID))
	part([]byte(f.Detail))
	part([]byte(f.IP))
	part([]byte(strconv.FormatInt(f.CreatedAt.UnixMicro(), 10)))

	return m.Sum(nil)
}

func (s *Store) writeAudit(ctx context.Context, tx pgx.Tx, a model.Actor, action string, entryID int64, detail any) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}

	var eid, aid any

	if entryID != 0 {
		eid = entryID
	}

	if a.ID != 0 {
		aid = a.ID
	}

	if len(s.auditKey) == 0 {
		_, err = tx.Exec(ctx, `INSERT INTO audit_logs(actor_id, actor_email, action, entry_id, detail, ip)
			VALUES ($1,$2,$3,$4,$5,$6)`, aid, a.Email, action, eid, raw, a.IP)
		return err
	}

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, auditLockID); err != nil {
		return err
	}

	var prev []byte

	err = tx.QueryRow(ctx, `SELECT entry_hash FROM audit_logs WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`).Scan(&prev)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	var f auditFields

	err = tx.QueryRow(ctx, `INSERT INTO audit_logs(actor_id, actor_email, action, entry_id, detail, ip)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, actor_id, actor_email, action, entry_id, detail::text, ip, created_at`,
		aid, a.Email, action, eid, raw, a.IP).
		Scan(&f.ID, &f.ActorID, &f.ActorEmail, &f.Action, &f.EntryID, &f.Detail, &f.IP, &f.CreatedAt)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `UPDATE audit_logs SET prev_hash=$2, entry_hash=$3 WHERE id=$1`,
		f.ID, prev, auditHash(s.auditKey, prev, f))

	return err
}

// AuditVerifyResult is the outcome of walking the whole chain.
type AuditVerifyResult struct {
	OK       bool   `json:"ok"`
	Checked  int64  `json:"checked"`   // rows whose hash verified
	Legacy   int64  `json:"legacy"`    // rows written before chaining was enabled
	BrokenID int64  `json:"broken_id"` // first bad row, 0 when OK
	Reason   string `json:"reason,omitempty"`
}

// VerifyAuditChain recomputes every hash in id order. It detects edited rows,
// deleted or inserted rows in the middle of the chain, and stripped hashes.
// Truncation at the very end of the table cannot be detected by a chain alone.
func (s *Store) VerifyAuditChain(ctx context.Context) (AuditVerifyResult, error) {
	if len(s.auditKey) == 0 {
		return AuditVerifyResult{}, errors.New("audit key is not configured")
	}

	rows, err := s.write.Query(ctx, `SELECT id, actor_id, actor_email, action, entry_id, detail::text, ip, created_at,
		prev_hash, entry_hash FROM audit_logs ORDER BY id`)
	if err != nil {
		return AuditVerifyResult{}, err
	}

	defer rows.Close()

	res := AuditVerifyResult{OK: true}

	var (
		expectedPrev []byte
		started      bool
	)

	fail := func(id int64, reason string) (AuditVerifyResult, error) {
		res.OK, res.BrokenID, res.Reason = false, id, reason
		return res, nil
	}

	for rows.Next() {
		var f auditFields

		var prev, hash []byte

		if err := rows.Scan(&f.ID, &f.ActorID, &f.ActorEmail, &f.Action, &f.EntryID, &f.Detail, &f.IP, &f.CreatedAt,
			&prev, &hash); err != nil {
			return AuditVerifyResult{}, err
		}

		if hash == nil {
			if started {
				return fail(f.ID, "bản ghi thiếu hash giữa chuỗi")
			}

			res.Legacy++

			continue
		}

		started = true

		if !bytes.Equal(prev, expectedPrev) {
			return fail(f.ID, "chuỗi bị đứt: có bản ghi bị xóa hoặc chèn trước bản ghi này")
		}

		if !hmac.Equal(hash, auditHash(s.auditKey, expectedPrev, f)) {
			return fail(f.ID, "nội dung bản ghi đã bị sửa")
		}

		expectedPrev = hash
		res.Checked++
	}

	return res, rows.Err()
}

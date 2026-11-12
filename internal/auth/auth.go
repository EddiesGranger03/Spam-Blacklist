package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 2
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	saltLen      = 16
)

const MinPasswordLen = 10

// HashPassword băm mật khẩu bằng argon2id với salt ngẫu nhiên, trả về chuỗi chứa tham số để xác minh sau này.
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword kiểm tra mật khẩu với chuỗi hash đã lưu, so sánh theo thời gian hằng số.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}

	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}

	// Khóa argon2 chuẩn chỉ 32 byte. Chặn chuỗi hash bất thường trước khi tính argon2 với độ dài tùy ý.
	if len(want) == 0 || len(want) > 64 {
		return false
	}

	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))  // #nosec G115 -- len(want) đã được giới hạn 1..64 ở trên
	return subtle.ConstantTimeCompare(got, want) == 1
}

var dummyHash, _ = HashPassword("dummy-password-for-timing")

// BurnTime tốn thời gian bằng một lần xác minh mật khẩu, để khi email không tồn tại thì phản hồi vẫn chậm như khi có tồn tại.
func BurnTime(password string) { VerifyPassword(password, dummyHash) }

// NewToken tạo token ngẫu nhiên 32 byte và hash của nó (chỉ lưu hash).
func NewToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", nil, err
	}

	token = base64.RawURLEncoding.EncodeToString(b)
	return token, HashToken(token), nil
}

// HashToken băm token bằng SHA-256 để lưu vào database.
func HashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

var ErrThrottled = errors.New("too many attempts")

type Throttle struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

// NewThrottle tạo bộ đếm giới hạn số lần thất bại trong một cửa sổ thời gian.
func NewThrottle(max int, window time.Duration) *Throttle {
	return &Throttle{max: max, window: window, fails: map[string][]time.Time{}}
}

// prune bỏ các thời điểm thất bại đã quá cửa sổ và trả về danh sách còn lại của khóa.
func (t *Throttle) prune(key string, now time.Time) []time.Time {
	list := t.fails[key]
	i := 0
	for i < len(list) && now.Sub(list[i]) > t.window {
		i++
	}

	list = list[i:]
	if len(list) == 0 {
		delete(t.fails, key)
	} else {
		t.fails[key] = list
	}

	return list
}

// Allowed cho biết khóa còn được phép thử đăng nhập hay đã vượt giới hạn.
func (t *Throttle) Allowed(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.prune(key, time.Now())) < t.max
}

// Fail ghi nhận một lần thất bại cho khóa.
func (t *Throttle) Fail(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.prune(key, now)
	t.fails[key] = append(t.fails[key], now)

	if len(t.fails) > 100_000 {
		for k := range t.fails {
			t.prune(k, now)
		}
	}
}

// Count trả số lần thất bại còn nằm trong cửa sổ của key.
func (t *Throttle) Count(key string) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return len(t.prune(key, time.Now()))
}

// Reset xóa bộ đếm của khóa (khi đăng nhập thành công).
func (t *Throttle) Reset(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, key)
}

// SignDevice tạo token "thiết bị tin cậy" gắn với một email: "<unix>.<hmac>". Cấp sau lần đăng nhập thành công; lần
// sau thiết bị này không bị giới hạn rộng theo email (kẻ tấn công dò mật khẩu từ nhiều IP không khóa được người dùng
// thật). Token không thay thế mật khẩu: nó chỉ miễn giới hạn đó, mật khẩu vẫn phải đúng.
func SignDevice(secret, email string, now time.Time) string {
	ts := strconv.FormatInt(now.Unix(), 10)
	return ts + "." + deviceMAC(secret, email, ts)
}

// VerifyDevice kiểm tra token của SignDevice: đúng email, đúng chữ ký, chưa quá maxAge và không ở tương lai.
func VerifyDevice(secret, email, token string, now time.Time, maxAge time.Duration) bool {
	ts, mac, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}

	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}

	age := now.Sub(time.Unix(sec, 0))
	if age < -time.Minute || age > maxAge {
		return false
	}

	return hmac.Equal([]byte(mac), []byte(deviceMAC(secret, email, ts)))
}

// deviceMAC tính HMAC của email và dấu thời gian bằng secret, dùng cho token thiết bị tin cậy.
func deviceMAC(secret, email, ts string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("vsf-device|" + email + "|" + ts))

	return hex.EncodeToString(m.Sum(nil))
}

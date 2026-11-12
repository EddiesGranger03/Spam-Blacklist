package auth

import (
	"bytes"
	"testing"
	"time"
)

// TestPasswordHashVerify kiểm tra băm và xác minh mật khẩu đúng và sai.
func TestPasswordHashVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyPassword("correct horse battery", h) {
		t.Fatal("correct password must verify")
	}

	if VerifyPassword("wrong", h) {
		t.Fatal("wrong password must not verify")
	}

	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt must make hashes differ")
	}

	for _, bad := range []string{"", "plain", "$argon2id$v=19$m=1$x$y", "$bcrypt$a$b$c$d"} {
		if VerifyPassword("x", bad) {
			t.Fatalf("malformed hash %q must not verify", bad)
		}
	}
}

// TestTokens kiểm tra token ngẫu nhiên khác nhau và hash ổn định.
func TestTokens(t *testing.T) {
	tok, hash, err := NewToken()
	if err != nil || len(tok) < 40 {
		t.Fatalf("token=%q err=%v", tok, err)
	}

	if !bytes.Equal(hash, HashToken(tok)) {
		t.Fatal("hash must match HashToken(token)")
	}

	tok2, _, _ := NewToken()
	if tok == tok2 {
		t.Fatal("tokens must be random")
	}
}

// TestThrottle kiểm tra giới hạn số lần thất bại và reset.
func TestThrottle(t *testing.T) {
	th := NewThrottle(3, 50*time.Millisecond)

	for i := 0; i < 3; i++ {
		if !th.Allowed("ip") {
			t.Fatal("should be allowed before limit")
		}

		th.Fail("ip")
	}

	if th.Allowed("ip") {
		t.Fatal("must be throttled after 3 failures")
	}

	if !th.Allowed("other") {
		t.Fatal("other keys unaffected")
	}

	time.Sleep(70 * time.Millisecond)

	if !th.Allowed("ip") {
		t.Fatal("window expired, should be allowed again")
	}

	th.Fail("ip")
	th.Reset("ip")

	if !th.Allowed("ip") {
		t.Fatal("reset must clear failures")
	}
}

// TestDeviceToken kiểm tra token thiết bị tin cậy gắn đúng email và thời điểm.
func TestDeviceToken(t *testing.T) {
	now := time.Now()
	tok := SignDevice("secret-1", "a@b.c", now)

	if !VerifyDevice("secret-1", "a@b.c", tok, now.Add(time.Hour), 24*time.Hour) {
		t.Fatal("valid token rejected")
	}

	for name, c := range map[string]struct {
		secret, email, token string
		at                   time.Time
	}{
		"other email":  {"secret-1", "x@y.z", tok, now},
		"other secret": {"secret-2", "a@b.c", tok, now},
		"expired":      {"secret-1", "a@b.c", tok, now.Add(48 * time.Hour)},
		"future":       {"secret-1", "a@b.c", SignDevice("secret-1", "a@b.c", now.Add(time.Hour)), now},
		"tampered":     {"secret-1", "a@b.c", tok[:len(tok)-1] + flip(tok[len(tok)-1]), now},
		"garbage":      {"secret-1", "a@b.c", "nope", now},
		"empty":        {"secret-1", "a@b.c", "", now},
	} {
		if VerifyDevice(c.secret, c.email, c.token, c.at, 24*time.Hour) {
			t.Errorf("%s: token accepted", name)
		}
	}
}

// TestThrottleCount kiểm tra số lần đếm đúng trong cửa sổ thời gian.
func TestThrottleCount(t *testing.T) {
	th := NewThrottle(3, time.Minute)
	th.Fail("k")
	th.Fail("k")

	if th.Count("k") != 2 || th.Count("other") != 0 {
		t.Fatalf("count = %d / %d", th.Count("k"), th.Count("other"))
	}
}

// flip đổi một ký tự của chuỗi (dùng để kiểm tra token bị sửa thì không hợp lệ).
func flip(c byte) string {
	if c == '0' {
		return "1"
	}

	return "0"
}

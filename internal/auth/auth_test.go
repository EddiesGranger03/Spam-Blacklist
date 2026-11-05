package auth

import (
	"bytes"
	"testing"
	"time"
)

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

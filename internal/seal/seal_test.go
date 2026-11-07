package seal

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testKey    = "0123456789abcdef0123456789abcdef-data"
	testPepper = "fedcba9876543210fedcba9876543210-pepper"
)

func newTest(t *testing.T) *Sealer {
	t.Helper()

	s, err := New(testKey, testPepper, 1)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := newTest(t)

	blob, err := s.Seal("+84901234567", AADValue)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Contains(blob, []byte("84901234567")) {
		t.Fatal("ciphertext contains plaintext")
	}

	got, err := s.Open(blob, AADValue)
	if err != nil || got != "+84901234567" {
		t.Fatalf("round trip failed: %q %v", got, err)
	}

	blob2, _ := s.Seal("+84901234567", AADValue)
	if bytes.Equal(blob, blob2) {
		t.Error("nonce reuse: identical ciphertexts for the same plaintext")
	}
}

func TestOpenRejectsTamperingAndWrongColumn(t *testing.T) {
	s := newTest(t)
	blob, _ := s.Seal("secret note", AADNote)

	if _, err := s.Open(blob, AADValue); err == nil {
		t.Error("ciphertext moved to another column must not decrypt")
	}

	blob[len(blob)-1] ^= 1
	if _, err := s.Open(blob, AADNote); err == nil {
		t.Error("tampered ciphertext must not decrypt")
	}

	if _, err := s.Open([]byte("short"), AADNote); err == nil {
		t.Error("short input must fail")
	}

	other, _ := New("another-data-key-another-data-key-0000", testPepper, 1)
	good, _ := s.Seal("x", AADNote)

	if _, err := other.Open(good, AADNote); err == nil {
		t.Error("different key must not decrypt")
	}
}

func TestBlind(t *testing.T) {
	s := newTest(t)
	a := s.Blind("phone", "exact", "+84901234567")

	if !bytes.Equal(a, s.Blind("phone", "exact", "+84901234567")) {
		t.Fatal("blind index must be deterministic")
	}

	for _, other := range [][3]string{
		{"phone", "exact", "+84901234568"},
		{"url", "exact", "+84901234567"},
		{"phone", "prefix", "+84901234567"},
	} {
		if bytes.Equal(a, s.Blind(other[0], other[1], other[2])) {
			t.Errorf("collision for %v", other)
		}
	}

	if bytes.Equal(a, s.Blind("phoneexact", "", "+84901234567")) {
		t.Error("field boundary shift must not collide")
	}

	p2, _ := New(testKey, "different-pepper-different-pepper-00", 1)
	if bytes.Equal(a, p2.Blind("phone", "exact", "+84901234567")) {
		t.Error("different pepper must change the index")
	}

	if Hash64(a) == Hash64(s.Blind("phone", "exact", "+84901234568")) {
		t.Error("Hash64 collision on neighbouring numbers")
	}
}

func TestNewValidatesSecrets(t *testing.T) {
	if _, err := New("short", testPepper, 1); err == nil {
		t.Error("short key accepted")
	}

	if _, err := New(testKey, "short", 1); err == nil {
		t.Error("short pepper accepted")
	}

	same := strings.Repeat("x", 40)
	if _, err := New(same, same, 1); err == nil {
		t.Error("identical key and pepper accepted")
	}
}

func TestMask(t *testing.T) {
	cases := map[string]string{
		"+84901234567":           "+84***67",
		"https://evil.example/x": "htt***/x",
		"abc":                    "a***",
		"":                       "",
	}
	for in, want := range cases {
		if got := Mask(in); got != want {
			t.Errorf("Mask(%q) = %q, want %q", in, got, want)
		}
	}
}

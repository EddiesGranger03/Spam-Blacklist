package seal

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const (
	testKey    = "0123456789abcdef0123456789abcdef-data"
	testPepper = "fedcba9876543210fedcba9876543210-pepper"
)

// newTest tạo Sealer với khóa test.
func newTest(t *testing.T) *Sealer {
	t.Helper()

	s, err := New(testKey, testPepper, 1)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

// TestSealOpenRoundTrip kiểm tra mã hóa rồi giải mã trả lại đúng bản rõ.
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

// TestOpenRejectsTamperingAndWrongColumn kiểm tra giải mã từ chối bản mã bị sửa hoặc sai cột (AAD).
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

// TestBlind kiểm tra chỉ mục blind ổn định và phụ thuộc vào pepper.
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

// TestNewValidatesSecrets kiểm tra New từ chối secret quá ngắn hoặc trùng nhau.
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

// TestMask kiểm tra hàm che giá trị nhạy cảm.
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

// --- C4: nhiều khóa theo phiên bản (xoay DATA_KEY) ---

const (
	oldKey  = "old-data-key-old-data-key-old-data-key-0001"
	oldKey2 = "older-data-key-older-data-key-older-key-0002"
)

// newRotated tạo Sealer với khóa hiện tại và các khóa cũ, dùng cho test xoay khóa.
func newRotated(t *testing.T, current string, version int16, retired map[int16]string) *Sealer {
	t.Helper()

	s, err := New(current, testPepper, version, WithRetiredKeys(retired))
	if err != nil {
		t.Fatal(err)
	}

	return s
}

// Dữ liệu mã hóa bằng khóa cũ phải đọc được khi chọn đúng phiên bản, và KHÔNG đọc được khi chọn nhầm phiên bản.
func TestOpenVersionSelectsTheRightKey(t *testing.T) {
	old, err := New(oldKey, testPepper, 1)
	if err != nil {
		t.Fatal(err)
	}

	blobOld, _ := old.Seal("+84901234567", AADValue)

	s := newRotated(t, testKey, 2, map[int16]string{1: oldKey})
	blobNew, _ := s.Seal("+84907654321", AADValue)

	if got, err := s.OpenVersion(1, blobOld, AADValue); err != nil || got != "+84901234567" {
		t.Fatalf("OpenVersion(1) phải đọc được bản mã khóa cũ: %q %v", got, err)
	}

	if got, err := s.OpenVersion(2, blobNew, AADValue); err != nil || got != "+84907654321" {
		t.Fatalf("OpenVersion(2) phải đọc được bản mã khóa hiện tại: %q %v", got, err)
	}

	if _, err := s.OpenVersion(2, blobOld, AADValue); err == nil {
		t.Error("chọn nhầm phiên bản (khóa mới cho bản mã khóa cũ) không được giải mã")
	}

	if _, err := s.OpenVersion(1, blobNew, AADValue); err == nil {
		t.Error("chọn nhầm phiên bản (khóa cũ cho bản mã khóa mới) không được giải mã")
	}

	if s.Version() != 2 {
		t.Errorf("Seal phải dùng khóa hiện tại (phiên bản 2), got %d", s.Version())
	}

	// Open không tham số chỉ dùng khóa hiện tại (cache Redis): bản mã khóa cũ phải bị từ chối.
	if got, err := s.Open(blobNew, AADValue); err != nil || got != "+84907654321" {
		t.Fatalf("Open (khóa hiện tại): %q %v", got, err)
	}

	if _, err := s.Open(blobOld, AADValue); err == nil {
		t.Error("Open không phiên bản không được thử khóa cũ")
	}

	if v := s.Versions(); len(v) != 2 || v[0] != 1 || v[1] != 2 {
		t.Errorf("Versions() = %v, want [1 2]", v)
	}

	if !s.HasVersion(1) || !s.HasVersion(2) || s.HasVersion(3) {
		t.Error("HasVersion sai")
	}
}

// Phiên bản chưa cấu hình phải cho lỗi RÕ RÀNG chỉ ra biến cần đặt, không phải "decryption failed" mơ hồ.
func TestOpenVersionUnknownIsExplicit(t *testing.T) {
	s := newTest(t)

	_, err := s.OpenVersion(7, []byte("x"), AADValue)
	if !errors.Is(err, ErrUnknownKeyVersion) {
		t.Fatalf("want ErrUnknownKeyVersion, got %v", err)
	}

	if !strings.Contains(err.Error(), "DATA_KEY_V7") {
		t.Errorf("thông báo phải nêu biến cần đặt (DATA_KEY_V7): %v", err)
	}
}

// TestNewValidatesRetiredKeys kiểm tra New từ chối khóa cũ không hợp lệ.
func TestNewValidatesRetiredKeys(t *testing.T) {
	cases := map[string]struct {
		cur     string
		version int16
		retired map[int16]string
	}{
		"retired key too short":          {testKey, 2, map[int16]string{1: "short"}},
		"retired key equals current":     {testKey, 2, map[int16]string{1: testKey}},
		"retired key equals pepper":      {testKey, 2, map[int16]string{1: testPepper}},
		"retired version equals current": {testKey, 2, map[int16]string{2: oldKey}},
		"two versions share one secret":  {testKey, 3, map[int16]string{1: oldKey, 2: oldKey}},
		"retired version not positive":   {testKey, 2, map[int16]string{0: oldKey}},
		"current version not positive":   {testKey, 0, nil},
		"current version negative":       {testKey, -1, nil},
	}

	for name, c := range cases {
		if _, err := New(c.cur, testPepper, c.version, WithRetiredKeys(c.retired)); err == nil {
			t.Errorf("%s: phải bị từ chối", name)
		}
	}

	if _, err := New(testKey, testPepper, 3, WithRetiredKeys(map[int16]string{1: oldKey, 2: oldKey2})); err != nil {
		t.Fatalf("cấu hình hợp lệ nhiều khóa cũ phải được chấp nhận: %v", err)
	}
}

// Blind index chỉ phụ thuộc pepper: xoay DATA_KEY không được làm đổi khóa tra cứu.
func TestBlindIndexDoesNotDependOnDataKey(t *testing.T) {
	a := newTest(t)
	b := newRotated(t, oldKey, 2, map[int16]string{1: testKey})

	if !bytes.Equal(a.Blind("phone", "exact", "+84901234567"), b.Blind("phone", "exact", "+84901234567")) {
		t.Fatal("blind index không được đổi khi chỉ xoay DATA_KEY")
	}
}

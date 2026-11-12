package auth

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Chuỗi hash có phần khóa dài bất thường phải bị từ chối trước khi tính argon2 với độ dài đó.
func TestVerifyPasswordRejectsOversizedHashKey(t *testing.T) {
	good, err := HashPassword("Correct-Horse-9")
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyPassword("Correct-Horse-9", good) {
		t.Fatal("hash hợp lệ phải xác minh được")
	}

	parts := strings.Split(good, "$")
	if len(parts) != 6 {
		t.Fatalf("định dạng hash không như mong đợi: %q", good)
	}

	// Thay phần khóa bằng 1 KB: vẫn là base64 hợp lệ nhưng vượt giới hạn 64 byte.
	parts[5] = base64.RawStdEncoding.EncodeToString(make([]byte, 1024))
	oversized := strings.Join(parts, "$")

	if VerifyPassword("Correct-Horse-9", oversized) {
		t.Fatal("hash có khóa 1 KB phải bị từ chối")
	}

	parts[5] = ""
	if VerifyPassword("Correct-Horse-9", strings.Join(parts, "$")) {
		t.Fatal("hash có khóa rỗng phải bị từ chối")
	}
}

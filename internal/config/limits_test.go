package config

import (
	"strings"
	"testing"
)

// setRequiredEnv đặt các biến bắt buộc để Load chạy được; test từng số sẽ ghi đè biến cần kiểm tra.
func setRequiredEnv(t *testing.T) {
	t.Helper()

	t.Setenv("SESSION_SECRET", "test-session-secret-0123456789abcdef")
	t.Setenv("DATA_KEY", testDataKey)
	t.Setenv("DATA_PEPPER", testPepper)
}

// Số cấu hình âm hoặc bằng 0 phải bị từ chối, và thông báo nêu đúng tên biến.
// Trước đây giá trị âm bị ép kiểu thành số không dấu rất lớn (BLOOM_EXPECTED_ITEMS) hoặc bị ép kiểu int32 không kiểm tra.
func TestLoadRejectsNonPositiveNumbers(t *testing.T) {
	cases := map[string]string{
		"PG_MAX_CONNS":         "0",
		"BLOOM_EXPECTED_ITEMS": "-5",
		"RATE_LIMIT_RPS":       "0",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			setRequiredEnv(t)
			t.Setenv(name, value)

			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("%s=%s phải bị từ chối với thông báo nêu %s, nhận được: %v", name, value, name, err)
			}
		})
	}
}

// Giá trị hợp lệ thì Load không báo lỗi.
func TestLoadAcceptsValidNumbers(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PG_MAX_CONNS", "32")
	t.Setenv("BLOOM_EXPECTED_ITEMS", "1000000")
	t.Setenv("RATE_LIMIT_RPS", "100")

	c, err := Load()
	if err != nil {
		t.Fatalf("giá trị hợp lệ bị từ chối: %v", err)
	}

	if c.BloomExpectedItems != 1000000 || c.PGMaxConns != 32 || c.RateLimitRPS != 100 {
		t.Fatalf("giá trị đọc sai: %+v", c)
	}
}

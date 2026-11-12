package main

import (
	"strings"
	"testing"
)

const deadDSN = "postgres://vsf:vsf@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"

// Cấu hình hoặc kết nối sai phải dừng sớm với lỗi nói rõ nguyên nhân, trước khi đụng tới dữ liệu.
func TestRotatePepperStopsEarlyOnBadConfigurationOrConnection(t *testing.T) {
	setPepperEnv(t, deadDSN, testPepperOld)

	if err := run([]string{"-dry-run"}); err == nil {
		t.Error("an unreachable database must be an error")
	}

	setPepperEnv(t, deadDSN, "short")

	if err := run([]string{"-dry-run"}); err == nil || !strings.Contains(err.Error(), "DATA_PEPPER_OLD") {
		t.Errorf("a short old pepper must be named in the error: %v", err)
	}

	setPepperEnv(t, deadDSN, testPepperOld)
	t.Setenv("SESSION_SECRET", "")

	if err := run([]string{"-dry-run"}); err == nil || !strings.Contains(err.Error(), "SESSION_SECRET") {
		t.Errorf("a missing SESSION_SECRET must be named in the error: %v", err)
	}
}

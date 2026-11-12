package main

import (
	"strings"
	"testing"
)

const deadDSN = "postgres://vsf:vsf@127.0.0.1:1/none?sslmode=disable&connect_timeout=1"

// Cấu hình hoặc kết nối sai phải dừng sớm với lỗi nói rõ nguyên nhân, trước khi đụng tới dữ liệu.
func TestRekeyStopsEarlyOnBadConfigurationOrConnection(t *testing.T) {
	setRekeyEnv(t, deadDSN, true)

	if err := run([]string{"-status"}); err == nil {
		t.Error("an unreachable database must be an error")
	}

	t.Setenv("SESSION_SECRET", "")

	if err := run([]string{"-status"}); err == nil || !strings.Contains(err.Error(), "SESSION_SECRET") {
		t.Errorf("a missing SESSION_SECRET must be named in the error: %v", err)
	}

	setRekeyEnv(t, deadDSN, true)
	t.Setenv("DATA_KEY", "too-short")

	if err := run([]string{"-status"}); err == nil || !strings.Contains(err.Error(), "DATA_KEY") {
		t.Errorf("a short DATA_KEY must be named in the error: %v", err)
	}
}

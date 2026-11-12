package store

import (
	"context"
	"testing"
)

// Số kết nối vượt giới hạn phải bị từ chối trước khi mở kết nối nào (không cần database).
func TestOpenPoolRejectsTooManyConnections(t *testing.T) {
	_, err := openPool(context.Background(), "postgres://u:p@127.0.0.1:1/x?sslmode=disable", 5000)
	if err == nil {
		t.Fatal("5000 kết nối phải bị từ chối")
	}
}

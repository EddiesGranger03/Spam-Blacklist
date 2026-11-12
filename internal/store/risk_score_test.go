package store

import (
	"errors"
	"testing"

	"vsf/internal/normalize"
)

// risk_score ngoài 0..100 phải bị từ chối ở tầng store, không phụ thuộc người gọi đã Validate hay chưa.
func TestRiskScore16(t *testing.T) {
	for _, ok := range []int{0, 1, 50, 100} {
		got, err := riskScore16(ok)
		if err != nil || int(got) != ok {
			t.Fatalf("%d: got %d, err %v", ok, got, err)
		}
	}

	for _, bad := range []int{-1, 101, 32768, 70000, -70000} {
		_, err := riskScore16(bad)
		if !errors.Is(err, normalize.ErrInvalid) {
			t.Fatalf("%d phải bị từ chối với ErrInvalid, nhận được %v", bad, err)
		}
	}
}

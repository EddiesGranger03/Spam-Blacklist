// Package scaletest holds heavy, repeatable scale and chaos tests for the 3-layer filter, the snapshot/leader
// bootstrap and the Redis Pub/Sub sync. Every test file is behind the `scale` build tag, so a normal
// `go test ./...` compiles and runs nothing here. Run it with scripts/scale-test.sh; see docs/SCALE_TEST.md.
package scaletest

#!/usr/bin/env bash
# Chạy bộ test quy mô + chaos (internal/scaletest, build tag `scale`). CI thường KHÔNG chạy: các file test có
# `//go:build scale`, nên `go test ./...` bỏ qua hoàn toàn.
#
#   scripts/scale-test.sh                 # filter bench + startup + rolling deploy + chaos (10M dòng)
#   scripts/scale-test.sh filter          # chỉ bench filter (không cần DB)
#   scripts/scale-test.sh startup|deploy|chaos
#   SCALE_ROWS=2000000 scripts/scale-test.sh chaos      # quy mô nhỏ hơn cho máy ít RAM
#   SCALE_FILTER_N=1000000,10000000,50000000 scripts/scale-test.sh filter
#   KEEP=1 scripts/scale-test.sh          # không dừng container khi xong (giữ bảng 10M dòng để chạy lại)
#   scripts/scale-test.sh import          # import lớn giữa hai lần snapshot (FPR của delta, dựng sớm); RISK_IMPORT_N để đổi cỡ
#
# Cần Docker (Postgres 16 + Redis 7 dựng bằng deploy/docker-compose.scale.yml) và ~4 GB RAM trống cho 10M dòng.
# Kết quả (log đầy đủ) ghi vào docs/data/scale-<thời điểm>.txt.
set -euo pipefail

cd "$(dirname "$0")/.."

what="${1:-all}"
export SCALE_DATABASE_URL="${SCALE_DATABASE_URL:-postgres://vsf:vsf@127.0.0.1:5545/vsf_scale_test?sslmode=disable}"
export SCALE_REDIS_ADDR="${SCALE_REDIS_ADDR:-127.0.0.1:6391}"
export SCALE_ROWS="${SCALE_ROWS:-10000000}"

out="docs/data/scale-$(date +%Y%m%d-%H%M%S).txt"
mkdir -p docs/data

run() { # run <regex> <timeout>
	go test -tags scale -run "$1" -v -count=1 -p 1 -timeout "$2" ./internal/scaletest 2>&1 | tee -a "$out"
}

if [ "$what" != "filter" ]; then
	docker compose -f deploy/docker-compose.scale.yml up -d --wait
	if [ -z "${KEEP:-}" ]; then trap 'docker compose -f deploy/docker-compose.scale.yml stop' EXIT; fi
fi

case "$what" in
filter) run 'TestScaleFilter' 30m ;;
startup) run 'TestScaleStartup' 90m ;;
deploy) run 'TestScaleRollingDeploy' 90m ;;
chaos) run 'TestChaos' 90m ;;
import)
	export RISK_DATABASE_URL="${RISK_DATABASE_URL:-$SCALE_DATABASE_URL}" RISK_REDIS_ADDR="${RISK_REDIS_ADDR:-$SCALE_REDIS_ADDR}"
	run 'TestRiskImportBetweenSnapshots' 180m
	;;
all)
	run 'TestScaleFilter' 30m
	run 'TestScaleStartup|TestScaleRollingDeploy' 120m
	run 'TestChaos' 120m
	;;
*) echo "unknown target: $what" >&2; exit 2 ;;
esac

echo "log: $out"

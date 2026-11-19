#!/usr/bin/env bash
# Kiểm chứng đa instance bằng HTTP thật: 3 server + Postgres (+ replica) + Redis dựng bằng deploy/docker-compose.multi.yml.
# Log ghi vào docs/data/. Xem docs/SCALE_TEST.md.
#
#   scripts/multi-test.sh                       # = run: propagation, rolling restart, kill leader (cmd/multitest)
#   REPLICA=1 scripts/multi-test.sh             # server đọc qua Postgres replica (READ_DATABASE_URL)
#   SCENARIOS=propagation scripts/multi-test.sh
#   scripts/multi-test.sh redis-freeze          # docker pause Redis 60 s dưới tải, đo độ trễ check/ghi/đồng bộ
#   DELAYS="0s 1s 2s" scripts/multi-test.sh replica-lag   # replica trễ giả lập: update ở A -> check ngay ở A/B/C
#   scripts/multi-test.sh clean                 # xóa container + volume + image + binary tạm
#   KEEP=1 ...                                  # không dừng container khi xong
#
# Nhiều máy thật: không dùng script này để dựng. Chạy `docker compose up -d server-a` trên từng máy với DATABASE_URL,
# REDIS_ADDR... trỏ tới Postgres/Redis dùng chung, rồi từ bất kỳ máy nào:
#   go run ./cmd/multitest -nodes http://m1:8080,http://m2:8080,http://m3:8080 -scenarios propagation \
#       -metrics-token <METRICS_TOKEN>
# (rolling/leader cần -restart-cmd/-kill-cmd, ví dụ "ssh {name} sudo systemctl restart vsf").
set -euo pipefail

cd "$(dirname "$0")/.."

cmd="${1:-run}"
export SERVER_IMAGE="${SERVER_IMAGE:-vsf-server:multi}"
export METRICS_TOKEN="${METRICS_TOKEN:-multi-metrics-token-0123}"
export FILTER_SNAPSHOT_POLL="${FILTER_SNAPSHOT_POLL:-5s}"
A="http://127.0.0.1:${MULTI_PORT_A:-8201}"
B="http://127.0.0.1:${MULTI_PORT_B:-8202}"
C="http://127.0.0.1:${MULTI_PORT_C:-8203}"
COMPOSE="docker compose -f deploy/docker-compose.multi.yml"
BIN="${BIN:-.multi-bin}"
stamp=$(date +%Y%m%d-%H%M%S)
mkdir -p docs/data "$BIN"

profile=()
if [ -n "${REPLICA:-}" ] || [ "$cmd" = replica-lag ]; then
	profile=(--profile replica)
	export READ_DATABASE_URL="${READ_DATABASE_URL:-postgres://vsf:vsf@postgres-replica:5432/vsf?sslmode=disable}"
fi

# tool <name>: build cmd/<name> once into $BIN and print its path.
tool() {
	[ -x "$BIN/$1" ] || go build -o "$BIN/$1" "./cmd/$1"
	echo "$BIN/$1"
}

wait_ready() {
	for u in "$@"; do
		for _ in $(seq 1 120); do curl -fs "$u/readyz" >/dev/null 2>&1 && break; sleep 1; done
	done
}

up() {
	$COMPOSE "${profile[@]}" up -d --build postgres redis ${READ_DATABASE_URL:+postgres-replica}
	$COMPOSE "${profile[@]}" up -d --build server-a
	wait_ready "$A"
	$COMPOSE "${profile[@]}" up -d server-b server-c
	wait_ready "$A" "$B" "$C"
}

# api_key: create an API key and a hits.csv for the bench once per stack, then print the key.
api_key() {
	if [ ! -s "$BIN/key" ]; then
		"$(tool gencsv)" -n 20000 -url 0 -out "$BIN/hits.csv" >/dev/null 2>&1
		"$(tool risktest)" setup -node "$A" -email admin@multi.test -csv "$BIN/hits.csv" >"$BIN/key"
		sleep 5 # the import runs in the background: give it time to commit and propagate
	fi
	cat "$BIN/key"
}

# bench_windows <url> <windows> <secs> <concurrency> <out.csv> <label>: one CSV row per window, to line latency up
# with an event that happens in the middle of the run.
bench_windows() {
	local url=$1 n=$2 secs=$3 conc=$4 out=$5 label=$6 key r s
	key=$(api_key)
	[ -s "$out" ] || echo "label,start_epoch,end_epoch,result" >"$out"
	for _ in $(seq 1 "$n"); do
		s=$(date +%s)
		r=$("$(tool bench)" -url "$url" -key "$key" -file "$BIN/hits.csv" -c "$conc" -d "${secs}s" -hit 0.1 2>&1 | tr '\n' ' ' || true)
		echo "$label,$s,$(date +%s),\"$r\"" >>"$out"
	done
}

metrics() {
	echo "# $1"
	for u in "$A" "$B" "$C"; do
		curl -s -H "Authorization: Bearer $METRICS_TOKEN" "$u/metrics" |
			grep -E '^vsf_(sync_|cache_errors|ratelimit_backend_errors|apikey_requests|check_negative_uncached|filter_)' |
			sed "s#^#$u #" || true
	done
}

finish() {
	if [ -z "${KEEP:-}" ] && [ "$cmd" != clean ]; then
		$COMPOSE "${profile[@]}" stop >/dev/null 2>&1 || true
	fi
}
trap finish EXIT

case "$cmd" in
run)
	up
	out="docs/data/multi-$stamp.txt"
	go run ./cmd/multitest -nodes "$A,$B,$C" -compose "$COMPOSE" -metrics-token "$METRICS_TOKEN" \
		-snapshot-poll "$FILTER_SNAPSHOT_POLL" -scenarios "${SCENARIOS:-propagation,rolling,leader}" \
		-rounds "${ROUNDS:-100}" 2>&1 | tee "$out"
	echo "log: $out"
	;;

redis-freeze)
	up
	key=$(api_key)
	out="docs/data/redis-freeze-$stamp"
	metrics before >"$out.metrics.txt"
	bench_windows "$B" 3 10 16 "$out.windows.csv" baseline
	bench_windows "$B" 14 10 16 "$out.windows.csv" freeze_and_after &
	benchpid=$!
	sleep 3
	"$(tool risktest)" redis -writer "$A" -reader "$B" -key "$key" -container "$($COMPOSE ps -q redis)" -freeze 60s \
		-email admin@multi.test -metrics-token "$METRICS_TOKEN" | tee "$out.txt"
	wait $benchpid || true
	metrics after >>"$out.metrics.txt"
	echo "results: $out.*"
	;;

replica-lag)
	up
	key=$(api_key)
	rep=$($COMPOSE "${profile[@]}" ps -q postgres-replica)
	out="docs/data/replica-lag-$stamp.txt"
	: >"$out"
	for d in ${DELAYS:-0s 500ms 1s 2s}; do
		docker exec "$rep" psql -U vsf -d vsf -c "ALTER SYSTEM SET recovery_min_apply_delay = '$d'" -c "SELECT pg_reload_conf()" >/dev/null
		sleep 2
		echo "=== recovery_min_apply_delay=$d ===" | tee -a "$out"
		"$(tool risktest)" fresh -writer "$A" -readers "$A,$B,$C" -key "$key" -rounds "${ROUNDS:-20}" -interval 10ms \
			-timeout 60s -email admin@multi.test | tee -a "$out"
	done
	docker exec "$rep" psql -U vsf -d vsf -c "ALTER SYSTEM RESET recovery_min_apply_delay" -c "SELECT pg_reload_conf()" >/dev/null
	metrics after >>"$out"
	echo "results: $out"
	;;

clean)
	$COMPOSE --profile replica down --volumes --remove-orphans
	docker image rm "$SERVER_IMAGE" 2>/dev/null || true
	rm -rf "$BIN"
	;;

*)
	sed -n '2,11p' "$0"
	exit 2
	;;
esac

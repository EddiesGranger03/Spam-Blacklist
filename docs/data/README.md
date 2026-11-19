# Log gốc của các số đo

Chỉ giữ log của những con số được trích trong [SCALE_TEST.md](../SCALE_TEST.md). Lần chạy mới ghi thêm file vào đây (xem `scripts/scale-test.sh`, `scripts/multi-test.sh`).

| File | Số đo |
|---|---|
| `build-60M.txt` | Leader quét + dựng filter ở 60M; pod mới khởi động từ snapshot (mục 2.2, 2.3) |
| `scan-100M.txt` | Chỉ quét bảng 100M dòng (mục 2.3) |
| `leader-build-load-30M.txt` | Ảnh hưởng của lần quét mỗi giờ lên check và Postgres ở 29M (mục 2.4) |
| `multi-node.txt` | 3 server thật: lan truyền, rolling restart, kill leader (mục 2.5) |
| `redis-freeze.txt` | Redis treo 60 s sau khi sửa F9 (mục 2.6) |
| `replica-lag.txt` | Replica trễ 0–5 s, kiểm F6 (mục 2.6) |
| `import-early-rebuild.txt` | Import 1,5M có/không dựng snapshot sớm, F10 (mục 2.6) |
| `apikey-bench.txt` | Bench 32 client × 3 server sau khi sửa F8 (mục 2.6) |

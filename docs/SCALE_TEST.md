# Kiểm chứng quy mô và sự cố: filter, snapshot, đồng bộ giữa các pod

Tài liệu này tóm tắt **số đo thật** của cơ chế filter mới và các lỗi đã tìm ra khi kiểm chứng. Vận hành xem [RUNBOOK.md](RUNBOOK.md); quyết định thiết kế còn mở xem [adr/](adr/). Log gốc của những con số được trích nằm ở [data/](data/).

## 1. Điều kiện đo

- **Máy:** Windows 11, Intel i5-13450HX, 11,8 GB RAM (lúc đo chỉ trống ~0,2–3 GB). Postgres 16 và Redis 7 chạy trong Docker **trên cùng máy**, `fsync=off`.
- **Hệ quả:** thời gian liên quan tới mạng và đĩa (quét bảng, tải snapshot, Pub/Sub) **lạc quan hơn production**. Thời gian CPU (dựng filter) và số byte thì sát thực tế.
- **Dữ liệu:** bảng `blacklist_entries` thật (32 partition), hash phân bố đều, 2% WHITELIST, sinh bằng SQL. Từ 30M trở lên dùng seed "lean" (cột mã hóa 1 byte) để vừa ổ đĩa.
- **Đo thật** = có log trong `docs/data/`. **Ngoại suy** = tính từ số đo thật, có ghi cách tính.

## 2. Kết quả chính

### 2.1 Filter: binary fuse thay Bloom (đo thật ở 1M, 10M, 30M, 60M)

| | Binary fuse (mới) | Bloom cũ |
|---|---|---|
| RAM thường trực | **1,13 B/số** (113 MB ở 100M, ngoại suy) | 1,25 B/số |
| Tỉ lệ báo nhầm "có thể có" (FPR) | **0,39%** | 0,82% |
| Tra cứu | 6–107 ns | 24–95 ns |
| Âm tính giả (số có thật bị báo "không có") | **0** | 0 |

FPR giảm một nửa, nghĩa là số request phải xuống DB xác nhận giảm một nửa. Cái giá: RAM tạm lúc dựng khoảng 40 B/số (xem 2.3).

### 2.2 Khởi động và deploy (đo thật ở 10M, 30M, 60M)

| Kịch bản | Thời gian tới ready | Dòng đọc từ bảng |
|---|---|---|
| Cách cũ: mỗi pod tự quét bảng (10M) | 13,6 s | 10 triệu |
| **Pod mới từ snapshot** (10M / 30M / 60M) | **0,17 s / 0,55 s / 0,92 s** | **0** |
| 3 pod deploy cùng lúc, đã có snapshot (10M) | cả ba trong 298 ms | **0** |
| 3 pod deploy cùng lúc, chưa có snapshot (10M) | ~12,5 s | đúng **1** lần quét (leader), không phải 3 |

### 2.3 Giới hạn của leader (đo thật tới 60M, ngoại suy phần còn lại)

| | 10M | 30M | 60M | 100M | 300M |
|---|---|---|---|---|---|
| Leader quét + dựng | 12,8 s | 41 s | 78,5 s | ngoại suy ≥ 2 phút | |
| RAM đỉnh của leader | 433 MB | 1,2 GB | 2,4 GB | **~4,2 GB** (ngoại suy) | ~12 GB |
| Snapshot | 10,5 MB | 31,6 MB | 63,1 MB | ~111 MB | ~320 MB |

- **60M là mức lớn nhất máy dev dựng được.** Giới hạn nằm ở RAM của leader, không phải Postgres: bảng 100M (14 GB) vẫn quét được với tốc độ 1,25 triệu dòng/s.
- Hệ số 40–43 B/số lặp lại ở cả 10M, 30M và 60M, nên ngoại suy là đáng tin.
- Pod thường không bị giới hạn này: chỉ pod đang làm leader cần nhiều RAM, và chỉ trong lúc dựng.

### 2.4 Ảnh hưởng của lần quét bảng mỗi giờ (đo thật ở 29M, có tải)

- Trong 2–3 phút leader quét: p99 check tăng từ **~10 ms lên 14–37 ms** (đỉnh 98 ms), thông lượng giảm 30–45% ở các cửa sổ xấu. Không lỗi 5xx, không tăng kết nối.
- Postgres chịu khoảng 1 core và ~37 MB/s đọc đĩa trong lúc quét.
- Ngoại suy 100M: quét 6–11 phút mỗi giờ. **Đây là lý do có [ADR 0001](adr/0001-sharded-filter-incremental-snapshot.md)** (bỏ quét định kỳ).
- Log: [leader-build-load-30M.txt](data/leader-build-load-30M.txt), [build-60M.txt](data/build-60M.txt), [scan-100M.txt](data/scan-100M.txt).

### 2.5 Đồng bộ giữa các pod (đo thật, 3 server thật qua HTTP)

| Thao tác ở server A → server khác thấy | p50 | p99 |
|---|---|---|
| Tạo entry BLACKLIST | 3,6 ms | 9,6 ms |
| BLACKLIST → WHITELIST (gỡ) | 3,6 ms | 6,9 ms |
| Sửa số điện thoại | 5,2 ms | 10,2 ms |
| Không có Redis (poll 1 s) | ~1 s | ~1 s |

- Rolling restart 3 server: 306–496 probe trên các server còn lại mỗi lượt, **0 sai, 0 lỗi**.
- Tắt leader đột ngột: server khác lên làm leader sau 0,25 s; server bị tắt quay lại sau ~2 s và thấy cả thay đổi xảy ra lúc nó tắt.
- Log: [multi-node.txt](data/multi-node.txt).

### 2.6 Sự cố (đo thật)

| Sự cố | Kết quả |
|---|---|
| Kill leader giữa lúc ghi snapshot | Rollback sạch, pod sau đó dùng bản cũ, ready sau 156 ms, 0 dòng đọc |
| Snapshot mới nhất hỏng (3 kiểu) | Không bao giờ được dùng; lùi về bản cũ còn tốt trong 178 ms; không còn bản tốt thì leader dựng lại ngay (~11 s) |
| Redis đóng kết nối | Ghi vẫn thành công; các pod chuyển sang poll 1 s và hội tụ trong ≤ 1 s; Redis về thì subscribe lại sau ~2 s |
| **Redis treo 60 s** (`docker pause`) | p99 check **3–5 ms**, 10–14 nghìn rps, 0 lỗi; ghi entry p99 107 ms. Log: [redis-freeze.txt](data/redis-freeze.txt) |
| Message Pub/Sub bị mất | Poll an toàn bắt được đúng sau 1 chu kỳ (mặc định 30 s) |
| Replica trễ 0–5 s (`READ_DATABASE_URL`) | **0/45 âm tính giả** ở mọi mức; số mới thấy trong 5–35 ms. Gỡ/WHITELIST trễ bằng độ trễ replica (an toàn). Log: [replica-lag.txt](data/replica-lag.txt) |
| Import 1,5M dòng giữa hai lần snapshot | Có dựng sớm: FPR **0,48%** (không có: 4,07%; import 6M không dựng sớm từng lên 68%). Log: [import-early-rebuild.txt](data/import-early-rebuild.txt) |
| Cache API key hết hạn dưới tải (32 client × 3 server, 75 s) | **3.061.272 request, 0 lần 429**. Log: [apikey-bench.txt](data/apikey-bench.txt) |

## 3. Lỗi đã tìm ra và đã sửa

Mỗi lỗi đều có test tái hiện (fail trước khi sửa, pass sau khi sửa).

| # | Mức | Lỗi | Cách sửa |
|---|---|---|---|
| F1 | Cao | Leader lưu snapshot lỗi thì quét lại bảng liên tục, không chờ | Giữ filter đã dựng trong RAM, chỉ thử lưu lại; chờ tăng dần (`FILTER_RETRY_BASE`/`MAX`) |
| F2 | Trung bình | Snapshot mới nhất hỏng thì không lùi về bản cũ | Thử từ mới tới cũ, đánh dấu bản hỏng (`corrupt`) |
| F3 | Trung bình | Snapshot hỏng làm pod mới chờ tới ~1 giờ | Pod yêu cầu leader dựng ngay (`filter_rebuild_requests`), nhiều pod hỏi vẫn chỉ dựng 1 lần |
| F4 | Thấp | Không có metric hay health cho snapshot | 10 metric `vsf_filter_*`, mục `snapshot` trong `/readyz` |
| F5 | **Nghiêm trọng** | Khóa leader trùng khóa nhật ký kiểm toán: đăng nhập và mọi thao tác ghi ở admin treo | Đổi khóa leader sang 727276; test bảo đảm mọi khóa khác nhau |
| F6 | **Nghiêm trọng** (khi dùng replica) | Ghi ở A, hỏi B ngay có thể trả "an toàn" sai tới 30 s | Feed thử lại tới khi replica bắt kịp; checker hỏi primary và không cache kết quả âm trong lúc đó |
| F7 | Thấp | Nhiều pod cùng khởi động trên DB trống thì một pod thoát | Tạo admin đầu tiên trùng thì coi như đã có |
| F8 | Thấp | Key hợp lệ nhận 429 khi cache key hết hạn dưới tải | Gộp các lần tra trùng nhau (single-flight); jitter TTL chỉ rút ngắn |
| F9 | **Nghiêm trọng** | Redis treo làm mọi request check mất 5 s (go-redis mặc định bỏ qua timeout của context) | Timeout 100 ms mỗi thao tác Redis, circuit breaker, Pub/Sub dùng kết nối riêng |
| F10 | Trung bình | Import lớn làm lớp delta quá tải, FPR lên tới 68% | Leader dựng snapshot sớm khi delta ≥ 70% (`FILTER_DELTA_REBUILD_RATIO`) |
| G1 | **Nghiêm trọng** | Sau khi xoay `DATA_PEPPER`, pod dùng snapshot hash cũ: **mọi số BLACKLIST bị báo an toàn** (tái hiện 40/40) | Snapshot mang dấu `domain_id` của pepper; pod chỉ dùng snapshot khớp; `RotatePepper` xóa snapshot cũ |

Ngoài ra có bộ kiểm tra tính đúng đắn chạy nền (`internal/verify`): mỗi phút lấy mẫu số BLACKLIST trong DB và kiểm filter có báo "có" không; một lần báo nhầm là log ERROR và tăng metric `vsf_filter_verify_false_negative_total`.

## 4. Chưa kiểm chứng / còn mở

- **Dựng filter ở 100M+**: máy dev không đủ RAM; cần máy ≥ 16 GB.
- **Nhiều máy thật** và mạng thật: mới chạy nhiều process trên một máy (code đã sẵn sàng, xem mục 5).
- **Leader quét bảng mỗi giờ** và **RAM leader tăng theo số lượng**: chờ duyệt [ADR 0001](adr/0001-sharded-filter-incremental-snapshot.md).
- **Chính sách khi không pod nào có filter**: chờ duyệt [ADR 0002](adr/0002-degraded-mode-policy.md).
- Một pod bị lỗi RAM có thể đánh dấu nhầm snapshot tốt là hỏng (hậu quả: cả cụm lùi về bản cũ rồi dựng lại; không sai kết quả).
- Gỡ/WHITELIST qua replica mất ~0,6 s ngay cả khi replica không trễ; nguyên nhân chưa rõ, không ảnh hưởng tính đúng.

## 5. Cách chạy lại

```bash
# Quy mô + sự cố, trong một process (Postgres/Redis riêng: deploy/docker-compose.scale.yml)
scripts/scale-test.sh                 # filter + khởi động + deploy + chaos (10M dòng)
scripts/scale-test.sh filter          # chỉ bench filter, không cần DB
scripts/scale-test.sh import          # import lớn giữa hai lần snapshot
SCALE_LEAN=1 SCALE_BIG_N=30000000 go test -tags scale -run TestScaleBig -v -timeout 3h ./internal/scaletest

# 3 server thật qua HTTP (deploy/docker-compose.multi.yml)
scripts/multi-test.sh                 # lan truyền, rolling restart, kill leader
scripts/multi-test.sh redis-freeze    # Redis treo 60 s dưới tải
DELAYS="0s 1s 2s" scripts/multi-test.sh replica-lag
scripts/multi-test.sh clean
```

Các test nặng nằm sau build tag `scale`, nên `go test ./...` thông thường không chạy chúng.

**Chạy trên nhiều máy thật:** trên mỗi máy chỉ chạy một server (`docker compose -f deploy/docker-compose.multi.yml up -d --no-deps server-a`) với `DATABASE_URL`, `READ_DATABASE_URL` (tùy chọn), `REDIS_ADDR` trỏ tới Postgres/Redis dùng chung; `DATA_KEY`, `DATA_PEPPER`, `SESSION_SECRET` phải giống nhau trên mọi máy. Rồi từ một máy bất kỳ:

```bash
go run ./cmd/multitest -nodes http://m1:8080,http://m2:8080,http://m3:8080 -metrics-token "$METRICS_TOKEN" -scenarios propagation
# thêm rolling/leader khi điều khiển được từ xa:
#   -services m1,m2,m3 -scenarios propagation,rolling,leader \
#   -restart-cmd 'ssh {name} sudo systemctl restart vsf' -kill-cmd 'ssh {name} sudo systemctl kill -s KILL vsf'
```

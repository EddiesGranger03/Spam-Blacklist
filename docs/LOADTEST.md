# Báo cáo loadtest VSF (bản đo của Claude)

> Đo ngày 2026-11-10.

> **Tóm tắt cho lãnh đạo (cập nhật 2026-11-12).** Các số dưới đây đo trên một máy (i5-13450HX), dùng chung CPU với Docker và IDE. Nhiễu giữa các lần chạy khoảng ±30%, nên chỉ chênh lệch lớn mới có ý nghĩa. Không dùng làm SLA.
>
> - **Điểm nghẽn đã sửa:** `FindMatches` nhanh hơn 1,7 đến 2,5 lần khi có nhiều request trúng blacklist (mục 5c).
> - **changefeed:** entry mới thấy được ngay khi có transaction mở (0,01 giây; trước đây không thấy trong 10 giây).
> - **import:** transaction dài nhất giảm từ 4,98 giây xuống 1,13 giây ở 200.000 dòng.
> - **Khởi động lạnh ở 9,57 triệu dòng** (thiết kế cũ, mỗi pod tự dựng Bloom): tới `/readyz` trong khoảng 32 đến 40 giây, phần lớn là rebuild Bloom (31 giây). *Với snapshot: pod mới sẵn sàng sau ~0,17 giây và không đọc dòng nào của `blacklist_entries` (đo ở 9,8 triệu dòng, xem [SCALE_TEST.md](SCALE_TEST.md)).* RAM server khoảng 60 MB. Sau khởi động, 16 kết nối: 5.966 request/s, p99 10 ms, không lỗi.
> - **Loadtest trong Docker:** app 2 CPU/1 GB, Postgres 4 CPU/2 GB, Redis 1 CPU/256 MB, 1 triệu dòng. Điểm nghẽn là CPU của app (chạm trần 2 nhân), không phải Postgres. RAM app khoảng 60 MB.

> Mọi số liệu lấy từ file kết quả thô của lần chạy (≈ 60 lượt × 20 giây), không làm tròn có lợi.

## 1. Môi trường đo

| Mục | Giá trị |
|---|---|
| CPU | Intel Core i5-13450HX, 10 nhân / 16 luồng |
| RAM | 11,8 GB |
| Hệ điều hành | Windows 11 Home |
| Go | 1.27.3 |
| Postgres | container `deploy-postgres-1` (postgres:16, `shared_buffers=128MB`, `max_connections=100`) |
| Redis | container `deploy-redis-1` (redis:7), chỉ bật ở kịch bản D |
| Dữ liệu | DB `vsf_load`: **997.588** dòng (1.000.000 sinh ra, trùng bị gộp), 32 partition |
| Server | build từ code hiện tại (`go build ./cmd/server`), chạy cổng 8098, `APP_ENV=development` |
| Công cụ tạo tải | harness riêng (stdlib Go) cùng cách đo với `cmd/bench`, có thêm: phân loại lỗi, tách độ trễ trúng/trượt, chế độ batch/health. Mỗi lượt 20 giây, mỗi kịch bản 3 lượt, có 1 lượt khởi động bỏ qua |
| Cấu hình mặc định | `AUTH_DISABLED=true`, không Redis, `POLL_INTERVAL=1s`, pool Postgres 32 kết nối |

**Hạn chế quan trọng (đọc trước khi dùng số):**
- Máy tạo tải, server và Postgres **dùng chung 16 luồng**, nên số tuyệt đối thấp hơn môi trường thật.
- Windows có độ phân giải đồng hồ thô: nhiều giá trị p50 dưới 1 ms hiện là ≈0,52 ms hoặc `0s`. **Không tin các con số dưới 1 ms**, chỉ dùng chúng để so sánh tương đối.
- Dao động giữa các lượt chạy cùng cấu hình khoảng ±5–15%, nên chênh nhỏ hơn mức đó không có ý nghĩa.
- Chỉ đo số điện thoại. Dữ liệu trúng được chọn ngẫu nhiên đều trong 699.726 số, nên **không có "khóa nóng"**. Ngoài ra bộ sinh số dùng seed cố định nên **các lượt chạy phát lại cùng một dãy khóa**: kết quả có Redis ở kịch bản D bị thổi phồng (xem mục 5d).

## 2. Kết quả theo kịch bản (3 lượt mỗi dòng)

Ký hiệu: RPS là số request mỗi giây. Độ trễ tính trên request thành công. "Trúng" là số nằm trong blacklist (phải đi xuống DB), "trượt" là số không có (Bloom trả lời ngay).

### A, B, C: `GET /v1/check`, không Redis, không xác thực

| Kịch bản | RPS (3 lượt) | p95 toàn bộ | p99 toàn bộ | p50 trúng | p99 trúng | p99 trượt | Lỗi |
|---|---|---|---|---|---|---|---|
| A: c=64, hit 10% | 18.233 / 18.827 / 18.774 | 25,6–26,8 ms | 39,6–41,1 ms | 24,9–26,1 ms | 58,4–59,9 ms | 7,8–8,9 ms | 0 |
| B: c=16, hit 10% | 18.552 / 18.152 / 17.244 | 5,1–5,4 ms | 8,7–9,5 ms | 4,8–5,2 ms | 12,3–13,6 ms | 4,0–4,3 ms | 0 |
| B: c=256, hit 10% | 17.071 / 19.070 / 19.081 | 119–122 ms | 137–142 ms | 118–121 ms | 156–165 ms | 8,3–13,8 ms | 14 (lượt 1) |
| C: c=64, hit 5% | 29.168 / 27.816 / 29.922 | 8,1–9,8 ms | 25,7–30,4 ms | 16,0–19,2 ms | 47,6–55,0 ms | 7,3–8,1 ms | 0 |
| C: c=64, hit 20% | 11.171 / 11.135 / 11.287 | ≈30 ms | 42,3–43,0 ms | ≈24 ms | ≈54 ms | 5,7–7,1 ms | 0 |
| C: c=64, hit 50% | 4.943 / 4.877 / 5.019 | 34,7–35,9 ms | 45,6–47,3 ms | 23,2–23,9 ms | 49,8–51,8 ms | ≈16 ms | 0 |

Lượt lỗi của B c=256 là 14 lỗi `conn_refused`, độ trễ lớn nhất lên 3,4 giây.

### Batch và health

| Kịch bản (c=64, hit 10%) | Số lần gọi/s | Số mục/s | p50 | p95 | p99 | max |
|---|---|---|---|---|---|---|
| `POST /v1/check/batch`, 10 mục | 2.222 / 2.268 / 2.308 | 22.200–23.100 | 34–35 ms | 54–57 ms | 65–70 ms | 137 ms |
| `POST /v1/check/batch`, 100 mục | 237 / 251 / 253 | 23.700–25.300 | 242–258 ms | 305–398 ms | 479–517 ms | 843 ms |
| `GET /healthz` | 88.403 / 91.419 / 87.870 | – | ≈0,53 ms | 2,2 ms | 3,3–3,4 ms | 11,9 ms |
| `GET /readyz` (có ping DB) | 15.521 / 17.419 / 19.143 | – | 3,2–3,9 ms | 5,3–6,6 ms | 6,9–8,7 ms | 25,7 ms |

### D: có Redis (c=64)

| Trạng thái cache | RPS (3 lượt) | p50 trúng | p99 trúng |
|---|---|---|---|
| Lạnh (xóa khóa `chk:*` trước mỗi lượt), hit 10% | 16.362 / 16.705 / 16.065 | 29,5–29,8 ms | 72–74 ms |
| Ấm, hit 10% (3 lượt liên tiếp) | 19.708 → 30.712 → **38.558** | 4,2 → 3,6 → **3,3 ms** | 52 → 60 → 50 ms |
| Lạnh, hit 50% | 4.635 | 25,1 ms | 61 ms |
| Ấm, hit 50% (2 lượt) | 8.906 → 12.533 | 5,4 → 3,9 ms | 54 → 50 ms |

### E: có xác thực API key (key RPS 1.000.000, không hạn mức)

| Kịch bản | RPS | p95 | p99 | Lỗi |
|---|---|---|---|---|
| c=64, hit 10% (3 lượt) | 19.731 / 16.163 / 16.322 | 19–26 ms | 37,5–40 ms | 0 |
| c=256, hit 10% (2 lượt) | 18.822 / 19.459 | 118–122 ms | 137–141 ms | 0 (lượt 1 không đo được, công cụ tạo tải bị crash 3 lần) |
| Không gửi key | HTTP **401** (đúng như thiết kế) | | | |

Chi phí xác thực **không tách được khỏi nhiễu**: 3 lượt c=64 dao động 16,2k–19,7k, lớn hơn mọi chênh lệch có thể có so với baseline (18,2k–18,8k).

## 3. Tài nguyên tiêu thụ

| Kịch bản | CPU server (số nhân dùng) | RAM đỉnh server | CPU container Postgres (giữa lượt) |
|---|---|---|---|
| A: c=64, hit 10% | ≈3,2 nhân | ≈162 MB | **≈1.185% (≈12 nhân trên 16 luồng)** |
| C: hit 50% | ≈1,7 nhân | ≈162 MB | ≈1.256% |
| `/healthz` | ≈7 nhân | ≈162 MB | 0,08% |
| `/readyz` | ≈4,5 nhân | ≈162 MB | ≈226% |
| Redis ấm, hit 10% | – | ≈163 MB | **≈9%** |

Bộ nhớ Postgres khoảng 1,09 GiB. Bloom filter chiếm 12,5 MB cho 997.588 mục.
Phân bổ tầng của lượt khởi động: 320.942 request dừng ở Bloom, 38.530 phải xuống DB (≈10,7%, đúng bằng `hit` 10%, nên **Bloom không bỏ sót ca nào trong môi trường bình thường**).

**Báo cáo:** có lỗi kết nối của máy tạo tải ở c≥256, và dùng số liệu c=16/64 làm chuẩn, vì chúng sạch lỗi.

## 4. Phát hiện chính

### Phát hiện 1 (quan trọng nhất): điểm nghẽn là DB, chủ yếu do thời gian lập kế hoạch truy vấn

- Số request trúng đi xuống Postgres. Ở mọi mức hit, số lượt tra DB mỗi giây gần như cố định: **≈1,5k (hit 5%) → 1,9k (10%) → 2,2k (20%) → 2,5k (50%)**. Postgres dùng ≈12 nhân để phục vụ chỉ ≈2k lượt/giây, tức ≈5 ms CPU mỗi truy vấn.
- **Đã xác nhận nguyên nhân (xem mục 5b bên dưới).** Truy vấn `FindMatches` bị lập kế hoạch lại ở mọi lần gọi (≈1–2 ms), trong khi thực thi chỉ ≈0,1–0,24 ms. (Con số 3,9 ms đo lúc đầu là phiên psql mới, chưa nóng cache, nên cao hơn thực tế.)
- Hệ quả thực tế: tổng RPS ≈ 2.000 / tỉ lệ trúng. Tỉ lệ trúng cao (spam thật) làm sập thông lượng: 29k (5%) → 4,9k RPS (50%).
- Độ trễ trúng tăng theo tải: p50 ≈5 ms (c=16) → 25 ms (c=64) → 120 ms (c=256). Tăng kết nối không tăng thông lượng, chỉ làm hàng đợi dài hơn.
- Request trượt không bị ảnh hưởng nhiều (p99 ≈8 ms ở c=64), nên Bloom filter làm đúng việc.

### 5b. Điều tra chi phí lập kế hoạch (DB planning)

**Cơ chế:** `FindMatches` ([entries.go:275](../internal/store/entries.go)) join bảng 32 partition với `unnest($1..$4)`. Postgres phải lập kế hoạch qua 32 partition. Với prepared statement, Postgres chỉ chuyển sang kế hoạch dùng lại (generic) nếu chi phí ước tính không cao hơn kế hoạch riêng (custom). Ở đây kế hoạch generic ước tính **2666** so với custom **266** (vì generic không tính được việc cắt partition lúc chạy), nên **không bao giờ được chọn**.

**Bằng chứng:**
- Trong 1 phiên psql, chạy 40 lần truy vấn ở chế độ `auto`: `custom_plans=40, generic_plans=0`.
- Phiên nóng: Planning **1,0–2,0 ms**, Execution **0,10–0,24 ms** (lập kế hoạch gấp khoảng 10 lần thực thi). Với kế hoạch generic: Planning 0,02 ms.
- Thông lượng đo bằng harness Go dùng cùng driver `pgx v5.12`, pool 32 kết nối, 32 goroutine, dữ liệu thật (997.588 dòng), mỗi dòng chạy 8 giây:

| Cách chạy | 1 khóa (số điện thoại) | 5 khóa (URL) | p50 / p99 (1 khóa) |
|---|---|---|---|
| **Hiện tại** (`unnest` join, chế độ `auto`) | **2.489 truy vấn/s** | **2.577/s** | 11,0 ms / 39,2 ms |
| Giữ truy vấn, ép `plan_cache_mode=force_generic_plan` | 10.399/s (×4,2) | 9.948/s (×3,9) | 2,6 ms / 9,6 ms |
| Viết lại bằng `value_hash = ANY(...) AND value_blind = ANY(...)` | **21.392/s (×8,6)** | 10.695/s (×4,1) | 1,3 ms / 4,2 ms |

Con số 2.489/s khớp với trần ≈2–2,5k lượt tra DB mỗi giây ở loadtest, nên đây chính là điểm nghẽn.

**Các phương án và quyết định:**
- **A (đã làm):** viết lại truy vấn bằng `ANY`, rồi lọc `type`/`match_type`/`value_blind` chính xác ở Go. Chỉ ảnh hưởng một hàm, tăng 4–9 lần. Kết quả đo ở mục 5c.
- **B (không áp dụng):** đặt `plan_cache_mode=force_generic_plan` cho cả pool. Tăng ≈4 lần, thấp hơn phương án A (≈8,6 lần), và áp dụng cho **mọi** truy vấn nên có thể làm chậm các truy vấn khác. Sau khi làm A thì không còn cần.
- **C (không làm):** giảm số partition: cần migration dữ liệu, rủi ro cao, trong khi điểm nghẽn đã được xử lý bằng A.

**Lưu ý của phương án A:** hai mảng `ANY` độc lập nên có thể ghép chéo khóa này với blind của khóa kia. Chỉ cần lọc lại ở Go để loại kết quả sai, rủi ro thấp.

### 5c. Kết quả sau khi sửa `FindMatches`

**Đã làm:** viết lại `FindMatches` ([entries.go:261](../internal/store/entries.go)) dùng `ANY` thay cho join `unnest`, kèm bước lọc lại chính xác bộ 4 `(hash, type, match_type, blind)` ở Go. Thêm 2 test hồi quy trong [findmatches_test.go](../internal/store/findmatches_test.go). Test ghép chéo đã được chứng minh **đỏ** trên bản `ANY` thô (không có bước lọc ở Go) và **xanh** sau khi thêm bước lọc.

**Kiểm chứng:** 12/12 test của `store` pass trên DB `vsf_test` (trước đây các test này tự bỏ qua vì thiếu `TEST_DATABASE_URL`), `go vet` sạch, toàn bộ test các gói khác pass.

**Đo trước/sau:** build bản cũ từ `HEAD` và bản mới từ working tree, chạy **xen kẽ** trong cùng một phiên (3 lượt × 15 giây mỗi kịch bản, có khởi động lại server và 5 giây làm nóng trước mỗi lượt), 0 lỗi ở mọi lượt. Số trung vị:

| Kịch bản | RPS cũ → mới | Thay đổi | p99 toàn bộ (cũ → mới) | p50 request trúng (cũ → mới) |
|---|---|---|---|---|
| c=16, 10% trúng | 15.078 → 25.260 | **×1,68** | 7,6 → 3,8 ms | 4,0 → 1,4 ms |
| c=64, 10% trúng | 16.332 → 20.390 | **×1,25** | 13,8 → 10,6 ms | 6,9 → 3,6 ms |
| c=64, 20% trúng | 11.952 → 18.562 | **×1,55** | 21,5 → 11,2 ms | 9,1 → 3,8 ms |
| c=64, 50% trúng | 5.676 → 14.158 | **×2,49** | 35,8 → 13,6 ms | 18,0 → 4,8 ms |

**Cách đọc và hạn chế:**
- Càng nhiều request trúng (phải xuống DB), cải thiện càng lớn, đúng với nguyên nhân đã tìm ra. Ở 10% trúng, cải thiện nhỏ hơn vì lúc đó điểm nghẽn chuyển sang CPU của server và máy tạo tải.
- Số tuyệt đối của bản cũ hôm nay **khác** bảng ở mục 2 (đo hôm trước): sau khi Docker khởi động lại, DB chạy nhanh hơn. Vì vậy chỉ so sánh trong cùng bảng này (cùng phiên, xen kẽ), đừng so với mục 2.
- Dao động giữa các lượt vẫn lớn (ví dụ bản cũ c=64/10% trúng: 12,3k đến 17,3k), nên chênh dưới ≈15% không có ý nghĩa. Các mức cải thiện ×1,5 trở lên vượt xa nhiễu này.
- Redis và xác thực với bản mới: xem mục "Đo trước/sau C1, C2 và các kịch bản sự cố" ở cuối tài liệu (đã dùng Redis và API key).

### 5d. Ước lượng tỉ lệ trúng cache từ `metrics_truoc_D.txt` và `metrics_sau_D.txt`

**Dữ liệu vào:** server của bạn (cổng 8099, `REDIS_ADDR=localhost:6379`, bản build trước khi sửa `FindMatches`). Bạn xóa khóa `chk:*` trong Redis, chụp `truoc_D` (lúc đó chưa có bộ đếm tầng nào, tức bằng 0), rồi chạy `cmd/bench` (c=64, 30 giây, hit 0,1). `sau_D` chụp lần cuối lúc 09:55, **sau 5 lượt chạy** (không phải 3: lần chụp sau lượt thứ 3 đã bị ghi đè).

| Bộ đếm | Giá trị |
|---|---|
| `bloom` (Bloom báo "không có", trả lời ngay) | 5.120.400 |
| `cache` (trúng Redis) | 479.962 |
| `db` (trượt cache, xuống Postgres) | 141.088 |
| Tổng | 5.741.450 |

Kiểm tra chéo: tổng = 609.419 + 1.012.764 + 1.271.473 + 1.394.336 + 1.453.458 = 5.741.450 (đúng bằng tổng request của 5 lượt `bench`); `cache + db` = 621.050 = tổng số phản hồi `blacklisted` của 5 lượt (không có dương tính giả Bloom).

**Ước lượng:**
- **Tỉ lệ trúng cache = cache / (cache + db) = 479.962 / 621.050 = 77,3%** (trong số request mà Bloom nói "có thể có").
- Tính trên tổng mọi request: tầng Bloom 89,2%, tầng cache 8,4%, tầng DB 2,5%.
- Mã A (Redis tắt, c=64, hit 0,1, 3 lượt do mình chạy lại với cùng bản build): 20.424 / 19.795 / 18.679 RPS, p95 25–27 ms, p99 38–41 ms, 0 lỗi; tầng DB chiếm **10,8%** tổng request (190.194 / 1.768.068). Redis đưa tỉ lệ này xuống 2,5%, tức giảm khoảng 77% số lượt tra DB.

**Vì sao 77,3% không nên dùng như "hiệu quả cache với lưu lượng thật":**
- Mỗi lượt `bench` dùng seed cố định, nên 5 lượt **phát lại cùng một dãy khóa**. Bằng chứng: số khóa khác nhau thực tế (141.088 lượt `db`) khớp với mô hình "dãy khóa của lượt dài nhất, trừ trùng nội bộ" (≈139.954, lệch 0,8%), chứ không phải ≈412.000 như khi khóa được chọn ngẫu nhiên độc lập ở mỗi lượt.
- Với lưu lượng ngẫu nhiên đều trên 699.726 số, không phát lại: lượt đầu (nguội) chỉ trúng ≈4,5%; sau cộng dồn 621.050 lượt tra thì ≈34%.
- Hệ quả đúng với số đo của bạn: lượt 1 (cache nguội) chỉ đạt 20.302 RPS, bằng mã A (≈20,4k). Các lượt sau tăng dần 33,7k → 42,3k → 46,4k → 48,4k RPS là do phát lại, không phải do cache hiệu quả thật.
- Nếu muốn con số cho 3 lượt đầu: ước lượng ≈60% theo cùng mô hình (số thật không còn vì file bị ghi đè).

**Đã sửa công cụ (`cmd/bench`) và kiểm chứng giả thuyết "phát lại":**
- Cờ mới: `-seed N` (mặc định `0` = theo thời gian, mỗi lượt một dãy khóa; seed in ra để chạy lại), `-dist uniform|zipf` và `-zipf-s` (khóa nóng), `-metrics-url` (tự đọc `/metrics` trước và sau lượt chạy, in tỉ lệ Bloom/cache/DB và tỉ lệ trúng cache). Lỗi `status 0` giờ được phân loại nguyên nhân (`error_causes=...`). 8 test đơn vị mới ở `cmd/bench/main_test.go`.
- Thử trên server có Redis, c=64, 20 giây mỗi lượt, xóa khóa `chk:*` trước mỗi nhóm:

| Cách chạy | Tỉ lệ trúng cache lượt 1 → 2 → 3 | RPS lượt 1 → 2 → 3 |
|---|---|---|
| Seed ngẫu nhiên mỗi lượt, khóa đều | **2,6% → 7,6% → 12,4%** | 17,2k → 16,8k → 16,9k |
| Seed cố định (`-seed 1`, tái hiện lỗi cũ) | 3,2% → 60,8% → **95,2%** | 21,0k → 36,9k → 38,9k |
| Zipf s=1,1, seed ngẫu nhiên | 70,6% → 77,7% | 35,5k → 36,1k |

- Mô hình dự đoán lượt 1 (nguội, khóa đều) khoảng 2,6%; đo được **2,6%**. Khi seed cố định, tỉ lệ vọt lên 95% và RPS gấp đôi: đây chính là hiện tượng phát lại đã làm thổi phồng số đo Redis trước đây.
- **Kết luận đúng về Redis:** với khóa phân bố đều, cache gần như không giúp ích trong lượt đầu và tăng rất chậm; chỉ khi có khóa nóng (Zipf) mới đạt tỉ lệ trúng cao ngay. Hiệu quả thật của Redis phụ thuộc vào mức độ lặp lại của khóa trong lưu lượng thật, cần đo trên dữ liệu thật.
- Đối chứng công cụ mới không làm lệch số đo cũ (cùng server, xen kẽ, cờ mặc định, 3 lượt mỗi bên): bench gốc 18.007 / 17.206 / 16.596 RPS, bench mới 16.835 / 16.630 / 17.291 RPS, chênh trong nhiễu.

### Phát hiện 2: Redis có ích, nhưng chậm ấm và ban đầu hơi tốn

- Cache lạnh còn **chậm hơn** không cache một chút (16,4k so với 18,8k RPS), vì mỗi request trúng thêm một lần ghi Redis.
- Khi ấm, RPS tăng gấp đôi (19,7k → 38,6k), độ trễ trúng giảm từ ≈26 ms xuống ≈3,3 ms, và Postgres chỉ còn ≈9% CPU.
- **Hiệu chỉnh (2026-11-11): con số "gấp đôi" ở trên bị thổi phồng bởi hiện tượng phát lại.** Cả harness của mình lẫn `cmd/bench` đều khởi tạo bộ sinh số ngẫu nhiên của mỗi luồng bằng seed cố định (`rand.NewSource(w+1)`, [bench/main.go:67](../cmd/bench/main.go)), nên **mỗi lượt chạy phát lại cùng một dãy khóa**. Lượt chạy sau gặp lại đúng các khóa đã nằm trong cache của lượt trước, nên tỉ lệ trúng cache bị đẩy cao một cách giả tạo. Với lưu lượng ngẫu nhiên thật (không phát lại) và khóa phân bố đều, tỉ lệ trúng cache ước tính chỉ ≈4–5% trong 30 giây đầu. Xem mục 5d.
- p99 trúng vẫn ≈50 ms, vì các lượt trúng chưa có trong cache vẫn phải xuống DB.

### Phát hiện 3: batch không hiệu quả hơn nhiều so với gọi từng cái

- Batch 100 mục cho 24–25k mục/s, chỉ hơn gọi lẻ (18–19k/s) khoảng 25%, và mỗi lần gọi mất p99 ≈0,5 giây. Điểm nghẽn vẫn là DB.
- Lỗi M1 (batch chỉ trừ 1 token) đã đo ở lần tấn công: batch 100 mục với `rps_limit=10` đạt 0 mục/s sau khi vá (xem ATTACK_PUBLIC_API.md).

### Phát hiện 4: `/readyz` chạm DB ở mỗi lần gọi và không cần xác thực

- Mỗi lần gọi tốn ping DB: 15–19k RPS, p50 ≈3,5 ms, Postgres ≈226% CPU. Với load balancer gọi vài giây một lần thì không đáng kể, nhưng đây là endpoint công khai làm nặng DB (liên quan M3 trong báo cáo trước).



## 6. Trạng thái các việc đề xuất

| Việc | Trạng thái |
|---|---|
| Thêm `-mode batch` và thống kê loại lỗi vào `cmd/bench` | **Đã làm** (có test). Thống kê loại lỗi (`error_causes`) có sẵn từ trước. |
| Đo lại sau khi sửa C1, C2 | **Đã làm**: xem "Trước và sau khi sửa C1 và C2" ở trên |
| Kịch bản sự cố GUIDE bước 13 | **Đã làm** ở 200.000 dòng, khởi động lạnh ở 9,57 triệu dòng, và loadtest Docker 1 triệu dòng. Quy mô 100 triệu dòng: **không cần** (xác nhận của sếp). |
| Đo trên nhiều máy, replica trễ | **Chưa làm** (không có môi trường). |

## 7. Cách tái hiện

Loadtest Docker có sẵn trong repo: `deploy/docker-compose.loadtest.yml` (hướng dẫn chạy ở đầu file). Các script đo khác nằm ở thư mục tạm của phiên làm việc, chưa thuộc repo.

Harness và driver nằm ở thư mục tạm của phiên làm việc, **chưa thuộc dự án**. Nếu bạn muốn đưa vào dự án (ví dụ gộp vào `cmd/bench`), mình sẽ gửi kế hoạch để bạn duyệt.


## Đo trước/sau C1, C2 và các kịch bản sự cố

**Môi trường.** Một máy Windows (i5-13450HX), Postgres 16 và Redis 7 trong Docker trên máy đó. Máy dùng chung CPU với Docker và IDE. Dữ liệu 199.895 SĐT nạp qua trang import. Số liệu chỉ so sánh tương đối trong cùng một lần chạy. **Nhiễu giữa các lần chạy khoảng ±30%** trên máy này (ví dụ cùng một cấu hình cho 7.265 và 12.542 request/s), nên chênh lệch nhỏ hơn mức đó không có ý nghĩa.

### Trước và sau khi sửa C1 và C2

Cùng kịch bản chạy trên bản HEAD (trước mọi lần vá) và bản hiện tại.

| Kịch bản | Trước (HEAD) | Sau (hiện tại) |
|---|---|---|
| C1: giữ transaction DB mở 45 giây, tạo entry qua admin, kiểm tra `/v1/check` | Không thấy entry trong 10 giây | Thấy sau **0,01 giây** |
| C1: `/readyz` lúc 36 giây khi transaction còn mở | 200, không cảnh báo | 200, có cảnh báo `changefeed_stalled` |
| C2: import 199.936 dòng, lấy mẫu tuổi transaction dài nhất mỗi 0,5 giây | Import 16,2 giây; tuổi transaction lớn nhất **4,98 giây** | Import 16,3 giây; tuổi transaction lớn nhất **1,13 giây** |

Lưu ý: lấy mẫu mỗi khoảng 0,5 đến 0,7 giây nên con số tuổi transaction là cận dưới. Ở 200.000 dòng, thời gian import gần như không đổi; lợi ích của C2 thể hiện rõ hơn khi file lớn.

### Kịch bản sự cố

| Kịch bản | Kết quả | Ghi chú |
|---|---|---|
| Khởi động lạnh tới `/readyz` = 200 (200.000 dòng) | 0,53 giây | Đã đo thêm ở 9,57 triệu dòng, xem mục cuối |
| Rebuild Bloom mỗi 10 giây khi có tải | Rebuild xảy ra **2 lần** trong 25 giây. Không lỗi. Đối chứng không rebuild: 7.265 request/s, p99 8,0 ms; có rebuild: 12.542 request/s, p99 4,3 ms | Chênh lệch nằm trong nhiễu, không kết luận được ảnh hưởng của rebuild |
| Import 200.000 dòng song song với bench (16 kết nối) | Import 7,0 giây. Bench: 7.655 request/s, p99 6,6 ms, không lỗi. Đối chứng không import: 11.644 request/s, p99 3,6 ms | Import có chạy thật; chênh lệch p99 cỡ 3 ms nằm gần vùng nhiễu |
| Tắt Redis giữa chừng (30 giây bench, tắt ở giây 10, bật lại ở giây 20) | Mọi request vẫn **200**. p99 tăng lên **46 ms** | Khớp với timeout 50 ms của bước giới hạn tốc độ khi Redis không phản hồi; server vẫn phục vụ (fail-open) |

**Đã xác minh Redis thật sự được dùng:** số lệnh Redis tăng từ 0 lên 445.632 trước khi tắt. Sau khi bật lại, bộ đếm bắt đầu lại từ 0 và đạt 127.496 lệnh.

**Chưa làm được:**
- Replica trễ (`READ_DATABASE_URL`): không có môi trường replica.
- Nhiều máy: tất cả chạy trên một máy.
- Khởi động lạnh 100 triệu dòng: đã đo 9,57 triệu dòng.

### Khởi động lạnh ở quy mô 9,57 triệu dòng

| Chỉ số | Giá trị |
|---|---|
| Sinh CSV 10 triệu dòng | 1,8 giây |
| Nạp qua trang import (sau khi gộp trùng) | 9.569.493 dòng, **816 giây** (khoảng 13,6 phút) |
| Khởi động lạnh tới `/readyz` = 200 | **31,8 giây** (lần 1); 39,7 giây (lần 2, đo cùng lúc tạo key) |
| Rebuild Bloom (theo log server) | **31,3 giây**, 9.664.917 mục, 13,3 MB |
| RAM server sau khởi động | khoảng 60 MB (đo bằng tasklist tại một thời điểm) |
| Bench sau khởi động, có API key, 16 kết nối, 20 giây | **5.966 request/s**, p50 1,81 ms, p95 6,83 ms, p99 10,07 ms, max 433 ms, **0 lỗi** (119.346 request, 19.034 lượt trúng blacklist) |

**Chênh lệch Bloom 1% đã được kiểm chứng:** số mục Bloom sau khởi động (9.664.917) lớn hơn số dòng DB đo trước đó (9.569.493) khoảng 1%. Đối chiếu ở 1 triệu dòng với import đủ: số dòng DB trước khi tắt, sau khi khởi động và `items` của Bloom đều là **997.588**, nên Bloom đếm đúng. Khi khởi động lạnh `items` bằng đúng số dòng quét được. Chênh lệch ở 10 triệu dòng nhiều khả năng do lần đếm DB lấy sớm hơn một lô import (khoảng 95.000, cỡ lô 100.000); chưa chạy lại ở quy mô đó để xác nhận trực tiếp.

**Ước lượng cho 100 triệu dòng (suy ra từ số đo trên, chưa đo):** import khoảng 2,3 giờ, Bloom khoảng 140 MB, khởi động lạnh khoảng 5 phút, đĩa khoảng 50 GB.

### Loadtest trong Docker: CPU và RAM từng thành phần (2026-11-12)

**Mục đích:** xem CPU và RAM từng thành phần xử lý ra sao khi chịu tải, trong điều kiện bị giới hạn tài nguyên (không cần quy mô lớn).

**Cấu hình** (`deploy/docker-compose.loadtest.yml`): app 2 CPU / 1 GB, Postgres 4 CPU / 2 GB, Redis 1 CPU / 256 MB. Dữ liệu 997.588 số điện thoại nạp qua trang import. Công cụ tạo tải (`cmd/bench`) chạy trên máy host, dùng chung CPU với Docker nên số tuyệt đối thấp hơn môi trường thật. CPU% của `docker stats` tính trên một nhân (200% = 2 nhân). Mỗi giai đoạn lấy mẫu mỗi khoảng 2 giây; "đỉnh" là mẫu cao nhất.

| Giai đoạn | Kết quả | App: CPU tb/đỉnh, RAM | Postgres: CPU tb/đỉnh, RAM | Redis: CPU tb/đỉnh, RAM |
|---|---|---|---|---|
| Nghỉ, không tải | | 0%, 181 MB | 1%/4%, 58 MB | 0%, 6 MB |
| Import 1 triệu dòng | 997.588 dòng trong **45 giây** (khoảng 22.000 dòng/s) | 22%/102%, 140–181 MB | 42%/99%, 419–602 MB | 0%, 5 MB |
| Check, 16 kết nối, 10% trúng | **10.387 request/s**, p50 1,13 ms, p99 7,3 ms | 118%/172%, 57–143 MB | 41%/73%, 674–722 MB | 29%/46%, 13–17 MB |
| Check, 64 kết nối, 10% trúng | **14.443 request/s**, p50 3,7 ms, p99 13,1 ms | 167%/198%, 55–56 MB | 40%/58%, 721–728 MB | 39%/49%, 25–31 MB |
| Check, 128 kết nối, 10% trúng | 12.422 request/s, p50 8,5 ms, p99 30,0 ms | 169%/196%, 60–61 MB | 36%/48%, 729 MB | 41%/50%, 37–42 MB |
| Check, 64 kết nối, 50% trúng | 9.971 request/s, p50 5,5 ms, p99 15,0 ms | 170%/194%, 58–59 MB | 90%/114%, 729–730 MB | 49%/63%, 63–79 MB |
| Batch 100 mục, 32 kết nối | 1.002 request/s = **100.195 mục/s**, p50 31,7 ms, p99 42,8 ms | 169%/194%, 64 MB | 90%/122%, 790–797 MB | 27%/35%, 114–138 MB |

Tất cả request đều trả 200, không có lỗi.

**Cách đọc:**
- **Điểm nghẽn là CPU của app:** ở 64 kết nối app dùng 167% trên trần 200% (2 nhân), trong khi Postgres chỉ dùng khoảng 40% của một nhân. Thêm kết nối (128) không tăng thông lượng, chỉ tăng độ trễ, vì app đã chạm trần CPU.
- **Khi nhiều request trúng blacklist (50%)** Postgres tăng lên khoảng 90–114% của một nhân và thông lượng giảm còn khoảng 10.000 request/s, đúng với việc các request trúng phải xuống DB.
- **RAM rất nhỏ:** app khoảng 55–65 MB khi chạy (181 MB là mẫu lúc khởi động và import). Postgres khoảng 730–800 MB với 1 triệu dòng (phần lớn là cache của chính Postgres, trần 2 GB còn rộng). Redis từ 5 đến 138 MB, tăng khi lưu cache kết quả batch.
- **Import 1 triệu dòng** dùng tối đa khoảng 600 MB RAM Postgres và 1 nhân app; RAM app không tăng theo kích thước file nhờ import theo lô.
- Nhiễu giữa các lần chạy trên máy này khoảng ±30%; chỉ dùng để so sánh tương đối, không làm SLA.


### Rekey và migration URL ở 9,76 triệu dòng (2026-11-12)

Dữ liệu tổng hợp 9.760.071 dòng (khoảng 30% URL, 2.999.809 entry URL), Postgres trong Docker cấu hình mặc định (`shared_buffers` 128 MB), chạy trên một máy.

| Việc | Kết quả |
|---|---|
| Quét migration URL lúc khởi động | 11,8 s (khởi động xong sau 16,3 s); không entry nào cần đổi, nên đây là chi phí quét, không phải chi phí ghi |
| Bloom rebuild | 9.760.071 mục trong 3,2 s (bộ nhớ đệm ấm); số mục Bloom bằng số dòng DB |
| `rekey -status` | 1,0 s |
| `rekey` thật | 1.744,7 s, 1.953 lô, 5.600 dòng/s, 0 dòng bị bỏ qua, sau đó 100% dòng ở khóa phiên bản 2 |

**Nhận xét:** rekey ở 9,76 triệu dòng chậm hơn trên mỗi dòng khoảng 6 lần so với 1 triệu dòng (36.800 dòng/s), do bị giới hạn bởi I/O khi bảng lớn hơn bộ nhớ đệm. Vì vậy không được ngoại suy tuyến tính; với 100 triệu dòng cần đo riêng. Chưa đo migration URL khi hàng triệu entry thực sự cần đổi.

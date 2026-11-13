# Báo cáo tổng hợp: Debug, Loadtest, Tấn công API public

> Báo cáo này phản ánh đúng trạng thái code hiện tại. Mỗi mục ghi rõ đã làm, đã kiểm chứng bằng gì, và còn lại gì.
> Chi tiết theo từng lần thử nằm ở [ATTACK_PUBLIC_API.md](ATTACK_PUBLIC_API.md) (tấn công) và [LOADTEST_CLAUDE.md](LOADTEST_CLAUDE.md) (loadtest).

---

## 0. Tóm tắt

### Ba nhiệm vụ

| # | Nhiệm vụ | Trạng thái |
|---|---|---|
| 1 | Debug, tìm lỗi nghiêm trọng và vá | Xong. Đã vá C1 đến C5, M1 đến M10 và A1. |
| 2 | Loadtest các API hotpath, có số liệu đo trên máy | Xong. Đã tìm điểm nghẽn và đo trước và sau khi sửa. |
| 3 | Tấn công API public, đề xuất phòng chống | Xong. Đã thử 10 kịch bản, vá các lỗi phát hiện được. Mọi đề xuất đều đã có trạng thái (mục 3.6). |

### Bảng mã lỗi

| Mã | Vấn đề | Trạng thái | Nơi xem |
|---|---|---|---|
| C1 | Changefeed kẹt âm thầm khi có transaction mở lâu, Bloom bỏ sót entry mới | Đã vá | 1.1 |
| C2 | Import chạy trong một transaction duy nhất | Đã vá | 1.2 |
| C3 | Export bị ngắt giữa chừng thì không có audit | Đã vá | 1.3 |
| C4 | Xoay khóa mã hóa làm hỏng dữ liệu | Đã vá | 1.4 |
| C5 | `ORDER BY xid` sắp theo chữ, bỏ sót dòng (phiên khác phát hiện) | Đã vá | 1.1 |
| A1 | API key giả gây tải Postgres không giới hạn | Đã vá | 3.2 |
| M1 | Batch chỉ trừ 1 token rate limit dù có 100 mục | Đã vá | 3.3 |
| M2 | Không có timeout đọc và ghi, đọc body trước khi xác thực | Đã vá | 1.5 |
| M3 | `/metrics` và `/readyz` công khai | Đã vá | 1.5 |
| M4 | `clientIP` bỏ qua proxy, throttle khóa chung cả nhóm | Đã vá | 1.5 |
| M5 | Inspector không che giá trị trong body JSON | Đã vá | 1.5 |
| M6 | Docker compose mở Redis và Postgres ra mọi interface | Đã vá | 1.5 |
| M7 | Cache trả entry đã hết hạn tới hết `CACHE_TTL` | Đã vá | 1.5 |
| M8 | Panic trong `CheckBatch` làm sập process | Đã vá | 1.6 |
| M9 | Path URL không chuẩn hóa (hoa/thường, `..`, `%xx`, ...) | Đã vá, có migration dữ liệu | 1.7 |
| M10 | Số điện thoại nội địa nước khác dùng `DEFAULT_REGION` cố định | Đã vá | 1.5 |

### Còn lại, cần biết
- Throttle đăng nhập: kẻ tấn công gửi trên 30 lần sai từ nhiều IP vẫn làm một email bị khóa 15 phút. Ngưỡng này đã cao hơn nhiều so với trước, nhưng vẫn có thể bị lạm dụng.
- Giới hạn tốc độ dùng chung qua Redis đã có, đã thử với 5 instance trên cùng một máy (mục 3.6). Chưa thử nhiều máy thật sau load balancer.
- `gosec`: 36 phát hiện, đã xử lý. Lỗi thật đã sửa; phần chủ ý được đánh dấu `#nosec` kèm lý do (mục 4.6). `govulncheck` đã chạy và đã nâng phụ thuộc.
- Chưa có TOTP/2FA cho admin.
- Loadtest trong Docker (app 2 CPU/1 GB, Postgres 4 CPU/2 GB, Redis 1 CPU/256 MB, 1 triệu dòng) đã đo CPU và RAM từng thành phần; khởi động lạnh ở 9,57 triệu dòng cũng đã đo (xem LOADTEST_CLAUDE.md). Theo yêu cầu của sếp, không cần chạy 100 triệu dòng.
- Chênh lệch 1% giữa số mục Bloom (9.664.917) và số dòng DB đo được ở 9,57 triệu dòng: **đã kiểm chứng, không phải lỗi Bloom**. Ở 1 triệu dòng, số dòng DB trước khi tắt, sau khởi động và `items` của Bloom đều là 997.588 (khớp tuyệt đối). Khi khởi động lạnh `items` bằng đúng số dòng quét được (không có hash cộng thêm). Chênh lệch ở 10 triệu dòng nhiều khả năng do lần đếm DB lấy sớm hơn một lô import (khoảng 95.000, cỡ lô 100.000); chưa chạy lại ở 10 triệu dòng để xác nhận trực tiếp.
- **Chưa commit**: 79 mục thay đổi (56 file sửa, 23 file hoặc thư mục mới), trộn việc của nhiều phiên. Cần tách commit theo từng việc và có review.

---

## 1. Nhiệm vụ 1: Debug và vá lỗi

### Cách làm
Đọc toàn bộ code Go, sau đó **tái hiện từng lỗi bằng một lệnh cụ thể** trước khi tin nó có thật. Sửa xong thì chạy lại đúng lệnh đó để thấy kết quả chuyển từ sai sang đúng. Chỉ đọc code thì dễ đoán sai; sửa mà không đo lại thì không biết đã hết lỗi chưa.

### 1.1 C1 và C5: changefeed và thứ tự xid

**Lỗi C1.** `ChangesSince` chỉ đọc các dòng có `xid < xmin` (điểm an toàn chung). Khi một transaction mở lâu giữ `xmin` lại, mọi dòng mới hơn cũng bị chặn theo, nên entry mới không vào được Bloom filter. Hậu quả: `/v1/check` trả "an toàn" cho số đã bị chặn, còn `/readyz` vẫn báo ready.

**Cách vá.**
- `ChangesSince` không còn lọc theo `xmin` trong `WHERE`. Thay vào đó trả thêm cờ `Pending` (xid ≥ xmin), tính trong cùng một snapshot.
- `Feed.SyncNow` nạp mọi dòng vào Bloom ngay. Thêm vào Bloom là idempotent, nên sớm thì vô hại; chỉ bỏ sót mới hại. Con trỏ chỉ đi qua dòng đã an toàn.
- Epoch cache được tính từ trạng thái đã thấy (dấu vân tay của đuôi), để cache âm cũ không sống sót khi dữ liệu đổi.
- Trần đuôi 1 triệu dòng; vượt trần thì `/readyz` báo lỗi. `/readyz` chỉ cảnh báo khi đuôi tồn tại quá 30 giây, vì Bloom vẫn đúng.

**Kiểm chứng.** Transaction treo: `check B` từ sai (false) thành đúng (true). Đuôi 1 triệu dòng: thời gian thêm một entry từ khoảng 32 giây xuống 0,6 đến 1,7 giây. Hai instance: ba khóa cache có ba epoch khác nhau.

**Lỗi C5.** `ORDER BY xid` trong truy vấn có cột kết quả `xid::text`, nên sắp theo chữ: `100` đứng trước `99`. Con trỏ nhảy qua 99 và dòng đó bị bỏ sót vĩnh viễn. Sửa thành `ORDER BY change_log.xid, change_log.seq`. Test tích hợp `TestChangesSinceOrdersXIDNumerically` đỏ trên bản cũ và xanh sau khi sửa.

### 1.2 C2: import trong một transaction

**Lỗi.** Import giữ một transaction suốt cả file (giới hạn job 2 giờ), nên giữ `xmin` lại suốt thời gian đó. Không có tiến độ, và lỗi ở phút cuối làm mất hết.

**Cách vá.** `Store.ImportWith` chia thành lô 100.000 dòng hoặc 32 MB. Mỗi lô được đọc, kiểm tra và mã hóa trong bộ nhớ trước, rồi ghi trong một transaction ngắn cùng các dòng `change_log`. Audit ghi hai dòng: `entry.import.start` và `entry.import` (kết quả done hoặc failed). Lỗi giữa chừng giữ các lô đã commit, và chạy lại file là an toàn.

**Đo.**

| Kịch bản | Tuổi transaction dài nhất | Ghi chú |
|---|---|---|
| 1 triệu dòng | 21,8 s (bản cũ) → 1,1 s (bản mới) | |
| 5 triệu dòng | bản mới 8,0 s; bản cũ không đo, suy ra khoảng 100 s (theo tỉ lệ 1 triệu ≈ 20 s, chưa kiểm chứng) | RAM đỉnh 219 MB, không tăng theo kích thước file |
| 2 import song song cùng một file | không đo tuổi transaction | 0 deadlock; số "thêm mới/cập nhật" bị lệch vì đếm trùng trước khi upsert (dữ liệu vẫn đúng) |

Cỡ lô 100.000 được chọn bằng đo: chậm hơn một lô duy nhất khoảng 16%, đổi lại transaction chỉ vài giây.

### 1.3 C3: audit export

`exportCSV` ghi `entry.export.start` trước khi stream. Nếu không ghi được audit thì từ chối export. Dòng `entry.export.end` dùng `context.WithoutCancel` (để vẫn ghi được khi client ngắt), kèm `rows` và `status` (`complete`, `aborted` hoặc `failed`).

**Kiểm chứng.** Ngắt curl giữa chừng: audit `aborted` với 10.000 dòng. Export đủ: `complete` với 299.769 dòng.

### 1.4 C4: xoay khóa mã hóa

**Lỗi.** Dữ liệu được mã hóa bằng một khóa duy nhất, `key_version` có nhưng không dùng để chọn khóa. Đổi `DATA_KEY` làm `/v1/check` và trang admin trả HTTP 500 với các giá trị đang bị chặn. Đổi nhầm `DATA_PEPPER` còn tệ hơn: mọi tra cứu trượt và giá trị bị chặn bị báo là an toàn, không có lỗi nào.

**Cách vá.**
- Keyring theo phiên bản (`DATA_KEY_V<n>`). Mỗi dòng có một `key_version` cho cả ba cột mã hóa.
- `VerifyKeys` chạy lúc khởi động trên mẫu 125 dòng. Thiếu khóa cũ, sai khóa hoặc sai pepper thì server từ chối khởi động và nói rõ cần sửa gì.
- `cmd/rekey` (`-status`, `-dry-run`, chạy thật) mã hóa lại các dòng cũ theo cụm. Chạy được khi server đang chạy và chạy lại được sau khi bị gián đoạn.
- Phiên này cũng sửa một lỗi tiềm ẩn do chính mình viết ở migration M9 (chỉ mã hóa lại `value_enc`).

**Kiểm chứng.** Bản cũ đổi `DATA_KEY`: `/v1/check` HTTP 500. Bản mới thiếu khóa cũ: từ chối khởi động. Có khóa cũ: dữ liệu đọc được; `rekey` 1 triệu dòng mất 27,2 s (khoảng 36.800 dòng/giây), 9,76 triệu dòng mất 1.744,7 s (khoảng 5.600 dòng/giây, đã đo, 0 dòng bị bỏ qua; chậm hơn trên mỗi dòng khoảng 6 lần so với 1 triệu dòng, nên ước lượng tuyến tính cũ không đúng); `VerifyKeys` mất 38 ms.

### 1.5 Nhóm M2 đến M7 và M10

| Mã | Sửa gì | Kiểm chứng |
|---|---|---|
| M2 | `ReadTimeout` 30 s, `WriteTimeout` 60 s. Import nới đọc tới 10 phút; export đặt lại hạn ghi sau mỗi lô. `instrument` không đọc body trước xác thực cho `/v1`. | Gửi body từng byte mỗi 2 giây: server cắt sau 32 giây. Import 13 MB và export 300.000 dòng vẫn chạy. |
| M3 | `/metrics` cần `Bearer METRICS_TOKEN`; không đặt token thì chỉ nhận loopback. `/readyz` chỉ hiện chi tiết lỗi với loopback. | Không token: 401. Đúng token: 200. Từ IP ngoài không token: 403. |
| M4 | `TRUSTED_PROXIES` (CIDR, mặc định rỗng). Chỉ đọc `X-Forwarded-For` khi kết nối đến từ proxy tin cậy, duyệt từ phải sang trái. Throttle đăng nhập dùng cặp `email|IP`. | 22 lần sai từ IP A bị 429; IP B cùng proxy vẫn đăng nhập được. 9 ca unit test cho XFF. |
| M5 | Inspector che các trường JSON `value`, `q`, `phone`, `url`, `number`, `domain`, `host` (giữ 3 ký tự đầu). Body của `/v1` không còn được lưu, nên đường public không lộ gì. | Test đỏ khi bỏ fix. Trên server: không thấy giá trị gốc trong feed inspector. |
| M6 | Compose bind Postgres và Redis vào `127.0.0.1`. Redis có `requirepass` (`REDIS_PASSWORD`). | `redis-cli` không mật khẩu trả `NOAUTH`. |
| M7 | Cache lưu thêm thời điểm hết hạn của entry khớp. Cache hit sau thời điểm đó bị bỏ qua và truy vấn lại DB. | Test đỏ khi bỏ fix, xanh khi có fix. |
| M10 | Tham số `region` tùy chọn cho `/v1/check` và batch (cấp top-level và từng mục). Mã vùng sai trả 400. | Số `2025550123`: mặc định VN ra `+842025550123` (sai); `region=US` ra `+12025550123`. |

**Throttle đăng nhập theo email.** Khóa theo cặp `email|IP` (5 lần/15 phút), cộng giới hạn rộng theo email (30 lần/15 phút) để chặn dò mật khẩu từ nhiều IP. Kiểm chứng: kẻ tấn công bị 429 không làm admin bị khóa từ IP khác; 30 lần sai từ các IP khác nhau thì lần thứ 31 bị 429.

### 1.6 M8: panic trong `CheckBatch`

`CheckBatch` chạy mỗi mục trong một goroutine, và `chimw.Recoverer` không bắt được panic ở goroutine đó. Một đầu vào lạ có thể làm sập cả process. Sửa: `checkItem` có `recover` riêng cho từng mục. Mục bị panic trả `internal error`, các mục khác vẫn đúng, và bộ đếm `vsf_check_panics_total` tăng.

### 1.7 M9: chuẩn hóa path URL

**Lỗi.** `host` được hạ chữ thường nhưng `path` thì không. `evil.com/SecurePath` không khớp `EVIL.COM/SECUREPATH`, `evil.com//securepath/./x` hay `evil.com/%73ecurepath/x`.

**Cách vá.** `canonicalPath` theo RFC 3986 mục 6.2.2: giải mã ký tự không bảo lưu, bỏ dot-segment, gộp `//`, hạ chữ thường toàn bộ path. Giữ nguyên `%2f` và query. Việc hạ chữ thường là lựa chọn có chủ đích: hai trang chỉ khác hoa/thường trên cùng host bị coi là một. Migration `005_url_path_canonical` chạy một lần lúc khởi động. Nó chuyển các entry cũ và gộp các cặp va chạm (giữ entry có risk cao hơn), có audit, và chạy lại được.

**Đo.** Migration 1 triệu entry (tổng hợp, 90% cần đổi): 118 giây; chạy lại 2,8 giây. Chi phí `Candidates` không đổi trong nhiễu. Vì migration chặn khởi động, ở 9,76 triệu dòng (khoảng 3 triệu entry URL, không entry nào cần đổi) bước quét mất 11,8 s và khởi động xong sau 16,3 s (đã đo); trường hợp xấu nhất (hàng triệu entry cần đổi) chưa đo, ước lượng khoảng 20 phút cho 10 triệu entry là suy ra từ mẫu 1 triệu.

### 1.8 Cách làm: đo trước, sửa, đo lại
Mỗi lỗi được tái hiện bằng test đỏ hoặc kịch bản chạy thật trước khi sửa. Có vài lần bản đầu chậm hoặc sai và phải làm lại: migration M9 từng chạy 773 entry/giây trước khi viết lại theo cụm; `ORDER BY` sai được phát hiện khi đọc `EXPLAIN ANALYZE`. Các số trong báo cáo là số đo, trừ khi có ghi chú là suy ra.

---

## 2. Nhiệm vụ 2: Loadtest các API hotpath

### Điểm nghẽn chính: Postgres, không phải code Go
`FindMatches` join bảng 32 partition bằng `JOIN unnest(...)`. Postgres lập kế hoạch lại qua mọi partition ở mỗi lần gọi (khoảng 1 đến 2 ms lập kế hoạch cho 0,1 đến 0,24 ms thực thi). Đổi sang `value_hash = ANY(...) AND value_blind = ANY(...)` để Postgres cắt partition lúc lập kế hoạch. Sau đó kiểm tra lại từng bộ khóa ở Go, vì `ANY` so từng cột độc lập; có test chứng minh không ghép chéo hai khóa.

| Kịch bản (xen kẽ bản cũ và bản mới, cùng máy) | RPS cũ → mới | Hệ số |
|---|---|---|
| 16 kết nối, 10% trúng | 15.078 → 25.260 | ×1,68 |
| 64 kết nối, 10% trúng | 16.332 → 20.390 | ×1,25 |
| 64 kết nối, 20% trúng | 11.952 → 18.562 | ×1,55 |
| 64 kết nối, 50% trúng | 5.676 → 14.158 | ×2,49 |

Càng nhiều request phải xuống DB, cải thiện càng lớn, đúng với nguyên nhân.

### Phát hiện phụ: tỉ lệ trúng cache bị đo sai
`cmd/bench` dùng seed cố định, nên mỗi lượt chạy lại đúng một dãy khóa và "trúng cache" là giả. Sửa: seed lấy theo thời gian (mặc định), thêm phân bố Zipf (khóa nóng, gần lưu lượng thật hơn), và tính tỉ lệ trúng qua metrics. Với phân bố đều, cache nguội chỉ trúng khoảng 2,6%. Chỉ với khóa nóng mới đạt 70% trở lên.

### Quyết định về các phương án khác
- `plan_cache_mode = force_generic_plan` cho cả pool: **không áp dụng**. Sau khi viết lại `FindMatches`, kế hoạch truy vấn này không còn là điểm nghẽn; thiết lập này tăng khoảng 4 lần so với khoảng 8,6 lần của cách đã làm, và áp lên mọi câu SQL khác nên có rủi ro làm chậm chúng.
- Giảm số partition từ 32: **không làm**. Cần migration dữ liệu lớn, rủi ro cao, trong khi điểm nghẽn đã được xử lý bằng cách khác.

---

## 3. Nhiệm vụ 3: Tấn công API public

### 3.1 Phạm vi và cách làm
Dựng một server thử riêng (không đụng server thật) với xác thực bật thật. Thử 10 kịch bản trên `/v1/check`, `/v1/check/batch`, `/healthz`, `/readyz` (không thử `/admin`):

1. Bỏ qua xác thực.
2. Dò API key bằng thời gian phản hồi.
3. Vượt rate limit bằng batch.
4. Input không hợp lệ và fuzzing.
5. Giới hạn batch.
6. Dò trạng thái blacklist qua thời gian phản hồi.
7. Header injection, CORS, tải trọng thất thường.
8. Tải dồn có kiểm soát.
9. Header bảo mật trên API public.
10. Dò lỗi 500 và rò thông tin.


### 3.2 A1: API key giả gây tải Postgres không giới hạn (phát hiện ngoài kế hoạch)

**Phát hiện.** Khi thử kịch bản 1, nhận ra bộ giới hạn tốc độ chỉ chạy sau khi xác thực thành công, nên request xác thực sai không bị giới hạn ở đâu cả.

**Khai thác.** Cache "key không tồn tại" lưu theo 8 ký tự đầu. Kẻ tấn công đổi 8 ký tự ngẫu nhiên mỗi lần, nên mọi request trượt cache và buộc tra Postgres.

**Đo trước khi vá.** 12.434 request/giây tới Postgres, CPU Postgres khoảng 201%. Khách hợp lệ chạy song song giảm 24% thông lượng, dù không cần key hợp lệ nào.

**Sửa.** `allowLookup(ip)`: giới hạn tra cứu DB theo IP, đặt ngay trước lệnh truy vấn DB (chỉ khi cache trượt). Không đặt ở ngoài `apiAuth`, vì khi đó một IP NAT dùng chung có thể bị chặn oan.

**Kết quả.**

| Chỉ số | Trước | Sau |
|---|---|---|
| CPU Postgres khi bị tấn công | ≈201% | ≈0,35% |
| Request tấn công chạm được DB | 100% | 0,07% (49 trên 67.842) |
| Khách hợp lệ khi bị tấn công song song | −24% | −11% (phần còn lại do máy thử dùng chung CPU) |

**Giải pháp tốt hơn (đã làm, mục 4.2).** Bộ giới hạn ban đầu nằm trong bộ nhớ của từng instance, nên kẻ tấn công có thể trải request qua nhiều instance. Đã chuyển sang token bucket trên Redis (Lua nguyên tử), dùng chung cho mọi instance.

### 3.3 M1: batch chỉ trừ 1 token

**Lỗi.** `Allow()` của `golang.org/x/time/rate` luôn trừ 1 token, không quan tâm số mục trong batch.

**Đo trước khi vá.** Key `rps_limit=10`, batch 100 mục: đạt 1.300 mục/giây, gấp 130 lần giới hạn khai báo.

**Sửa.** Dùng `AllowN(now, units)` với `units` là số mục. Vì `burst = rps_limit`, batch lớn hơn `rps_limit` luôn bị chặn, nên thêm cột `max_batch` cho từng key (mặc định 0 = hành vi cũ). Burst của key là `max(rps_limit, max_batch)`, tốc độ duy trì vẫn đúng `rps_limit`. Đo 20 giây: 209 mục với `max_batch=0`, 299 mục với `max_batch=100`, chênh đúng một lần burst.

**Kết quả.** Batch 100 mục, `rps_limit=10`: 0 mục qua (100% bị 429), trước là 1.300 mục/giây. Đối chứng `rps_limit=200`: 233 mục/giây, sát cấu hình. Nhãn trên giao diện tạo key đổi thành "mục/giây".

### 3.4 Path phân biệt hoa/thường
Lỗi này phát hiện lúc tấn công và đã fix

### 3.5 Những gì thử nhưng không lọt
- Bỏ qua xác thực bằng các cách thông thường.
- Dò key bằng thời gian phản hồi: `subtle.ConstantTimeCompare` hoạt động đúng.
- Input dị dạng, JSON lồng sâu 100.000 cấp, body trên 1 MB: bị chặn đúng, không ép được lỗi 500, không rò thông tin nội bộ.
- CORS: không có header mở ngoài ý muốn.
- Tải dồn 512 kết nối đồng thời: không sập.

### 3.6 Đề xuất phòng chống và trạng thái

| Đề xuất | Trạng thái |
|---|---|
| Chuyển giới hạn tốc độ sang Redis để chạy nhiều instance | Đã thử 5 instance trên cùng máy; chưa thử nhiều máy thật. |
| Chuẩn hóa path (hoa/thường) | Đã fix |
| Kiểm tra độ dài input trước khi echo lại | Đã có: URL tối đa 2.048 ký tự, SĐT tối đa 32 ký tự, kiểm tra trước khi xử lý |
| Metric `auth_rate_limited` để phát hiện dò quét | Đã có trong `api.go` |
| M2 đến M10 còn lại | Đã fix |

**Đã thử lại 2026-11-12** sau các bản vá, cùng 10 kịch bản: xem [ATTACK_PUBLIC_API.md](ATTACK_PUBLIC_API.md), mục "Lần thử lại 2026-11-12". Kết quả khớp với các bản vá: batch vượt giới hạn đạt 0 mục/s; 2.962 trên 3.000 key giả bị chặn 429; fuzzing không có lỗi 5xx. Đã thử thêm slowloris thật (header đóng sau 5,0 giây, body sau 31,0 giây), upload gửi chậm 43 giây được chấp nhận, và C1/C2 qua API khi có transaction mở (xem phần bổ sung trong ATTACK_PUBLIC_API.md).

---

## 4. Các đợt sửa khác

Các mục dưới đây do một phiên khác thực hiện. Mình đã đối chiếu với code và chạy lại các test liên quan; đều xanh.

**4.1 Chuẩn hóa URL v2.** Dấu `\` thành `/` (kể cả ngay sau scheme), bỏ tham số `;jsessionid=...` khỏi từng segment, nhận diện host IP dạng thập phân, hex và bát phân. Kiểm chứng bằng test bảng nhiều ca, kiểm tra idempotent, test migration trên Postgres, và thử qua `/v1/check` trên một instance khác. Đợt 2026-11-12 bổ sung: host IP được chuẩn hóa (IPv6 viết gọn và hạ chữ thường, IPv4-mapped về IPv4); entry domain cũng đi qua chuẩn hóa; migration `007_url_canonical_v3` quét thêm entry domain. Có test bảng và test migration.

**4.2 Giới hạn tốc độ dùng chung qua Redis.** Token bucket bằng Lua nguyên tử trên Redis, thời gian lấy từ `TIME` của Redis. Dùng cho giới hạn theo key (A1, M1 và trừ theo số mục batch) và giới hạn tra cứu theo IP. Redis lỗi hoặc quá 50 ms thì cho qua (fail-open) và đếm metric, không quay về bộ đếm cục bộ.
- Đo 3 instance, `rps_limit=10`, 90 request song song: Redis dùng chung cho đúng 10 request 200 mỗi lần; không Redis (mỗi instance một bộ đếm) cho 30. Giới hạn không còn bị nhân với số instance.
- Cái giá: throughput giảm khoảng 55% (≈41.000 xuống ≈19.500 rps), p50 tăng khoảng 1,9 ms, p99 gần như không đổi. Đo trong Docker (xem LOADTEST_CLAUDE.md): ở 14.443 request/s Redis chỉ dùng khoảng 39% của một nhân và 25 MB RAM, nên chi phí chấp nhận được. Cách giảm thêm (lấy trước một lô token) làm giới hạn kém chính xác khi có nhiều instance, nên **không áp dụng**.

**4.3 Đăng nhập.** Thiết bị tin cậy: sau đăng nhập đúng, cookie HttpOnly `vsf_device` (chữ ký HMAC theo email, 30 ngày) cho phép bỏ qua giới hạn rộng theo email. Mật khẩu vẫn phải đúng. Làm chậm dần: từ lần sai thứ 10 của một email, thiết bị lạ phải chờ thêm 0,5 giây nhân số lần vượt, tối đa 5 giây; thiết bị tin cậy không bị chậm. Cảnh báo: log mức Error và metric `vsf_login_attack_suspected_total` tăng đúng một lần khi một email chạm 10 lần sai. TOTP/2FA là một tính năng mới (bảng dữ liệu, giao diện đăng ký thiết bị, mã dự phòng) nên không gộp vào đợt vá này; cần quyết định sản phẩm.

**4.4 Xoay `DATA_PEPPER`.** Lệnh `cmd/rotate-pepper` và `store.RotatePepper`. Đây là thao tác offline: phải dừng mọi instance, vì server chạy pepper cũ không tìm thấy dòng đã xoay và sẽ báo số bị chặn là an toàn. Lệnh từ chối chạy nếu pepper cũ sai. Trên 299.775 dòng: dry-run 0,76 giây, xoay thật 6,1 giây, chạy lại là no-op. Server cấu hình pepper mới trước khi xoay sẽ từ chối khởi động.

**4.5 Thử nhiều instance (3 instance trên cùng máy).** Thay đổi tạo trên instance 1 xuất hiện ở instance 2 và 3 sau 272 đến 635 ms (`POLL_INTERVAL=300ms`). `rekey` 299.775 dòng mất 7,9 giây trong khi 3 instance phục vụ 12 luồng check liên tục: 51.021 request, 0 sai, 0 lỗi. Bloom dựng lại 299.775 mục trong 154 ms. Chưa thử: nhiều máy thật, hơn 3 instance.

**4.6 Quét bảo mật.**
- `govulncheck`: có 1 lỗ hổng chạm tới code (GO-2026-6859, `net/http` MaxBytesReader, sửa ở go1.27.4) và 3 lỗ hổng trong module không được gọi tới. Đã nâng toolchain lên go1.27.4 và nâng `golang.org/x/net`.
- `gosec` (bản mới nhất, 2026-11-12): 36 phát hiện, đã phân nhóm và xử lý. Lỗi thật đã sửa: lỗi khi đóng file upload bị bỏ qua (`admin_import.go`); số cấu hình âm bị ép kiểu thành số rất lớn (`BLOOM_EXPECTED_ITEMS`, `PG_MAX_CONNS`, `RATE_LIMIT_RPS` nay bị từ chối khi khởi động); hash argon2 có khóa bất thường nay bị từ chối trước khi tính; số kết nối pool giới hạn 1..1000. Phần chủ ý (ép kiểu hash giữa int64 và uint64, cookie có `Secure` theo cấu hình, đường dẫn file do server tạo, bộ sinh số giả có seed, một tên cột SQL bị nhận nhầm là bí mật) được đánh dấu `#nosec` kèm lý do ngay trong code. Sau khi sửa: 0 phát hiện chưa xử lý.
- Kết quả rà soát `#nosec` (31 chỗ): 18 `G115` (ép kiểu số nguyên), 4 `G404` (số giả ngẫu nhiên), 3 `G124` (cookie), 2 `G304` (đường dẫn file), 2 `G109`+`G115` (cấu hình), 1 `G101` (nhận nhầm tên cột SQL). Trong đó, `G115` đã được kiểm tra ở phía trên bằng code (khóa phiên bản 1..32767, `risk_score` 0..100, số kết nối 1..1000, độ dài argon2 1..64, số mục Bloom 1..MaxInt32) hoặc là chủ ý đổi cách đọc bit của hash 64 bit giữa `int64` và `uint64`. 6 chỗ ban đầu đã được loại bỏ hẳn bằng cách sửa code (`cmd/rekey` đổi sang kiểu `int16`; `risk_score` kiểm tra trong `riskScore16` thay vì tin người gọi; số liệu cấu hình bị từ chối khi không hợp lệ). `G404` chỉ nằm ở công cụ benchmark/sinh dữ liệu và chọn mẫu kiểm tra khóa, không dùng cho bí mật. `G124` đúng vì `APP_ENV=production` bắt buộc `COOKIE_SECURE=true`. Chưa có người thứ hai đọc lại.

---


**Độ phủ test** (`go test -cover`):

| Package | Độ phủ | Ghi chú |
|---|---|---|
| `checker` | 96% | tra cứu, batch, cache |
| `config` | 93% | |
| `auth` | 88% | |
| `seal` | 89% | |
| `normalize` | 88% | |
| `inspector` | 87% | |
| `bloom` | 84% | |
| `changefeed` | 82% | |
| `apikey` | 76% | |
| `store` | 75% | cần Postgres thật |
| `handler` | 33% | trang admin và luồng HTTP mới được test một phần |
| `cmd/bench` | 26% | công cụ đo |
| `cmd/server` | 10% | khởi động và vòng nền |
| `cmd/rekey`, `cmd/rotate-pepper` | xem mục 9 | Đã có test cho lớp lệnh (rekey 4 test, rotate-pepper 6 test, trên DB thật). |
| `cache`, `metrics`, `model` | 0% | chủ yếu là adapter hoặc khai báo kiểu |


### Rủi ro còn lại
1. **Mất khóa hoặc mất pepper = mất dữ liệu**, không công cụ nào cứu được. Cần sao lưu khóa tách khỏi database và có người chịu trách nhiệm.
4. **Migration khi khởi động** có thể chậm với dữ liệu rất lớn; mới đo ở quy mô 1 triệu entry (tổng hợp).
5. **Phụ thuộc cấu hình production** (đã xử lý 2026-11-12): production từ chối khởi động nếu không khai báo `TRUSTED_PROXIES` hoặc `TRUSTED_PROXIES_NONE=true` (đặt cả hai cũng bị từ chối); `METRICS_TOKEN` nếu có phải ≥ 16 ký tự, để trống thì ghi cảnh báo và `/metrics` chỉ nhận loopback. Mất khóa dữ liệu thì không có cách khôi phục: khi khởi động server in vân tay `DATA_KEY` và `DATA_PEPPER` (8 byte đầu SHA-256, không lộ khóa) để đối chiếu với nơi lưu; vẫn cần người vận hành sao lưu khóa ở nơi tách khỏi bản sao lưu DB.
6. **Throttle đăng nhập** vẫn có thể bị lạm dụng ở mức 30 lần sai từ nhiều IP.

### Việc nên làm tiếp: trạng thái từng việc
| # | Việc | Trạng thái |
|---|---|---|
| 1 | Tách thay đổi thành commit có nghĩa (bảo mật, dữ liệu, test, comment, tài liệu) và review | **Chưa làm**: bạn chọn không commit; cần quyết định cách đưa vào nhánh chính |
| 2 | Chạy CI thật trên GitHub (vet và test trên Postgres 16 và Redis 7) | File `.github/workflows/ci.yml` **đã viết** và đúng cú pháp; **chưa chạy** vì chưa đẩy lên GitHub |
| 3 | Rà soát các chỗ `#nosec` có lý do đúng | **Đã rà soát nội bộ**: kiểm tra từng chỗ so với code xung quanh; 31 chỗ còn lại đều có điều kiện nêu trong lý do và được code bảo đảm (xem mục 4.6). Việc người thứ hai đọc lại vẫn nên làm trước khi phát hành |
| 4 | Thử nhiều máy thật sau load balancer | **Không làm được** trên máy này; đã thử 5 instance trên một máy |
| 5 | Đo migration URL và rekey với dữ liệu vài triệu đến vài chục triệu dòng | **Làm một phần**: rekey 1 triệu dòng 27 giây, migration URL 1 triệu entry 118 giây (tổng hợp), khởi động lạnh 9,57 triệu dòng đã đo; **đã đo ở 9,76 triệu dòng**: rekey 1.744,7 s (5.600 dòng/s), quét migration URL 11,8 s, Bloom rebuild 3,2 s (nguội 31 s); chưa đo migration URL khi hàng triệu entry cần đổi |

Đã làm: test cho `cmd/rekey` và `cmd/rotate-pepper`; xử lý `gosec`; file CI; thử lại 10 kịch bản tấn công; thử 5 instance trên một máy; loadtest Docker (CPU, RAM từng thành phần); chuẩn hóa IPv6 và migration 007. Tải một instance (199.895 dòng): 11.404 request/s ở 16 kết nối và 17.639 request/s ở 64 kết nối, không lỗi (chi tiết trong ATTACK_PUBLIC_API.md và LOADTEST_CLAUDE.md).

---

## 6. Lưu ý khi chạy test
- Gói `store` dùng chung database `TEST_DATABASE_URL` (ví dụ `vsf_test`) và có test làm rỗng các bảng. **Không chạy hai phiên test cùng lúc trên cùng một database.**
- Gói `handler` (đăng nhập) tạo database tạm riêng cho cả gói, tự xóa khi xong. Cần user có quyền `CREATE DATABASE`; thiếu quyền thì test Skip kèm lý do.
- Gói `handler` chạy riêng khoảng 2 đến 3 giây. Gói `store` khoảng 30 đến 40 giây.

---

## 7. Kiến thức nền

**Transaction, xid và xmin.** Mỗi transaction có một `xid` tăng dần. `xmin` là xid nhỏ nhất mà hệ thống coi là còn có thể đang chạy; mọi xid nhỏ hơn đã xong. Lọc theo `xid < xmin` là cách an toàn để không đọc transaction chưa xong, nhưng một transaction cũ giữ `xmin` lại sẽ chặn mọi thứ mới hơn. Mọi cơ chế dựa vào "điểm an toàn chung" đều có rủi ro này.

**Token bucket.** Xô có dung tích `burst`, được rót `rps` token mỗi giây. Một việc lấy ra N token. Thiếu token thì bị từ chối, không có chuyện "cho một nửa". Nếu `burst` nhỏ hơn N thì việc đó không bao giờ được chấp nhận. Luôn hỏi: một lần gọi thực sự tốn bao nhiêu đơn vị việc?

**Planning và execution trong Postgres.** Mỗi câu SQL có bước lập kế hoạch (chọn index, chọn partition) và bước thực thi. Với bảng partition, nếu câu SQL không cho Postgres thấy giá trị lúc lập kế hoạch thì nó phải cân nhắc mọi partition. `EXPLAIN ANALYZE` cho biết bước nào tốn thời gian.

**Bloom filter.** Trả lời "chắc chắn không có" hoặc "có thể có". Không bao giờ bỏ sót hash đã thêm (không có false negative), nhưng có thể dương giả. Vì chỉ thêm và không xóa, thêm sớm hay thêm hai lần đều vô hại; chỉ bỏ sót mới hại.

**So sánh hằng thời gian.** `subtle.ConstantTimeCompare` so sánh không phụ thuộc vị trí byte khác nhau, nên không lộ thông tin qua thời gian phản hồi. Muốn biết có lộ thật không thì phải đo, vì đọc code không đủ.

**Vòng phản hồi trước khi sửa.** Không tin một lỗi tồn tại cho đến khi tái hiện được bằng một lệnh cụ thể. Sau khi sửa, chạy đúng lệnh đó và thấy kết quả chuyển từ sai sang đúng. Benchmark có seed cố định cũng là một cách tự lừa mình: nó cho kết quả đẹp nhưng không phản ánh lưu lượng thật.

---

## 8. File liên quan

| File | Nội dung |
|---|---|
| [ATTACK_PUBLIC_API.md](ATTACK_PUBLIC_API.md) | Nhật ký tấn công từng kịch bản, số liệu, và các lần vá |
| [LOADTEST.md](LOADTEST.md) | Số liệu loadtest đầy đủ |
| `README.md` | Biến môi trường, quy trình xoay khóa và xoay pepper |

## 9. Nâng độ phủ test (coverage)

Đo bằng `go test -p 1 -count=1 -coverprofile ./...` trên một database riêng `vsf_cov_test` (để không dính phiên khác) và Redis thật. Tất cả test xanh, `go vet` sạch. Bảng dưới là số đo sau vòng hai (đã thêm test cho các nhánh lỗi).

| Gói | Ban đầu | Vòng 1 | Vòng 2 | Ghi chú |
|---|---|---|---|---|
| `internal/handler` | 32,6% | 81,7% | **84,3%** | Bộ test HTTP tích hợp: dựng app đầy đủ (Postgres thật, Bloom, changefeed, checker, API key, Router thật) và gọi qua HTTP |
| `internal/store` | 74,8% | 80,6% | **82,1%** | Thêm đường chuyển bảng plaintext cũ và xác minh mẫu |
| `cmd/bench` | 26,2% | 95,8% | **95,1%** | Tách `run(args, out)`; test với server giả |
| `cmd/server` | 9,8% | 76,4% | **85,4%** | Tách `serve(ctx, stop, log)`; thêm test các nhánh lỗi lúc khởi động |
| `cmd/rekey` | 0% | 85,5% | **76,8%** | Tách `run(args)`; test đầu cuối trên database riêng. Số giảm so với vòng 1 vì tôi thấy mã nguồn của gói này đã đổi giữa hai lần đo (do phiên khác), chưa xem lại |
| `cmd/rotate-pepper` | 0% | 84,0% | **80,0%** | Như trên |
| `internal/cache`, `metrics`, `model` | 0% | 100% / 100% / 100% | **100%** mỗi gói | |
| Toàn repo | | 83,1% | 84,6% (vòng 3: 86,0%; vòng 4: **86,8%**, xem bên dưới) | |

### Vòng 2: những gì đã thêm
- **`cmd/server`**: server từ chối khởi động khi `DATA_KEY` sai so với dữ liệu đã lưu; replica không kết nối được; mật khẩu bootstrap quá ngắn; cổng đã bị chiếm; và vẫn khởi động, vẫn trả lời check khi Redis chết (giới hạn và cache cho qua).
- **`store`**: chuyển bảng plaintext cũ ở quy mô đủ lớn để bước xác minh lấy mẫu thật sự chạy (2.100 dòng): dữ liệu và sequence giữ nguyên, dòng audit cũ bị xóa bản rõ, dòng audit đã nối chuỗi hash giữ nguyên; từ chối chuyển khi chưa có khóa; rollback sạch khi có một dòng không chuyển được; `verifySealed` bắt được thiếu dòng, blind index sai, bản mã hỏng; store không có khóa từ chối mọi thao tác.
- **`handler`**: import hỏng (loại mặc định sai, thiếu cột, dòng sai được báo kèm số dòng); xác minh audit phát hiện một dòng bị sửa trực tiếp trong DB; database chết giữa chừng thì trang quản trị trả 500 không lộ chi tiết, xác thực API trả 503, `/readyz` trả 503, `/healthz` vẫn 200.

### Phép thử đột biến cho bộ test handler
Với mỗi lỗi cố ý chèn vào mã nguồn, chạy lại bộ test và xem có đỏ không:

| Lỗi chèn vào | Kết quả |
|---|---|
| `requireRole` cho mọi vai trò qua | Bị bắt (`TestAppCSRFAndRoles`) |
| CSRF bỏ kiểm tra origin | Bị bắt |
| Tắt `csvSafe` (CSV injection) | Bị bắt |
| Throttle đăng nhập chỉ theo email | Bị bắt (3 test) |
| Key đã thu hồi trả sai mã trạng thái | Bị bắt |
| `/metrics` đảo điều kiện loopback | Bị bắt |
| Cookie thiết bị tin cậy không kiểm chữ ký | Bị bắt |
| Người dùng bị khóa vẫn đăng nhập được | Bị bắt |
| Viewer được export | Bị bắt |
| Trạng thái kết thúc export luôn sai | **Sống sót lần đầu**, đã thêm kiểm tra audit, giờ bị bắt |
| Bỏ region mặc định của batch | **Sống sót lần đầu**, đã thêm ca test region khác mặc định, giờ bị bắt |
| Đăng xuất không hủy phiên phía server | **Sống sót lần đầu** (test cũ chỉ kiểm khi cookie bị xóa phía client), đã thêm ca dùng lại cookie cũ, giờ bị bắt |

### Thay đổi nhỏ trong code để test được
- `cmd/bench`, `cmd/rekey`, `cmd/rotate-pepper`: `main` chỉ gọi `run(args ...)` dùng `flag.NewFlagSet`.
- `cmd/server`: tách `serve(ctx, stop, log)` khỏi `run`; chu kỳ vòng nền thành biến `flushEvery`, `purgeEvery`.
- `cmd/bench`: thêm kiểm tra khi không có request nào được gửi (trước đây có thể panic).
- `internal/metrics.RegisterGauges`: gọi lại được (lần sau thay lần trước) thay vì panic vì đăng ký trùng. Bắt buộc để test khởi động server nhiều lần trong một process; production chỉ gọi một lần nên hành vi không đổi.

### Vòng 3: số đo cuối và những gì đã thêm
Số đo sau vòng 3 (`go test -p 1 -count=1 -coverprofile ./...`, toàn repo **86,0%**): `cmd/server` **92,7%** (từ 85,4%), `handler` **85,5%** (từ 84,3%), `store` **84,2%** (từ 82,1%), `cmd/rotate-pepper` **86,0%**, `cmd/rekey` **78,6%**, `cmd/bench` 95,1%, `cache`, `metrics`, `model` 100%.

- **`cmd/server`**: server dừng với lỗi khi Bloom filter không dựng được (ở đây: bảng `change_log` biến mất nên `feed.Init` lỗi ở bước `Head`), thay vì chạy tiếp với Bloom rỗng; vòng nền vẫn chạy và vẫn dừng được khi database biến mất giữa chừng.
- **`store`**: một bài kiểm tra bảng gồm 38 thao tác công khai trên một Store đã đóng pool. Thao tác nào báo thành công trên database đã mất thì test đỏ. Cả 38 thao tác đều trả lỗi (không panic, không treo).
- **`handler`**: quy tắc người dùng tự sửa mình (không tự khóa, không tự hạ quyền); quy tắc xoay API key (ân hạn 0 ngày hết hạn ngay, giá trị ngoài 0..90 dùng mặc định 7 ngày, key mới kế thừa cấu hình, không xoay hay thu hồi lại key đã thu hồi); `/readyz` báo Bloom chưa dựng và chỉ lộ chi tiết cho loopback; `peerIP`, `sameOrigin`, tên cookie thiết bị.
- **`cmd/rekey`, `cmd/rotate-pepper`**: mã nguồn và các file test chính của hai lệnh này đã được một phiên khác viết lại (tên test khác hẳn bản của tôi ở vòng 1), đó là lý do độ phủ khác vòng 1. Tôi chỉ thêm `errors_test.go` cho mỗi lệnh (cấu hình sai, thiếu `SESSION_SECRET`, database không kết nối được).

### Phép thử đột biến mở rộng ra các gói khác
Chạy trên **bản sao** repo (không sửa repo thật). Mỗi lỗi chèn vào là một thay đổi nhỏ có ý nghĩa bảo mật hoặc đúng đắn:

| Gói | Lỗi chèn vào | Kết quả |
|---|---|---|
| checker | Bỏ qua hạn dùng của kết quả cache | Bị bắt |
| checker | Không kiểm tra region | **Sống sót lần đầu** (xem bên dưới), giờ bị bắt |
| apikey | Limiter Redis luôn cho qua | Bị bắt (3 test, sau đó 5 test) |
| normalize | Giữ `;jsessionid=` | Bị bắt |
| normalize | Không đổi IP thập phân/hex/bát phân | Bị bắt |
| normalize | Chấp nhận số IP tràn | Bị bắt |
| auth | Không so chữ ký cookie thiết bị | Bị bắt |
| auth | Cookie thiết bị không bao giờ hết hạn | Bị bắt |
| handler | Tin `X-Forwarded-For` từ bất kỳ nguồn nào | Bị bắt |
| handler | So token metrics ngược | Bị bắt |
| model | `AtLeast` chấp nhận vai trò không hợp lệ | Bị bắt |
| store | `rekey` ghi lại cả dòng đã ở khóa hiện tại | Bị bắt (3 test) |
| store | Xoay pepper bỏ qua dòng cũ | Bị bắt (3 test) |

Bốn lần chèn đầu tiên không biên dịch được nên không kết luận được; tôi đã viết lại thành các thay đổi biên dịch được và chạy lại. Lỗi sống sót: kiểm tra region trong `checker` chỉ bị bắt khi loại là `url`; với số điện thoại thì trình phân tích số cũng từ chối region lạ nên test cũ xanh. Đã thêm test cho loại `url`.

### Các lỗi test của chính tôi tìm thấy khi chạy lặp
- `TestAppAPIKeysAndCheckAPI` đỏ giả ngẫu nhiên: test chỉ chờ entry số điện thoại hiện trong Bloom mà không chờ entry URL (changefeed nạp từng thay đổi một). Đã thêm chờ; chạy lặp 8 lần đều xanh.
- `TestLoginBackoffSlowsUnknownDevicesOnly` đỏ giả khi máy tải: ngưỡng thời gian tuyệt đối sai vì băm argon2 có lúc tốn gần một giây. Đã đổi sang đếm số lần hàm làm chậm được gọi (thiết bị tin cậy phải là 0), chiều "bị làm chậm" vẫn đo thời gian vì đó là cận dưới.
- Hai test Redis của `apikey` đỏ giả lần nữa trong lần chạy toàn bộ khi máy rất tải (mỗi lời gọi Redis chậm hàng trăm ms nên token nạp lại trong lúc xả). Đã đổi sang key có tốc độ nạp 1 token/giây và assert tính thêm số token đã nạp theo thời gian thật; test tự bỏ qua nếu quá chậm. Chạy lặp 5 lần xanh, và phép thử đột biến vẫn bắt được limiter hỏng.

### Một hành vi thật mà test lộ ra, đã sửa
`UpdateAdmin` trước đây luôn xóa mọi phiên của tài khoản được cập nhật, kể cả khi admin chỉ bấm lưu chính mình mà không đổi gì (người đó bị đăng xuất). Đã sửa trong `internal/store/admins.go`: đọc giá trị cũ ngay trong câu `UPDATE` (khóa dòng) và chỉ xóa phiên khi vai trò hoặc trạng thái khóa thật sự đổi. Đổi vai trò hoặc khóa tài khoản vẫn kết thúc phiên ngay. Test của `store` và `handler` đã được cập nhật theo hành vi mới (lưu không đổi thì giữ phiên; đổi thật thì mất phiên).

### Vòng 4: tăng tốc test và phủ nốt các nhánh lỗi

Số đo cuối (`go test -p 1 -count=1 -coverprofile ./...`, máy không có phiên nào khác chạy test): toàn repo **86,8%** (vòng 5: 88,2%); `store` **85,8%**, `handler` **86,2%**, `cmd/rekey` **83,1%**, `cmd/server` **92,7%**, `cmd/rotate-pepper` 86,0%, `cmd/bench` 95,1%.

**Thời gian chạy (đo lại khi máy yên tĩnh).** Toàn bộ suite mất **103 giây**. Các con số 338 giây (`store`) và 126 giây (`cmd/server`) ở vòng trước là do máy đang tải bởi phiên khác, không phải thời gian bình thường; lời giải thích "do tạo database 32 partition cho mỗi test" ở vòng trước chỉ đúng một phần. Đo thật:
- `store`: 44 giây xuống **12 giây**. Nguyên nhân chính là `TRUNCATE` trên bảng có 32 partition tốn khoảng 616 ms mỗi test (đo trực tiếp trên PostgreSQL), trong khi `DELETE` kèm đặt lại sequence trên bảng nhỏ chỉ khoảng 8 ms. Helper `resetTables` dùng `DELETE` khi bảng dưới 20.000 dòng và vẫn dùng `TRUNCATE` khi nhiều hơn (DELETE chậm hơn trong trường hợp đó). Mọi test của `store` vẫn xanh.
- `cmd/server`: 38 giây xuống **5 đến 7 giây**. Mỗi test trước đây tạo database rồi `Migrate` từ đầu (tạo 2 lần 32 partition). Giờ tạo một database mẫu đã `Migrate` một lần cho cả lần chạy test rồi `CREATE DATABASE ... TEMPLATE`; `TestMain` xóa bản mẫu khi xong. Độ phủ giữ nguyên 92,7%.
- Các gói `rekey`, `rotate-pepper` mất 5 đến 10 giây, `handler` khoảng 22 giây (chủ yếu là băm argon2).

**`cmd/rekey`**: tách `runContext(ctx, args)` khỏi `run(args)` (chỉ `run` tạo `signal.NotifyContext`), nên test có thể "bấm Ctrl+C". Hai test mới: tiến độ được in ở lô 20 và 40 khi chạy 45 lô; Ctrl+C giữa chừng cho thông báo "interrupted", không mất hay trùng dòng nào (số dòng đã mã hóa lại cộng số dòng còn lại bằng tổng), và chạy lại thì làm nốt phần còn lại. Chạy lặp 4 lần đều xanh.

**`store`**: 
- `Migrate` trên database rỗng dựng toàn bộ schema, ghi đủ migration, dùng được ngay và chạy lại là no-op.
- Một migration lỗi thì dừng với lỗi nêu tên file và không được ghi là đã chạy.
- Hai instance khởi động cùng lúc đều thành công và mỗi migration chỉ được ghi một lần (khóa advisory).
- Context đã hủy thì `Migrate` trả lỗi.
- **Tính nguyên tử**: khi bước phụ của một giao dịch hỏng (`change_log` hoặc `audit_logs` bị đổi tên), `CreateEntry`, `UpdateEntry`, `DeleteEntry`, `CreateAdmin`, `UpdateAdmin`, `CreateAPIKey`, `RevokeAPIKey` đều trả lỗi và không để lại gì: không có entry mà Bloom filter không biết, không có thao tác quản trị nào thiếu dấu vết audit.

**`handler`**: lỗi bên trong khi check (database lỗi) trả 500 chung, không lộ chi tiết nội bộ; dữ liệu nhập sai vẫn là lỗi của người dùng (200 kèm thông báo); body form hỏng trả 400; `render` thiếu trang hoặc thiếu template con trả 500 chung, trang hợp lệ vẫn render.

**Phép thử đột biến thêm (chạy trên bản sao repo):**

| Lỗi chèn vào | Kết quả |
|---|---|
| `UpdateAdmin` luôn xóa phiên | Bị bắt |
| `serverError` lộ nguyên nhân lỗi ra người dùng | Bị bắt |
| `CreateEntry` bỏ qua lỗi ghi `change_log` | **Sống sót** |
| `Migrate` commit một migration đã lỗi | **Sống sót** |

Hai lỗi sống sót đều là "đột biến tương đương" theo quan sát: sau một câu lệnh lỗi, PostgreSQL đánh dấu giao dịch đã hủy, nên các câu lệnh sau (ghi audit, hoặc `COMMIT`) cũng thất bại và kết quả quan sát được không đổi. Đây là suy luận từ việc test vẫn xanh với lỗi chèn vào; tôi không chứng minh thêm bằng cách khác.

### Vòng 5: mất kết nối mạng giữa hai câu lệnh (mô phỏng tất định)

Trước đây mục này được ghi là "chưa test, chỉ giả lập được mong manh". Đã làm được bằng cách khác: `internal/testutil/pgfault` là một proxy TCP chạy giữa ứng dụng và PostgreSQL (chỉ dùng cho test, không gói production nào import). Proxy hiểu vừa đủ giao thức PostgreSQL để đếm các "vòng đi về" (mỗi `Sync` hoặc `Query` là một vòng) nên làm đứt kết nối ở một vòng được chọn chính xác, không phụ thuộc thời gian. Có hai kiểu đứt:
- **"before"**: đứt trước khi vòng thứ n tới server. Server thấy kết nối đóng giữa chừng và hủy giao dịch đang mở.
- **"after"**: server xử lý trọn vòng thứ n rồi kết nối mới đứt, client không nhận được phản hồi. Nếu vòng đó là `COMMIT` thì dữ liệu đã được lưu nhưng thao tác báo lỗi. Đây là tình huống khó nhất, và các test xác nhận nó thật sự xảy ra (có ít nhất một điểm đứt mà thao tác báo lỗi dù dữ liệu đã lưu).

Với n = 1, 2, 3, ... cho tới khi thao tác chạy xong mà không bị đứt, nên **mọi ranh giới giữa hai câu lệnh** của thao tác được thử, ở cả hai kiểu. Điều phải giữ ở mọi điểm đứt: thao tác báo lỗi (không báo thành công giả, không treo, không panic), và trạng thái là toàn bộ hoặc không gì.

| Phạm vi | Thao tác | Kiểm tra ở mọi điểm đứt |
|---|---|---|
| `store` (quét hết) | `CreateEntry`, `UpdateEntry`, `DeleteEntry` | số entry, dòng `change_log` và dòng audit luôn bằng nhau; không bao giờ có entry mà Bloom filter không biết |
| `store` (quét hết) | `CreateAdmin`, `UpdateAdmin`, `CreateAPIKey`, `RevokeAPIKey` | thay đổi và dòng audit cùng xảy ra hoặc cùng không; `UpdateAdmin` đổi vai trò, mất phiên và có audit đều cùng nhau |
| `store` (quét hết) | `Import` | một lô là 0 hoặc đủ 3 dòng, kèm đủ `change_log` |
| `store` (quét hết) | `Rekey`, `RotatePepper`, chuẩn hóa URL | không dòng nào mất hay đổi nội dung; chạy lại thì hoàn tất (mọi dòng ở khóa mới, mọi số tra cứu được bằng pepper mới, entry chặn đúng URL chuẩn) |
| `store` (lấy mẫu) | `Migrate` trên database rỗng (điểm đứt 1, 4, 11) và chuyển bảng plaintext cũ (3, 9, 20) | không để lại bảng dở dang; chạy lại hoàn tất; khóa advisory của kết nối đã chết được nhả; đủ 30 dòng cũ |
| `store` | đứt giữa lúc nhận kết quả lớn (`AllHashes`, `ListEntries`, `ExportBatch`) | trả lỗi, không trả dữ liệu cụt như thể đầy đủ |
| `changefeed` | dựng lại Bloom filter bị đứt giữa lúc đọc | trả lỗi và filter cũ còn nguyên, vẫn chặn mọi số đã có |
| `changefeed` | thăm dò `change_log` (mọi điểm đứt) | lần thăm dò đó báo lỗi, lần sau nạp được thay đổi, không bỏ sót vĩnh viễn |
| `handler` | tạo entry qua HTTP (15 vòng đi về, quét hết) | không có trạng thái dở dang; HTTP 204 chỉ khi entry đã lưu; dữ liệu đã lưu thì Bloom filter biết, kể cả khi client nhận 5xx; không lộ chi tiết driver |
| `handler` | tra cứu API key lúc đứt (2 vòng, quét hết) | luôn 503, không bao giờ 401 hoặc 403 (client không vứt key đúng chỉ vì database sự cố) |
| `handler` | kết nối bị cắt đột ngột | request kế tiếp thành công hoặc 500 rõ ràng, tự phục hồi sau vài request |
| `cmd/server` (lấy mẫu) | khởi động trên database rỗng, đứt ở các điểm 1, 3, 6, 10, 20, 40 | không treo; nếu thất bại thì trả lỗi; khởi động lại trên cùng database dở dang thì hoàn tất và có đúng một admin đầu tiên |

**Phép thử đột biến** (trên bản sao repo) cho thấy các test này bắt được lỗi thật đúng loại đang tìm:
- Ghi `change_log` ngoài giao dịch trong `CreateEntry`: bị bắt, kèm chẩn đoán "entries +0, change_log +1, audit +0" ở điểm đứt thứ 6.
- Kết thúc phiên ngoài giao dịch trong `UpdateAdmin`: bị bắt ("role changed=false but session ended=true").
- Báo sự cố database lúc xác thực key thành 401: bị bắt.
- Bộ quản lý Bloom bỏ qua lỗi khi dựng lại: bị bắt (filter cụt bị đem ra dùng).
- Một lần chèn khác (báo thành công trước khi commit) không áp dụng được vì tôi viết sai đoạn code cần sửa, nên chưa có kết quả.

**Giới hạn phải nói thẳng:**
- Mô phỏng ở mức TCP giữa ứng dụng và PostgreSQL trên cùng máy (không TLS, `sslmode=disable`). Không mô phỏng mất gói, độ trễ cao hay hết thời gian chờ chậm; không phủ Redis.
- `Migrate`, chuyển bảng cũ và khởi động server chỉ **lấy mẫu** vài điểm đứt (mỗi điểm cần một database mới và một lần migration đầy đủ), các thao tác còn lại quét hết.
- Kiểu "after" đóng nửa chiều (FIN) để server không bỏ dở dữ liệu đã nhận; ngoài đời kết nối đứt kiểu RST có thể khiến server bỏ dữ liệu chưa đọc, nhưng hệ quả (giao dịch hủy) đã được kiểu "before" phủ.
- Thời gian chạy: toàn bộ suite mất **250 giây** khi máy yên tĩnh (`store` 130 giây, `cmd/server` 38 giây). Các test chậm nhất (`Migrate`, chuyển bảng cũ, khởi động server) tự bỏ qua với `-short`.

Số đo cuối: toàn repo **88,2%** (`store` 89,9%, `handler` 86,5%, `changefeed` 85,4%, `cmd/server` 92,1%).

### Chưa làm được
- `TestChangeLogHeadAndPurge`: tự bỏ qua khi có transaction mở ở nơi khác trong cụm Postgres. Đó là hành vi đúng của `Head` (chỉ trả các dòng trước xmin của cả cụm); muốn chạy chắc chắn cần một cụm Postgres riêng cho test.
- `cmd/server`, `store`, `handler`: lỗi mạng giữa hai câu lệnh đã được phủ ở vòng 5; phần chưa phủ còn lại là các nhánh lỗi hiếm (ví dụ hết thời gian chờ chậm, mất gói, Redis) mà proxy hiện tại không mô phỏng.
- Phép thử đột biến toàn bộ mới khoảng 30 lỗi chèn tay, không phải toàn bộ mã nguồn. Coverage đo dòng lệnh, không chứng minh test mạnh.

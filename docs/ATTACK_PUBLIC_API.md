# Thử tấn công API public của VSF — nhật ký và số liệu

## Tóm tắt kết quả

> **Trạng thái cuối (2026-11-12):** các lỗi lọt được trong lần thử đầu đã được vá. Kết quả thử lại sau các bản vá nằm ở mục "Lần thử lại sau các bản fix và vá lỗi". Các bảng và kịch bản bên dưới giữ nguyên là nhật ký lúc phát hiện.
>
> **Kết luận** trong các lần thử đã làm, không còn lỗ hổng mức High/Critical đã biết trên API public. Ba phát hiện chính: bỏ qua xác thực không lọt; vượt giới hạn bằng batch đã vá; API key giả gây tải Postgres đã vá. Còn lại: throttle đăng nhập (xem báo cáo tổng hợp), chưa thử trên nhiều máy thật, chưa có pentest bên ngoài.

| # | Kịch bản | Kết quả | Mức độ |
|---|---|---|---|
| 1 | Bỏ qua xác thực | **Không lọt** được qua bất kỳ cách nào đã thử | — |
| 2 | Dò API key bằng thời gian phản hồi | Không thấy khác biệt thời gian giữa 4 trạng thái | — |
| 3 | Vượt rate limit bằng batch | **Lọt lúc phát hiện** (xử lý ~100 lần giới hạn). **Đã vá:** batch 100 mục với `rps_limit=10` đạt 0 mục/s | High (lúc phát hiện) |
| 4 | Input không hợp lệ / fuzz | Bị chặn đúng ở hầu hết trường hợp, 1 ghi chú nhỏ | Low |
| 5 | Giới hạn batch (0, 101, mảng lồng sâu, body >1 MB) | Chặn đúng mọi trường hợp | — |
| 6 | Dò trạng thái blacklist qua timing | Không cần: kết quả đã lộ trực tiếp trong JSON (bằng thiết kế) | — |
| 7 | Header injection, CORS, UTF-8 hỏng | Không lọt, không có CORS mở | — |
| 8 | Tải dồn có kiểm soát (c=64→512) | Chịu được, chỉ lỗi nhẹ ở c=512 (do giới hạn client, không phải server) | — |
| 9 | Header bảo mật trên `/v1/*` | Đầy đủ, không có `Access-Control-Allow-Origin` | — |
| 10 | Dò lỗi 500 / rò thông tin | Không ép được lỗi 500, thông báo lỗi luôn gọn và an toàn | — |
| 7b | Vét cạn API key giả, prefix ngẫu nhiên mỗi lần — tạo tải DB không giới hạn | **Lọt lúc phát hiện** (ngoài kế hoạch). **Đã vá:** 2.962/3.000 key giả bị 429, DB chỉ nhận 38 lượt tra | Critical (lúc phát hiện) |

---

## Kịch bản 1 — Bỏ qua xác thực

Tất cả đều trả **401** đúng như kỳ vọng: không gửi key, key rỗng, `Authorization: Bearer` rỗng, key sai định dạng, key đúng tiền tố sai bí mật, key hợp lệ gửi qua query string `?api_key=`, giá trị kiểu SQL injection trong `value` (không có key), method `PUT` thay `GET`, batch không key.

Một trường hợp trả **200**: gửi đồng thời `X-API-Key` hợp lệ **và** `Authorization: Bearer` giả. Đây là hành vi đúng (không phải lỗi): code đọc `X-API-Key` trước, chỉ dùng `Authorization` khi `X-API-Key` trống ([api.go:35-40](../internal/handler/middleware.go)). Không có đường lách.

Phát hiện phụ: mọi đường dẫn dưới `/v1/*` (kể cả đường dẫn không tồn tại, hay method sai) đều trả 401 khi không có key, thay vì 404. Middleware xác thực áp cho toàn bộ nhóm route trước khi khớp route cụ thể. Đây là điều **tốt** (không lộ "route nào có tồn tại" cho kẻ dò quét chưa có key).

## Kịch bản 2 — Dò API key bằng thời gian phản hồi

Đo 300 lần mỗi loại (sau 20 lần làm nóng), 4 trạng thái: không key, prefix không tồn tại, prefix tồn tại nhưng sai bí mật, key hợp lệ.

```
1_no_key                         p50=0s    p95=520µs p99=669µs
2_unknown_prefix                 p50=0s    p95=523µs p99=566µs
3_known_prefix_wrong_secret      p50=0s    p95=520µs p99=582µs
4_valid_key                      p50=0s    p95=522µs p99=577µs
```

Không có khác biệt vượt nhiễu đo (độ phân giải đồng hồ Windows thô ở mức dưới 1ms che bớt sự khác biệt thật, nếu có). `subtle.ConstantTimeCompare` ở [apikey.go:133](../internal/apikey/apikey.go) hoạt động đúng mục đích. **Không kết luận được có lỗ hổng**, nhưng cũng không chứng minh được có.

## Kịch bản 3 — Vượt rate limit bằng batch (xác nhận lỗi M1 bằng số liệu thật)

Dùng key cấu hình `rps_limit=10`. Đo bằng công cụ Go (không qua subprocess curl, để tránh nhiễu do chi phí khởi tạo process — lần đo đầu bằng bash+curl cho số liệu không ổn định vì lý do này, xem ghi chú debug bên dưới).

| Cách gọi | Trong 3 giây | Số mục xử lý mỗi giây |
|---|---|---|
| `/v1/check` (1 mục/lần) | 39 request thành công, 21.150 bị 429 | **13 mục/giây** |
| `/v1/check/batch` (100 mục/lần) | 39 request thành công, 5.000 bị 429 | **1.300 mục/giây** |

Số request thành công giống nhau (≈39, đúng vì rate limiter tính theo **số request**, không theo số mục — `rate.NewLimiter(rps, rps)` ở [apikey.go:204](../internal/apikey/apikey.go), còn `Allow` chỉ gọi `le.l.Allow()` một lần bất kể `units`). Kết quả: cấu hình `rps_limit=10` cho phép **1.300 mục/giây thật**, gấp **~130 lần** giới hạn khai báo.

#### Đã fix — kiểm chứng lại cùng kịch bản

Sửa `Allow()` dùng `le.l.AllowN(time.Now(), units)` thay cho `le.l.Allow()`, giữ `burst = rps_limit` như cũ. Đo lại đúng kịch bản trên, cùng server, sau khi vá:

| Cách gọi | Trước vá | Sau vá |
|---|---|---|
| `/v1/check` (1 mục/lần), `rps_limit=10` | 13 mục/giây | **13 mục/giây** (không đổi — đúng như kỳ vọng) |
| `/v1/check/batch` (100 mục/lần), `rps_limit=10` | **1.300 mục/giây** | **0 mục/giây — 100% (5.614/5.614) bị 429** |
| `/v1/check/batch` (100 mục/lần), `rps_limit=200` (key cấu hình đủ lớn, đối chứng) | — | **233 mục/giây**, sát đúng 200 đã cấu hình |

**Hệ quả thiết kế và cách xử lý:** với `max_batch` mặc định `0`, `burst = rps_limit`, nên batch lớn hơn `rps_limit` luôn bị 429 (không phải "chờ rồi được"). Để key nào cần batch lớn hơn `rps_limit` thì admin đặt **`max_batch`** riêng cho key đó (0–100, cột mới `api_keys.max_batch`, migration `004`, mặc định 0 nên key cũ không đổi): burst của key = `max(rps_limit, max_batch)`, còn tốc độ duy trì vẫn đúng `rps_limit`. Đo trên DB có sẵn dữ liệu (rps_limit=10): `max_batch=0` → batch 100 mục bị 429 hoàn toàn; `max_batch=100` → đúng 1 batch 100 mục lọt rồi phải chờ nạp lại; gọi lẻ liên tục 20 giây: `max_batch=0` được 209 mục (10,5/giây), `max_batch=100` được 299 mục — chênh đúng 90 mục = burst 100 trừ burst 10, tức **chỉ nới một lần ban đầu, không nâng tốc độ duy trì**. Lưu ý: key có `max_batch` lớn cũng được burst đó cho cả gọi lẻ khi nghỉ đủ lâu; đây là quyết định có ý thức theo từng key.

**Kiểm chứng:** `go vet ./...` sạch, toàn bộ `go test ./...` pass (12 package), gồm test hồi quy mới `TestRateLimit_BatchCostsProportionally` (tái hiện đúng kịch bản M1: batch đầu lọt, batch liền sau bị chặn, batch vượt `rps_limit` luôn bị chặn, gọi đơn lẻ không bị ảnh hưởng).

*Ghi chú debug:* lần đo đầu bằng vòng lặp bash gọi `curl` cho kết quả không nhất quán (15 batch liên tiếp đều 200, nhưng lần thử lại thì 23/30 thành công) — không phải do server, mà do chi phí khởi tạo process của `curl` trong bash làm tốc độ gọi thực tế dao động không kiểm soát được. Đổi sang công cụ Go bắn liên tục trong vòng lặp cho kết quả ổn định và dùng để kết luận.

Mã đối chứng cho thấy bộ đệm cache của tầng check vẫn hoạt động đúng (không liên quan rate limit): việc tăng `hit` không ảnh hưởng tới phát hiện này.

## Kịch bản 4 — Input không hợp lệ / fuzzing

| Input | Kết quả |
|---|---|
| `type` lạ, `type` rỗng | 400, thông báo rõ |
| `value` rỗng, quá dài (5000 ký tự) | 400 |
| Ký tự control / NUL byte thật trong `value` | 400, thông báo escape đúng, không crash |
| `url` scheme `javascript:`, `file:` | 400, bị chặn đúng (chỉ nhận `http`/`https`) |
| Mảng JSON lồng sâu 100.000 cấp trong `items` | 400 "invalid JSON body" tức thì (4ms) — bộ giải mã JSON của Go có giới hạn độ sâu sẵn, không bị treo |
| 1 mục batch có `value` dài 500.000 ký tự | **200**, server **echo lại nguyên văn** giá trị 500.000 ký tự trong `input` trước khi báo lỗi `phone is too long` → response **500.121 byte** cho một request có kích thước tương đương. Không phải lỗ hổng (không khuếch đại, tỉ lệ ~1:1), nhưng là thói quen code chưa tốt: `Result{Input: raw}` được gán trước khi kiểm tra độ dài ([checker.go:90](../internal/checker/checker.go)) |
| Batch 100 mục, tổng body ≈882 KB (gần ngưỡng 1 MB) | 200, xử lý bình thường |
| Batch 1 mục, body ≈1,34 MB (vượt ngưỡng 1 MB) | 400 "invalid JSON body" — `MaxBytesReader` chặn đúng ([api.go:120](../internal/handler/api.go)) |
| Content-Type `text/plain` nhưng body JSON hợp lệ | **200** — handler không kiểm tra `Content-Type`, chỉ giải mã JSON trực tiếp. Không phải lỗ hổng ở đây (API dùng key header, không dùng cookie, nên không có rủi ro CSRF kiểu "form giả mạo"), nhưng là điểm khác thường nên biết |
| Body UTF-8 không hợp lệ (`\xff\xfe`) | 200, ký tự được thay bằng `�` theo chuẩn, báo lỗi "not a number", không crash |
| CRLF trong `value` (thử request/response splitting) | 400, bị `phonenumbers` từ chối trước khi chạm tới bất kỳ nơi nào khác |

**Một phát hiện mới:**

**Đường dẫn URL phân biệt hoa/thường, trong khi tên miền không.** Dựng một entry test `url`, `match_type=prefix`, giá trị `case-evasion-test.example/SecurePath` (xóa ngay sau khi test):

```
Tra đúng case lúc tạo        → http://case-evasion-test.example/SecurePath/x   => blacklisted:true
Tra PATH viết hoa toàn bộ    → http://CASE-EVASION-TEST.EXAMPLE/SECUREPATH/x   => blacklisted:false
Tra PATH viết thường toàn bộ → http://case-evasion-test.example/securepath/x   => blacklisted:false
```

Nguyên nhân: [url.go:77](../internal/normalize/url.go) hạ chữ thường cho `host` nhưng **không** làm vậy cho `path` ([url.go:103](../internal/normalize/url.go), dùng `u.EscapedPath()` nguyên dạng). Kẻ gửi phishing chỉ cần viết hoa một phần đường dẫn (ví dụ link trong email: `Evil.com/SecurePath` → `evil.com/SECUREPATH` hoặc ngược lại) để **lọt qua mọi entry khớp theo path** (`prefix` và `exact`). Domain-only entry (`match_type=domain`) không bị ảnh hưởng vì không xét path.

Các test chuẩn hóa khác đều đúng: dấu chấm cuối domain, cổng `:80` mặc định, hoa/thường tên miền, Punycode, homoglyph (Cyrillic `а` cho ra mã Punycode khác hẳn domain thật — tốt, không bị coi là cùng một domain), path traversal dạng `..%2f` (giữ nguyên dạng chữ, không có ý nghĩa vì đây không phải đường dẫn hệ thống tệp), `%2e` trong host bị `url.Parse` từ chối thẳng.

## Kịch bản 5 — Giới hạn batch

Batch 0 mục, batch 101 mục, JSON méo (thiếu ngoặc), `items` không phải array, trường thừa trong object: **tất cả đều 400** với thông báo gọn, đúng như thiết kế (`dec.DisallowUnknownFields()`, kiểm tra `len(req.Items)`).

## Kịch bản 6 — Dò trạng thái blacklist qua timing

Không cần thiết: API `/v1/check` đã **trả trực tiếp** `"blacklisted":true/false` trong JSON — đây là thiết kế có chủ đích của sản phẩm (một dịch vụ kiểm tra blacklist), không phải lỗi. Không có "oracle timing" nào cần tìm vì câu trả lời đã công khai qua đúng kênh chính thức. (Việc ai được *gọi* API này — tức có key hay không — mới là lớp bảo vệ, và đã kiểm ở kịch bản 1–2.)

## Kịch bản 7 — Header injection / CORS / tải trọng thất thường

- Không có header `Access-Control-Allow-Origin` trong bất kỳ phản hồi nào, kể cả khi gửi `Origin: https://evil-site.example`. Trình duyệt sẽ tự chặn đọc response từ origin khác theo same-origin policy mặc định. **An toàn theo mặc định.**
- `OPTIONS` preflight trả 401 (vì không có xác thực) — không có CORS nào được "mở" một cách vô ý.
- Header bảo mật (`Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, `Permissions-Policy`) có đầy đủ trên cả `/v1/*`, vì middleware `securityHeaders` áp dụng toàn cục ([handler.go:98](../internal/handler/handler.go)).
- `X-Forwarded-For` giả không ảnh hưởng gì đáng kể ở `/v1` (route này không dùng IP để giới hạn tốc độ, chỉ dùng cho log/inspector).

### 7b. Phát hiện ngoài kế hoạch: vét cạn bằng API key giả tạo tải Postgres không giới hạn

**Phát sinh khi nào:** trong lúc thử kịch bản 1 (một request với "prefix không tồn tại" trả 401 rất nhanh), mình nhận ra `apiAuth` middleware trả 401 **trước khi** `limited()` (bộ giới hạn tốc độ) được gọi — vì `limited()` nằm trong thân `apiCheckOne`/`apiCheckBatch`, chỉ chạy **sau khi** xác thực thành công ([api.go:98-101](../internal/handler/api.go)). Nghĩa là **request xác thực sai không bị giới hạn tốc độ ở bất kỳ mức nào.**

Đồng thời, cache tra API key là cache **âm** theo `prefix` (8 ký tự, TTL 10 giây, [apikey.go:154](../internal/apikey/apikey.go)). Nếu kẻ tấn công **đổi prefix ngẫu nhiên mỗi lần gọi** (8 ký tự ngẫu nhiên, không khó), mọi request đều cache-miss và buộc server tra Postgres (`GetAPIKeyByPrefix`) một lần — **không cần biết bất kỳ key thật nào.**

**Đo thực tế (c=32, 3 giây mỗi lượt, trên server thử):**

| Kịch bản | Kết quả |
|---|---|
| **Đối chứng — key hợp lệ, không hạn mức** | 56.008 request / 2s = **28.004 req/s**, 100% thành công |
| **Đối chứng — key sai NHƯNG cố định** (không đổi prefix) | 56.207 request / 2s = **28.104 req/s**, 100% là 401 — **cache âm hoạt động đúng, không chạm DB mỗi lần** |
| **Tấn công — key giả, prefix NGẪU NHIÊN mỗi request** | 37.301 request / 3s = **12.434 req/s**, 100% là 401, **mỗi request một lượt tra Postgres thật** |
| CPU container Postgres trong lúc tấn công | **≈201%** (hơn 2 nhân CPU) |
| Client hợp lệ chạy ĐỒNG THỜI với tấn công | tụt từ 28.004 → **21.268 req/s** (**giảm ≈24%**) trong khi kẻ tấn công vẫn duy trì 10.208 req/s |

**Kết luận:** một kẻ tấn công **không có bất kỳ thông tin xác thực hợp lệ nào**, không cần đăng ký, không bị giới hạn tốc độ ở bất kỳ lớp nào trong code hiện tại, có thể tạo **hơn 12.000 truy vấn Postgres mỗi giây** chỉ bằng cách đổi 8 ký tự ngẫu nhiên trong header mỗi lần gọi `/v1/check`. Tải này đo được làm giảm ~24% thông lượng của khách hàng hợp lệ ngay trên máy thử (CPU 10-16 luồng); trên hạ tầng production với nhiều client thật đang dùng rps_limit cao, tác động có thể lớn hơn nhiều, và đây **chính là một hình thức DoS tầng DB** không cần vượt qua bất kỳ cơ chế xác thực nào — chỉ cần *thất bại* một cách có chiến lược.

Đây **không phải lỗi logic rate-limit riêng của API key** (M1) — nó xảy ra **trước** khi có bất kỳ API key nào tồn tại trong hệ thống. Nó cũng không bị chặn bởi `COOKIE_SECURE`, `AuthDisabled` hay bất kỳ cấu hình production nào đã thấy trong `config.go`. Mình xếp mức độ: **Critical** — vì không cần quyền gì, chi phí tấn công cực thấp, tác động trực tiếp vào thành phần dễ vỡ nhất của hệ thống (Postgres), và ảnh hưởng tới mọi khách hàng khác đang dùng API hợp lệ.

#### Đã fix — kiểm chứng lại cùng kịch bản

Sửa: `internal/apikey/apikey.go` (`allowLookup` — giới hạn theo IP ngay trước lượt tra DB, chỉ áp dụng khi cache-miss) và `internal/handler/api.go` (truyền IP vào `Authenticate`, trả 429 cho `ErrTooManyAuthAttempts`). Chạy lại đúng 4 phép đo cũ, cùng server, cùng tham số:

| Đo | Trước vá | Sau vá |
|---|---|---|
| Đối chứng — key hợp lệ | 28.004 req/s | 26.246 req/s (cùng mức, trong nhiễu đo) |
| Đối chứng — key sai CỐ ĐỊNH (cache âm) | 28.104 req/s | 27.432 req/s (không đổi, vẫn dùng cache) |
| **Tấn công — prefix ngẫu nhiên** | 12.434 req/s, **100% chạm DB** | 22.614 req/s, nhưng chỉ **49/67.842 (0,07%)** chạm được tới bước tra DB — còn lại bị **429** ngay, không chạm Postgres |
| **CPU container Postgres lúc tấn công** | **≈201%** | **≈0,35%** |
| Client hợp lệ chạy ĐỒNG THỜI với tấn công | 28.004 → 21.268 (**−24%**) | 26.246 → 23.257 (**−11%**, gần hết do CPU máy thử dùng chung giữa 2 tiến trình đo, không phải do Postgres bị nghẽn — Postgres gần như rảnh) |

Số "49 lượt chạm DB" khớp với thiết kế: `ipLookupBurst=20` cộng với phần nạp lại trong 3 giây ở `ipLookupRPS=10` (20 + 3×10 = 50, đo được 49, sai số do thời điểm đo).

**Kiểm chứng không phá vỡ hành vi cũ:** `go vet ./...` sạch, toàn bộ `go test ./...` pass, gồm 2 test hồi quy mới (`TestIPLookupRateLimit_BlocksRotatingPrefixes`, `TestIPLookupRateLimit_IndependentPerIP`) và các test `apikey` cũ (đã thêm tham số IP, hành vi không đổi).

**Đã làm sau đó:** bộ giới hạn đã chuyển sang Redis dùng chung cho mọi instance. Kiểm chứng ở mục "Lần thử lại": 60 request qua 5 instance với `rps_limit=10`, chỉ 10 request thành công.

## Kịch bản 8 — Tải dồn có kiểm soát

Dùng key hợp lệ, không hạn mức, tăng dần số kết nối đồng thời, 3 giây mỗi mức, dừng nếu lỗi > 5%:

| c | RPS | Lỗi |
|---|---|---|
| 64 | 56.690 | 0% |
| 128 | 61.065 | 0% |
| 256 | 63.768 | 0% |
| 512 | 55.100 | 0,33% |

Không sập ở bất kỳ mức nào thử (tối đa 512 kết nối đồng thời, giới hạn do thời gian kiểm thử, không phải do đã tìm thấy ngưỡng sập). 0,33% lỗi ở c=512 là hiện tượng nghẽn cổng/kết nối phía client trên Windows (đã gặp và mô tả trong [docs/LOADTEST_CLAUDE.md](LOADTEST_CLAUDE.md)), không phải lỗi server.

## Kịch bản 9 — Header bảo mật trên API public

Đầy đủ header bảo mật tiêu chuẩn, không có CORS mở ngoài ý muốn.

## Kịch bản 10 — Dò lỗi 500 / rò thông tin

Thử nhiều cách (input dị dạng, body hỏng UTF-8, số điện thoại có mã quốc gia không hợp lệ, body quá lớn, JSON lồng sâu): **không ép được lỗi 500 nào**. Mọi lỗi đều trả 400 với thông báo ngắn, không có stack trace, đường dẫn file, hay thông tin nội bộ. Đây là điểm làm tốt của dự án.

---

## Tổng hợp phát hiện mới / xác nhận, liên kết với báo cáo debug trước

| Mã | Mô tả | Trước đó | Sau khi tấn công thật |
|---|---|---|---|
| **M1** | Batch chỉ trừ 1 token rate-limit dù 100 mục | Suy luận từ đọc code | **Xác nhận bằng số liệu: ×130 so với giới hạn khai báo** |
| **A1 (mới)** | API key giả, prefix ngẫu nhiên → tải Postgres không giới hạn, không cần xác thực | Chưa phát hiện | **Mới, Critical — 12.434 req/s tới DB, giảm 24% thông lượng khách hợp lệ** |
| **M9 (mở rộng)** | Chuẩn hóa URL thiếu `//`, `/./`... | Suy luận từ đọc code | **Xác nhận + mở rộng: path phân biệt hoa/thường, domain thì không — bằng chứng thực nghiệm với fixture thật** |

---


## Lần thử lại sau các bản fix và vá lỗi

**Môi trường.** Một máy Windows (i5-13450HX). Postgres 16 và Redis 7 chạy trong Docker trên máy đó. Server là bản hiện tại. Năm instance chạy cùng một DB và một Redis, `POLL_INTERVAL=300ms`. Script điều phối và các kịch bản nằm ngoài repo; chỉ nhắm vào `127.0.0.1` và server thử do script tự khởi động.

| Kịch bản | Kết quả |
|---|---|
| 1. Bỏ qua xác thực | Không key, key sai định dạng, key sai bí mật: **401**. Key đúng: 200. |
| 2. Dò key bằng thời gian phản hồi | p50: prefix lạ 1,8 ms; prefix đúng nhưng bí mật sai 1,2 ms; key đúng 2,6 ms. p95 nằm trong khoảng 16 đến 20 ms. Nhiễu lớn hơn khác biệt, không có tín hiệu rò. |
| 3. Batch vượt rate limit (M1) | `rps_limit=10`: batch 100 mục đạt **0 mục/s** (100% bị 429). Request đơn lẻ đạt 13 mục/s (burst 10 cộng nạp lại). Trước khi vá là 1.300 mục/s. |
| 4. Input dị dạng, fuzzing | 8 payload (chuỗi 500 KB, unicode lạ, null byte, type và region không hợp lệ, JSON hỏng, JSON lồng 100.000 cấp, trường lạ): tất cả **400**, không có 5xx, không ngắt kết nối. |
| 5. Giới hạn batch | 101 mục: 400. 0 mục: 400. |
| 6. Dò trạng thái blacklist qua thời gian | Trúng: p50 3,1 ms, p95 17 ms. Không trúng: p50 2,4 ms, p95 19 ms. Không đọc được trạng thái blacklist qua thời gian phản hồi. |
| 7. CORS và Host | Origin lạ: không có `Access-Control-Allow-Origin`. Host giả mạo: vẫn 200, không phản chiếu vào phản hồi. |
| 9. Header bảo mật | Có `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`. |
| 10. Rò thông tin khi lỗi | Không có `goroutine`, `panic`, `pq:`, câu SQL, đường dẫn `.go` hay stack trong phản hồi lỗi. |
| A1. Flood key giả | 3.000 key có tiền tố ngẫu nhiên, 32 luồng: **2.962 bị 429** (`auth_rate_limited`), 38 request tới bước tra DB (đều 401). Số transaction DB tăng 63. Trước khi vá: 12.434 truy vấn/s và CPU Postgres khoảng 201%. |

**Nhiều instance (5 instance cùng DB và Redis):**
- Giới hạn dùng chung: 60 request đồng thời phân bổ đều qua 5 instance, `rps_limit=10`: **10 thành công, 50 bị 429**. Giới hạn không bị nhân theo số instance.
- Lan truyền thay đổi: entry mới tạo ở instance 1 xuất hiện ở instance 2, 3, 4, 5 sau **132 đến 309 ms** (tuỳ lần chạy, trong khoảng `POLL_INTERVAL` 300 ms).

**Kịch bản 8 (tải, cmd/bench):** một instance, 199.895 SĐT đã nạp qua trang import (khoảng 10% request trúng blacklist), tỉ lệ trúng cố định 0,1, thời lượng 10 giây, máy dùng chung với Docker và Python.

| Kết nối | Request/s | p50 | p95 | p99 | Lỗi |
|---|---|---|---|---|---|
| 16 | 11.404 | 1,06 ms | 3,71 ms | 4,66 ms | 0 (toàn 200) |
| 64 | 17.639 | 2,81 ms | 9,48 ms | 12,52 ms | 0 (toàn 200) |

### Bổ sung: slowloris thật, upload gửi chậm, C1 và C2 qua đường thật

Đã thử bằng socket thô và transaction DB thật, trên cùng server thử cục bộ.

| Kịch bản | Kết quả | Đối chiếu cấu hình |
|---|---|---|
| Header gửi chậm: gửi một byte header mỗi giây, không kết thúc | Server đóng kết nối (EOF) đúng **5,0 giây** (2 biến thể, lặp lại được) | `ReadHeaderTimeout` 5 giây |
| Body gửi chậm tới `/v1/check/batch`: khai báo 100 byte, gửi chậm | Server đóng kết nối sau **31,0 giây** | `ReadTimeout` 30 giây |
| 300 kết nối treo (chỉ gửi một phần header) | `/healthz` vẫn trả 200 trong 1 ms | |
| Upload CSV ~42 KB gửi chậm 1 KB/giây (~43 giây) tới `/admin/import` | Server chấp nhận, trả **200 OK** | Import nới `ReadTimeout` tới 10 phút |
| C1 qua API: giữ transaction DB mở 45 giây, tạo entry qua admin, kiểm tra `/v1/check` | Entry trúng blacklist sau **0,01 giây**. `/readyz` lúc 36 giây báo `changefeed_stalled` (vẫn 200). Sau commit, cảnh báo biến mất. | C1 đã vá (mục 7 báo cáo) |
| C2: import 199.936 dòng, lấy mẫu tuổi transaction dài nhất mỗi 0,5 giây (23 mẫu) | Import 16,4 giây. Transaction dài nhất quan sát được **0,96 giây**. | C2 đã vá (batch) |

Lưu ý:
- Một lần đo sớm cho header đóng sau 1,5 giây, không đúng với cấu hình. Đo lại nhiều lần cho 5,0 giây. Chưa xác định được nguyên nhân của lần 1,5 giây; kết quả này không đưa vào bảng.
- Đo C2 lấy mẫu mỗi 0,5 giây nên có thể bỏ sót đỉnh rất ngắn; con số 0,96 giây là cận dưới của tuổi transaction thật.
- Các số độ trễ vẫn đo trên máy dùng chung CPU với Docker và IDE. Chỉ dùng để so sánh tương đối, không dùng làm SLA.

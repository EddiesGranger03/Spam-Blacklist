# ADR 0002: Chính sách khi filter không dùng được (fail-open / fail-closed)

- **Trạng thái:** Đề xuất. Cần mentor/nghiệp vụ chọn phương án.
- **Ngày:** 2026-11-19
- **Liên quan:** `cmd/server/main.go` (readiness), `internal/checker`, `internal/snapshot`

## 1. Bối cảnh

Mỗi request check đi qua 4 bước: filter, cache Redis, DB, rồi trả kết quả. Hiện code đang **ngầm** chọn hành vi như sau:

| Tình huống | Hành vi hiện tại |
|---|---|
| Pod chưa có filter (đang tải snapshot, snapshot hỏng, chờ leader dựng) | `/readyz` báo chưa sẵn sàng nên load balancer không gửi traffic. Nếu bị gọi trực tiếp thì `Test()` trả `true`, tức đẩy hết xuống DB. |
| Filter có, DB lỗi hoặc chậm | Bước DB lỗi thì trả lỗi 5xx cho client. |
| Redis mất | Vẫn đúng: poll 1s, không cache. Tải DB tăng. |
| **Sự cố kép:** mọi pod chưa có filter (ví dụ snapshot hỏng hết **và** leader không dựng được vì DB quá tải) | **Toàn bộ dịch vụ check ngừng**, vì không pod nào ready. |

Câu hỏi nghiệp vụ là: khi **không thể trả lời chắc chắn**, hệ thống nên làm gì? Hai rủi ro ngược chiều nhau:

- **Âm tính giả** (cho lọt spam): người dùng bị lừa đảo. Đây là thiệt hại chính mà hệ thống được tạo ra để ngăn.
- **Ngừng dịch vụ / dương tính giả** (chặn nhầm, hoặc client không nhận được câu trả lời): khách hàng tích hợp API bị ảnh hưởng, ảnh hưởng SLA.

## 2. Các phương án

| # | Phương án | Hành vi khi sự cố kép | Ưu | Nhược |
|---|---|---|---|---|
| A | **Fail-closed: ngừng phục vụ** (hiện tại) | Trả 503, client tự quyết định | Không bao giờ trả lời sai | Mất dịch vụ toàn phần; client có thể tự fail-open theo cách tệ hơn |
| B | **Degraded: tra thẳng DB, có giới hạn** | Pod ready ở chế độ "degraded": mọi check đi DB, qua bộ giới hạn tốc độ / số kết nối riêng; vượt giới hạn thì trả 503 | Vẫn trả lời đúng cho phần lớn request; tự hồi phục | Có thể dồn thêm tải lên đúng cái DB đang yếu; cần load shedding cẩn thận |
| C | **Trả "không chắc chắn"** | Trả 200 với `verdict: "unknown"` cùng `degraded: true`; client tự áp chính sách của mình | Minh bạch, không đoán thay khách hàng | Đổi hợp đồng API; client cũ có thể hiểu "unknown" thành "an toàn" |
| D | **Fail-open: trả "an toàn"** | Trả an toàn | Dịch vụ luôn "sống" | **Cho lọt spam đúng lúc hệ thống yếu.** Không chấp nhận được với hệ thống chống lừa đảo |

## 3. Khuyến nghị

**B kết hợp C**, và **loại D**:

1. Khi mọi lớp còn bình thường: không có gì thay đổi.
2. Khi pod không có filter quá `T` giây (ví dụ 60 s): chuyển sang **degraded**.
   - Pod báo ready kèm cờ degraded.
   - Mọi check tra thẳng DB, qua bộ giới hạn đồng thời riêng (ví dụ ≤ 20% số kết nối pool).
   - Phần vượt giới hạn trả `503 + Retry-After`, không xếp hàng vô hạn.
3. Response có thêm `degraded: true`. Nếu không tra DB được trong hạn chót thì trả `verdict: "unknown"`, **không bao giờ** trả "an toàn" khi chưa xác minh.
4. Có metric và cảnh báo cấp **page** (gọi người trực) khi vào chế độ degraded.

## 4. Hệ quả

- Hợp đồng API thay đổi (thêm `degraded`, `verdict: unknown`). Cần đánh version và thông báo cho khách hàng tích hợp.
- Cần load-test riêng chế độ degraded: DB chịu được bao nhiêu RPS khi không có filter đứng trước.
- Runbook thêm mục "Dịch vụ ở chế độ degraded".

## 5. Câu hỏi cần mentor/nghiệp vụ chốt

1. Trong sự cố, ưu tiên **không cho lọt spam** (A/B/C) hay **luôn trả lời** (D)? Khuyến nghị: không chọn D.
2. Chấp nhận thay đổi hợp đồng API (C) không, hay chỉ làm B?
3. SLA và mức độ cảnh báo của chế độ degraded: page ngay, hay chỉ cảnh báo trong giờ hành chính?

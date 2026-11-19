# ADR 0001: Filter chia mảnh + snapshot tăng dần (không quét bảng định kỳ)

- **Trạng thái:** Đề xuất. Chờ user và mentor duyệt, chưa code.
- **Ngày:** 2026-11-19
- **Liên quan:** `internal/filter`, `internal/snapshot`, `internal/store/filtersnap.go`, `docs/SCALE_TEST.md`

## 1. Bối cảnh

Thiết kế hiện tại gồm static binary fuse, lớp delta và removed-set:

- Pod khởi động từ snapshot và không quét DB. Phần này đã đạt.
- Leader dựng lại static filter **bằng cách quét toàn bảng** `blacklist_entries` mỗi `FILTER_SNAPSHOT_INTERVAL` (mặc định 1 giờ).

Đây là hai giới hạn còn lại. Phần đã đo là đo thật trên máy dev, phần còn lại là ngoại suy (xem `docs/SCALE_TEST.md`):

| Vấn đề | Số liệu |
|---|---|
| Quét toàn bảng định kỳ | Đo thật: 41 s ở 30M dòng, 78,5 s ở 60M, 79 s chỉ để quét 100M. Lặp lại mỗi giờ, tức DB chịu một lần quét nặng mỗi giờ mãi mãi. |
| RAM đỉnh của leader khi dựng | Đo thật: ~40–43 B/số. Ngoại suy: 4,2 GB ở 100M, ~12 GB ở 300M. Vượt RAM thì **không còn ai dựng được snapshot**. |
| Một lần dựng là một khối nguyên | Lỗi giữa chừng thì làm lại từ đầu. Không chia được việc cho nhiều pod. |

Binary fuse là cấu trúc **tĩnh**: không thêm được phần tử. Vì vậy muốn ra static mới thì phải có **toàn bộ tập hash**. Hiện nguồn duy nhất của tập hash là bảng DB, nên mới phải quét.

## 2. Quyết định đề xuất

### 2.1 Chia mảnh (sharding) theo hash

- Chia không gian hash thành `S = 256` mảnh theo 8 bit cao của `value_hash`. `value_hash` là HMAC nên phân bố đều.
- Mỗi mảnh có static filter, delta và removed-set riêng.
- `Test(h)` chỉ cần chọn mảnh `h >> 56`, chi phí O(1), không chậm hơn hiện tại.
- Mỗi mảnh dựng độc lập, nên RAM đỉnh khi dựng ≈ 1/256 của toàn bộ: ~16 MB ở 100M, ~50 MB ở 300M.

### 2.2 Lưu cả tập hash đã sắp xếp (key set) trong snapshot

- Mỗi mảnh lưu thêm **danh sách hash đã sắp xếp, nén kiểu delta + varint**, cạnh fingerprint của filter.
- Hash 64 bit phân bố đều, sau khi sắp xếp và nén delta thì còn khoảng **4–5 byte/số**: ~450 MB ở 100M. Con số này chưa đo, cần một bước benchmark nhỏ.
- Snapshot mới của một mảnh được tính **thuần trong bộ nhớ**: lấy key set cũ, áp change_log (add/remove) theo thứ tự `seq` từ cursor cũ tới cursor mới, ra key set mới, rồi dựng lại static. **Không đọc bảng chính.**
- Chỉ dựng lại những mảnh có thay đổi ("bẩn"). Mảnh không đổi thì giữ nguyên object của lần trước.

### 2.3 Quét bảng chỉ còn để đối soát và khôi phục

- Quét toàn bảng **chỉ** chạy khi: (a) chưa có snapshot nào (lần đầu, hoặc sau xoay pepper), (b) chạy đối soát định kỳ thưa (ví dụ 1 lần/ngày vào giờ thấp điểm, theo từng mảnh, có throttle), (c) bộ kiểm tra đúng đắn (`internal/verify`) phát hiện âm tính giả.
- Đối soát chạy theo mảnh: quét range hash của một mảnh (hiện có partition HASH 32 phần, có thể tận dụng hoặc thêm index theo `value_hash`), so với key set đang lưu, rồi sửa lệch. Như vậy tải dàn đều theo thời gian chứ không dồn thành một cú quét lớn.

### 2.4 Lưu trữ

- Snapshot gồm một manifest (danh sách mảnh, version, cursor, domain id của pepper, checksum) và từng mảnh là một object riêng.
- Pod tải song song các mảnh. Cập nhật một mảnh chỉ cần ghi lại object của mảnh đó.
- Interface `SnapshotStore` giữ nguyên ý tưởng nhưng chuyển sang dạng object theo mảnh. Bản Postgres vẫn dùng được; **khuyến nghị dùng S3/MinIO** ở quy mô này để tránh phình WAL và backup.

## 3. Các phương án đã cân nhắc

| Phương án | Ưu | Nhược | Kết luận |
|---|---|---|---|
| Giữ nguyên (quét mỗi giờ) | Không phải sửa gì | Tải DB định kỳ, RAM leader có trần cứng | Không đạt ở 100M+ |
| Tăng interval lên 24h | Rất ít sửa | Delta và removed-set phình ra; vẫn có trần RAM | Chỉ dùng tạm |
| Đổi sang Bloom động không cần dựng lại | Thêm được phần tử, không cần quét | FPR ~1% (gấp 2,5 lần); không gỡ được nên vẫn phải dựng lại để dọn | Bỏ |
| Cuckoo filter chia mảnh | Thêm/gỡ trực tiếp, không cần key set | Rủi ro khi add trùng hoặc gỡ nhầm; đầy thì add thất bại; khó đảm bảo đúng tuyệt đối | Có thể dùng sau, rủi ro cao hơn |
| **Chia mảnh + key set + áp change_log (đề xuất)** | Không quét định kỳ, RAM đỉnh nhỏ, chỉ dựng mảnh bẩn, tải song song | Snapshot lớn hơn (thêm ~4–5 B/số); code phức tạp hơn; cần đối soát | **Chọn** |

## 4. Hệ quả

**Tích cực**
- Tải định kỳ lên DB gần bằng 0: chỉ còn đọc change_log và đối soát thưa.
- Trần RAM của leader chuyển từ O(N) sang O(N/S). Scale tới tỷ số chỉ cần tăng `S`.
- Lỗi khi dựng chỉ làm hỏng một mảnh, thử lại rẻ.

**Tiêu cực / rủi ro**
- Snapshot tăng thêm ~450 MB ở 100M (chưa đo). Chấp nhận được nếu dùng object storage.
- Key set **chính là dữ liệu nhạy cảm dạng hash**: hash có khóa (HMAC pepper) nên không đảo ngược được nếu không có pepper, nhưng vẫn cần cùng mức bảo vệ như bảng gốc.
- Nếu key set lệch so với DB (bug khi áp change_log), lỗi sẽ **tích lũy**. Vì vậy **bắt buộc** có bộ kiểm tra đúng đắn và đối soát định kỳ.
- Thay đổi format snapshot: cần migration và tăng version (pod cũ không đọc được format mới). Rollout theo hai bước: ghi cả hai format, rồi mới đọc format mới.

## 5. Kế hoạch triển khai (khi được duyệt)

1. Benchmark kích thước key set nén thật ở 10M/30M.
2. Viết `filter.Sharded` (S mảnh, interface `Test/Add/Remove` như cũ) và test tương đương với `Layered`.
3. Format snapshot v3 (manifest + mảnh + key set) và `SnapshotStore` theo object.
4. Leader dựng tăng dần từ snapshot cũ + change_log; quét DB chỉ khi bootstrap hoặc đối soát.
5. Đối soát theo mảnh, có throttle, gắn với bộ kiểm tra đúng đắn.
6. Chạy lại toàn bộ chaos/scale test; đo RAM đỉnh leader, thời gian dựng mảnh, tải DB.

## 6. Câu hỏi cần mentor chốt

- Có chấp nhận snapshot lớn hơn (thêm khoảng 4–5 byte mỗi số) để đổi lấy việc không quét DB định kỳ không?
- Hạ tầng có S3/MinIO không? Ở quy mô 100M+ thì nên dùng.
- Tần suất đối soát toàn bảng chấp nhận được: 1 lần/ngày hay 1 lần/tuần?

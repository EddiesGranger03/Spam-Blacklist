# Runbook vận hành: filter 3 lớp, snapshot, leader, Pub/Sub

Dành cho người trực vận hành. Cơ chế được mô tả ở [LUONG_VA_DANH_MUC_HAM.md](LUONG_VA_DANH_MUC_HAM.md) (Luồng 1 và 3); số đo ở [SCALE_TEST.md](SCALE_TEST.md). Mỗi mục dưới đây là một tình huống: dấu hiệu, nguyên nhân, việc cần làm, và điều **không** cần làm.

## 0. Mô hình trong 30 giây

- Mỗi pod giữ filter trong RAM, gồm 3 lớp: **static** (binary fuse 8, ~1,13 byte/key, dựng từ snapshot), **delta** (Bloom nhỏ cho hash thêm sau snapshot) và **removed** (tập chính xác cho hash bị gỡ sau snapshot). Lớp nào nói "không có" thì chắc chắn không có; "có thể có" luôn được Postgres xác nhận, nên filter sai chỉ làm chậm, không làm sai kết quả.
- **Snapshot** của lớp static nằm trong Postgres (`filter_snapshots` + `filter_snapshot_chunks`, migration 006), kèm con trỏ `(xid, seq)` của `change_log`. Pod mới tải snapshot, kiểm checksum rồi **replay `change_log` sau con trỏ**: không quét `blacklist_entries`.
- **Leader** là pod giữ advisory lock `727275` (một session Postgres riêng). Chỉ leader quét bảng và ghi snapshot (mỗi `FILTER_SNAPSHOT_INTERVAL`). Lock tự nhả khi session chết, pod khác tiếp quản ở lần poll kế (`FILTER_SNAPSHOT_POLL`). Lỗi dựng/lưu snapshot được thử lại với **backoff mũ có jitter** (`FILTER_RETRY_BASE` đến `FILTER_RETRY_MAX`) và khi `Save` lỗi thì leader **giữ filter đã dựng trong RAM, chỉ thử lại Save, không quét lại bảng**.
- **Đồng bộ giữa pod**: pod ghi publish `{seq_max, [hash, op]}` lên Redis sau commit; pod nhận áp ngay hash `add` rồi đọc `change_log` để áp đúng thứ tự (kể cả `remove`). `change_log` là nguồn sự thật; Pub/Sub chỉ để nhanh. Safety poll (`SAFETY_POLL_INTERVAL`) bắt message bị mất; mất Redis thì quay về poll nhanh (`POLL_INTERVAL`).

## 1. Biến cấu hình liên quan

| Biến | Mặc định | Ý nghĩa và khi nào đổi |
|---|---|---|
| `FILTER_SNAPSHOT_INTERVAL` | `1h` | Leader dựng snapshot mới mỗi chừng này. Ngắn hơn = replay lúc khởi động ngắn hơn nhưng tốn một lần quét bảng mỗi lần. Phải nhỏ hơn nhiều so với 23h (xem `MaxAge` bên dưới) |
| `FILTER_SNAPSHOT_POLL` | `30s` | Chu kỳ mỗi pod tìm snapshot mới, và chu kỳ thử giành leader. Cũng là thời gian tối đa để một pod mới nhận ra leader cũ đã chết |
| `FILTER_SNAPSHOT_KEEP` | `3` | Số snapshot giữ lại (mỗi cái ≈ 1,13 byte × số hash) |
| `FILTER_BOOTSTRAP_TIMEOUT` | `10m` | Pod không phải leader chờ snapshot quá lâu thì ghi **log lỗi** mỗi chừng này (vẫn tiếp tục chờ, `/readyz` 503) |
| `FILTER_SCAN_BATCH` | `5000` | Số dòng mỗi trang khi leader quét bảng, tối đa 5000 (giá trị lớn hơn bị hạ về 5000 để mỗi query nhẹ cho DB) (keyset trên `id`, từng partition một) |
| `FILTER_SCAN_PAUSE` | `2ms` | Nghỉ giữa các trang để không đè Postgres khi quét. Tăng khi DB đang chịu tải; đặt `0` khi rebuild thủ công lúc ít tải |
| `FILTER_RETRY_BASE` | `5s` | Chờ bao lâu sau lần dựng/lưu snapshot lỗi đầu tiên; gấp đôi mỗi lần lỗi liên tiếp, có jitter (50% đến 100% giá trị tính được) |
| `FILTER_RETRY_MAX` | `10m` | Trần của thời gian chờ đó (jitter không bao giờ vượt trần) |
| `FILTER_DELTA_REBUILD_RATIO` | `0.7` | F10: leader dựng snapshot **sớm** khi số hash thêm sau snapshot ≥ tỉ lệ này × sức chứa delta (sức chứa = 5% số phần tử static, tối thiểu 1.048.576). Vượt 1,0 thì FPR delta tăng vọt (4× sức chứa đo được FPR 68%). Số âm = tắt |
| `FILTER_REMOVED_REBUILD_MAX` | `1000000` | F10: ... hoặc khi removed-set (map chính xác, ~24 đến 48 B/hash, mọi `Test` phải lấy read-lock khi nó khác rỗng) chứa từng này hash (~48 MB/pod). Số âm = tắt |
| `FILTER_MIN_REBUILD_GAP` | `5m` | F10: khoảng cách tối thiểu giữa lần snapshot trước và một lần dựng sớm, để import dài không làm leader quét bảng liên tục. Dựng sớm vẫn tuân backoff `FILTER_RETRY_*` |
| `SAFETY_POLL_INTERVAL` | `30s` | Khi đang subscribe Redis: poll `change_log` thưa chừng này, chỉ để bắt message bị mất. **Đây là cận trên độ trễ khi mất message** |
| `POLL_INTERVAL` | `1s` | Poll nhanh khi KHÔNG có Redis (không cấu hình hoặc đang mất). **Đây là cận trên độ trễ khi mất Redis** |
| `SYNC_CHANNEL` | `vsf:changes` | Kênh Pub/Sub. Dùng chung một Redis cho nhiều môi trường thì phải đổi, nếu không staging đánh thức production (vô hại về đúng sai nhưng gây poll thừa) |
| `FILTER_VERIFY_INTERVAL` | `1m` | Chu kỳ bộ kiểm tra âm tính giả (mục 11). `0` = tắt |
| `FILTER_VERIFY_SAMPLE` | `1000` | Số hash BLACKLIST lấy mẫu mỗi chu kỳ. Chi phí ≈ đọc `3 × SAMPLE / số dòng mỗi trang` trang ngẫu nhiên (~50 trang cho 1000) trên read pool |
| `BLOOM_EXPECTED_ITEMS` | `10000000` | Chỉ còn là gợi ý dung lượng cho lần quét đầu; không phải giới hạn |

Giới hạn cố định trong code (không có biến môi trường): `MaxAge` = `changeLogRetention − 1h` = **23h** (snapshot già hơn bị từ chối vì `change_log` sau con trỏ có thể đã bị xóa; `change_log` giữ 24h); timeout publish 250 ms; ping Pub/Sub mỗi 5 s; backoff subscribe lại 1 s đến 15 s.

## 2. Deploy (rolling restart)

**Bình thường**: cứ rolling restart. Có snapshot hợp lệ thì mỗi pod mới sẵn sàng sau khoảng 0,1 đến 0,3 s ở 10M hash (đo thật, xem SCALE_TEST) mà **không đọc một dòng nào của `blacklist_entries`**. Pod cũ chưa tắt vẫn phục vụ.

**Triển khai lần đầu / sau khi xóa snapshot / sau xoay `DATA_PEPPER` (hash đổi hết)**: chưa có snapshot hợp lệ. N pod khởi động cùng lúc thì **chỉ một pod (leader) quét bảng**, các pod còn lại không ready (`/readyz` 503) cho tới khi leader ghi xong snapshot. Thời gian ≈ thời gian quét (12 đến 14 s ở 10M, tuyến tính theo số dòng: ước tính ~20 phút ở 1 tỷ dòng chưa đo). Vì vậy:

1. Đừng đặt readiness probe/`maxUnavailable` sao cho tất cả pod cũ bị tắt trước khi có một pod mới ready. Với deploy đầu tiên của tính năng này, hãy dựng snapshot trước khi tắt pod cũ: khởi động **một** pod mới, chờ log `filter snapshot built`, rồi mới rolling phần còn lại.
2. `FILTER_BOOTSTRAP_TIMEOUT` chỉ là ngưỡng cảnh báo, không bắt pod thoát.

**Xoay `DATA_PEPPER` (`cmd/rotate-pepper`, OFFLINE)**: `value_hash` của mọi dòng đổi, snapshot cũ (vẫn đúng checksum) chứa hash pepper cũ; nếu được cài, **mọi số BLACKLIST bị báo an toàn** (phát hiện G1, SCALE_TEST mục 10). Quy trình:

1. Dừng **mọi** instance (kể cả leader).
2. Chạy `rotate-pepper` (dry-run trước, rồi chạy thật). Lần chạy thật **xóa mọi snapshot không thuộc hash domain của pepper mới** ngay từ đầu (kết quả có `SnapshotsDropped`, audit `entry.pepper_rotate` có `snapshots_dropped`), rồi mới ghi lại các dòng. Chạy lại sau khi bị ngắt vẫn an toàn.
3. Khởi động lại với `DATA_PEPPER` mới theo quy trình cold deploy ở trên: không có snapshot hợp lệ → một leader quét bảng, các pod khác chờ (503) tới khi có snapshot mới.
4. Xác nhận: `SELECT id, domain_id, created_at FROM filter_snapshots WHERE complete AND NOT corrupt;` chỉ còn bản mới (một `domain_id` duy nhất); `vsf_bloom_false_negative_total` = 0.

Lớp bảo vệ thứ hai (kể cả khi quên bước 2 hoặc xóa snapshot bằng tay thất bại): mỗi snapshot mang **hash domain** = 8 byte đầu HMAC(khóa blind suy từ pepper, `"vsf-filter-domain-v1"`) (không lộ pepper; chạy không mã hóa dùng hằng `PlainDomain`), lưu ở header file (format v2) và cột `filter_snapshots.domain_id` (migration 008). Pod chỉ liệt kê/cài snapshot cùng domain; snapshot khác domain bị bỏ qua (log `filter snapshot built under another DATA_PEPPER; skipping it`), **không** bị đánh dấu corrupt, và được `Prune` xóa sau 1 ngày. Snapshot format v1 (trước bản sửa) có domain 0, không bao giờ khớp → sau khi nâng cấp, lần khởi động đầu cũng là cold deploy.

**Sau `cmd/rekey`** (chỉ đổi `DATA_KEY`, không đổi pepper): hash không đổi, snapshot vẫn dùng được.

## 3. Pod không ready (`/readyz` 503)

| Dấu hiệu trong log | Nghĩa là | Việc làm |
|---|---|---|
| `still waiting for a filter snapshot from the leader` | Chưa có snapshot hợp lệ và pod này không phải leader | Tìm pod giữ lock: `SELECT pid, application_name, state, now()-query_start FROM pg_stat_activity WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype='advisory' AND objid=727275 AND granted);`. Có kết quả = leader đang quét, cứ chờ. Không có kết quả = không pod nào dám làm leader: kiểm tra pod còn chạy `syncer.Run`, kết nối primary |
| `filter full build failed` / `filter snapshot build failed; will retry after backoff` | Leader quét lỗi (mất kết nối DB, hết RAM) | Xem `err`. Pod tự thử lại với backoff mũ (5 s, 10 s, 20 s … tối đa 10 phút). Hết RAM: quét cần ≈ 8 byte/key cho slice khóa + ≈ 24 byte/key khi dựng (mục 8 trong SCALE_TEST) |
| `filter snapshot is corrupt; flagging it and trying an older one` | Một snapshot hỏng, đã bị đánh dấu `corrupt`; pod thử bản cũ hơn | Thường không cần làm gì (mục 4) |
| `no usable filter snapshot: asked the leader to build one` | Không còn snapshot tốt; pod đã ghi yêu cầu rebuild | Leader sẽ dựng ở lần poll kế (mục 4). Nếu mãi không thấy `filter snapshot built`: kiểm tra có leader không (mục 9) và `filter snapshot … failed; will retry after backoff` |
| `filter snapshot save failed; will retry after backoff` | `Save` lỗi (đĩa đầy, mất kết nối primary). Filter đã dựng được **giữ trong RAM**, lần sau chỉ thử lại Save | Sửa nguyên nhân (đĩa, DB). Không cần restart; theo dõi `vsf_filter_snapshot_pending_save` và `vsf_filter_snapshot_consecutive_failures` |
| `snapshot … is … old (max 23h)` (`ErrStale`) | Leader không dựng snapshot suốt 23h; replay không còn an toàn | Mục 5: ép rebuild |

## 4. Snapshot hỏng

Hành vi (đã test với 10M hash, xem SCALE_TEST): pod duyệt các snapshot theo thứ tự **mới đến cũ**. Snapshot sai checksum, thiếu chunk hoặc sai metadata **không bao giờ được cài**; nó bị **đánh dấu `corrupt`** trong `filter_snapshots` (cột `corrupt`, `corrupt_reason`) nên không pod nào thử lại, rồi pod dùng bản tốt kế tiếp và replay `change_log` sau con trỏ của nó. Không quét bảng. Bản quá cũ (hơn 23 giờ) thì bỏ qua, không đánh dấu hỏng. Lỗi tạm thời (mất kết nối DB lúc đọc) **không** đánh dấu gì.

Khi **không còn** bản nào dùng được, pod ghi một **yêu cầu rebuild** (`filter_rebuild_requests`, bộ đếm `requests`/`handled`). Chỉ một yêu cầu được ghi tại một thời điểm dù bao nhiêu pod cùng hỏi; leader (đang chạy hay vừa khởi động) thấy `requests > handled` thì dựng ngay (vẫn tuân backoff khi lỗi) và đặt `handled` = `requests` sau khi lưu xong. Vậy không còn tình trạng pod mới chờ tới lần dựng theo lịch (mặc định 1 giờ).

Kiểm tra và can thiệp thủ công (hiếm khi cần):

```sql
SELECT id, items, size_bytes, chunks, complete, corrupt, corrupt_reason, created_at FROM filter_snapshots ORDER BY id DESC;
SELECT requests, handled, updated_at FROM filter_rebuild_requests;   -- requests > handled = đang chờ leader dựng
-- ép dựng lại ngay (leader sẽ làm ở lần poll kế):
UPDATE filter_rebuild_requests SET requests = handled + 1 WHERE requests <= handled;
-- đánh dấu tay một bản nghi ngờ (pod sẽ dùng bản cũ hơn):
UPDATE filter_snapshots SET corrupt = true, corrupt_reason = 'manual' WHERE id = <id>;
```

Bản hỏng được giữ 1 ngày để điều tra rồi `Prune` xóa. Snapshot dở dang (leader bị kill giữa lúc ghi) **không cần dọn**: `Save` chạy trong một transaction, kill giữa chừng thì Postgres rollback sạch (đã test: 0 dòng mồ côi). Dòng `complete=false` cũ quá 1 giờ cũng bị `Prune` xóa.

Theo dõi: metric `vsf_filter_snapshot_fallbacks_total` (dùng bản cũ), `vsf_filter_snapshot_corrupt_flagged_total`, `vsf_filter_rebuild_requests_total`; `/readyz` (loopback) có mục `snapshot`.

## 5. Rebuild thủ công

Khi nào: nghi filter sai (`vsf_bloom_false_negative_total` > 0, phải luôn bằng 0), sau khi sửa dữ liệu trực tiếp bằng SQL (không qua API nên không có dòng `change_log`), sau xoay `DATA_PEPPER`, hoặc leader không dựng được snapshot suốt gần 23h.

1. Cách nhẹ nhất khi có leader đang chạy: ghi yêu cầu rebuild (câu `UPDATE filter_rebuild_requests …` ở mục 4); leader dựng ở lần poll kế (≤ `FILTER_SNAPSHOT_POLL`) và mọi pod nhận snapshot mới. Không cần restart.
   Muốn loại bỏ hoàn toàn snapshot cũ (xoay pepper đã tự làm việc này, xem mục 2): `DELETE FROM filter_snapshots;` (an toàn: pod đang chạy giữ filter trong RAM) rồi ghi yêu cầu rebuild như trên.
2. Nếu không có leader nào đang chạy: restart **một** pod; nó giành lock và dựng. Pod khác đang chạy sẽ tự nhận snapshot mới ở lần poll kế. Nếu xóa snapshot rồi restart toàn bộ thì áp dụng mục 2 (cold deploy).
3. Quét tốn đọc toàn bảng: làm lúc ít tải; tăng `FILTER_SCAN_PAUSE` để nhường DB, hoặc đặt `FILTER_SCAN_PAUSE=0` nếu cần nhanh và DB rảnh.
4. Xác nhận: log `filter snapshot built` (có `items`, `bytes`, `took`) và `SELECT id, items, complete FROM filter_snapshots`.

Pod **đang chạy** không tự dựng lại từ bảng: nó chỉ áp snapshot mới do leader ghi. (Vì thế sau khi sửa dữ liệu bằng SQL trực tiếp, hash bị gỡ vẫn còn trong filter pod cũ cho đến khi pod nhận snapshot mới; hash thêm trực tiếp bằng SQL thì filter không biết, nên check có thể trả "an toàn" sai cho tới lúc snapshot kế. Luôn sửa qua API/store để có `change_log`.)

## 6. Redis down

Dấu hiệu: log `redis pub/sub subscription lost`, metric `vsf_sync_subscribed` = 0, `vsf_sync_fallback_total` tăng, log `change notification publish failed`, `/readyz` có cảnh báo.

Hệ thống chạy tiếp, **không sai dữ liệu**:
- Ghi vẫn thành công (publish là best-effort, bị chặn bởi `REDIS_OP_TIMEOUT` 100 ms; breaker mở thì gần 0).
- Mỗi pod chuyển sang poll `change_log` mỗi `POLL_INTERVAL` (1 s): độ trễ đồng bộ tăng từ vài ms lên ≤ 1 s (đã đo).
- Cache kết quả (`REDIS_ADDR`) và rate limit cũng dùng Redis: cache lỗi thì check đi xuống DB (chậm hơn), rate limit **cho qua** (fail-open).

**Redis treo** (`docker pause`, mạng đen: TCP nhận nhưng không trả lời) khác Redis chết: trước F9 mỗi check mất 5 s. Nay mọi thao tác Redis trên đường request bị chặn ở `REDIS_OP_TIMEOUT` (mặc định 100 ms); sau `REDIS_BREAKER_FAILURES` (3) lỗi liên tiếp, breaker mở và bỏ qua Redis trong `REDIS_BREAKER_COOLOFF` (2 s) rồi thử lại một lệnh. Dấu hiệu: `vsf_redis_breaker_open` = 1, `vsf_redis_breaker_short_circuits_total` tăng, `vsf_cache_errors_total`/`vsf_ratelimit_backend_errors_total` tăng. Hệ quả chấp nhận được: không có cache (tải DB tăng theo tỉ lệ miss), rate limit và quota **không còn hiệu lực** (fail-open) trong lúc treo, publish lỗi (pod khác bắt kịp qua poll). Đừng tăng `REDIS_OP_TIMEOUT` để "ít lỗi hơn": nó cộng thẳng vào độ trễ check khi Redis có sự cố.

Việc làm: khôi phục Redis. Khi Redis về, mỗi pod subscribe lại với backoff 1 s đến 15 s và **resync ngay** (đọc `change_log` từ con trỏ) nên không mất thay đổi nào. Không cần restart pod. Nếu Redis down lâu và tải DB tăng vì poll 1 s × số pod: tăng `POLL_INTERVAL` (đánh đổi độ trễ).

## 7. Đồng bộ chậm hoặc lệch giữa các pod

1. `vsf_sync_subscribed` = 1 ở mọi pod? Nếu không: mục 6.
2. `vsf_sync_publish_to_apply_seconds` (histogram): p99 nên ở mức mili giây. Cao bất thường nghĩa là pod nhận bận (SyncNow chậm vì DB) chứ không phải Redis.
3. `changefeed_lag_seconds` và `/readyz`: lần poll thành công gần nhất > 30 s thì pod báo not ready.
4. Một giao dịch mở rất lâu trên Postgres giữ `xmin`: `/readyz` cảnh báo `changefeed_stalled`. Hash **thêm** vẫn được áp ngay; hash **gỡ** (op=2, WHITELIST/xóa) bị hoãn đến khi giao dịch đó đóng, để không gây âm tính giả. Tìm và xử lý giao dịch treo (`pg_stat_activity`, `state='idle in transaction'`).
5. Có replica: `vsf_sync_catchup_wait_seconds` cao hoặc `vsf_sync_catchup_total{result="timeout"}` tăng = replica trễ (mục 10).
6. Mất message đơn lẻ: tự lành ≤ `SAFETY_POLL_INTERVAL` (30 s mặc định). Không cần làm gì.

## 8. Leader chết

Không cần làm gì. Session Postgres của leader chết thì advisory lock nhả ngay; pod khác giành lock ở lần `FILTER_SNAPSHOT_POLL` kế (tối đa 30 s) và dựng snapshot khi đến hạn `FILTER_SNAPSHOT_INTERVAL`. Trong lúc không có leader, mọi pod vẫn phục vụ và vẫn đồng bộ bằng `change_log`; hậu quả duy nhất là snapshot cũ dần (ảnh hưởng thời gian replay của pod khởi động mới, và nếu quá 23h thì mục 3).

## 9. Kiểm tra nhanh trạng thái

```sql
SELECT id, items, size_bytes, chunks, complete, created_at, now()-created_at AS age FROM filter_snapshots ORDER BY id DESC;
SELECT max(seq) AS head, count(*) FILTER (WHERE created_at > now() - interval '1 hour') AS last_hour FROM change_log;
SELECT pid, application_name, now()-backend_start AS up FROM pg_stat_activity
 WHERE pid IN (SELECT pid FROM pg_locks WHERE locktype='advisory' AND objid=727275 AND granted);   -- leader hiện tại
```

Metric Prometheus (mỗi pod):

| Metric | Ý nghĩa |
|---|---|
| `vsf_filter_leader` | 1 nếu pod này đang giữ lock leader |
| `vsf_filter_snapshot_age_seconds`, `vsf_filter_snapshot_id` | tuổi và id snapshot mà filter đang phục vụ được dựng từ đó |
| `vsf_filter_snapshot_consecutive_failures` | số lần dựng/lưu lỗi liên tiếp (đang backoff nếu > 0) |
| `vsf_filter_snapshot_pending_save` | 1 = đã dựng xong, đang chờ Save thành công |
| `vsf_filter_snapshot_build_failures_total`, `..._save_failures_total` | tổng lỗi quét/dựng và lỗi lưu |
| `vsf_filter_snapshot_fallbacks_total`, `..._corrupt_flagged_total` | số lần dùng bản cũ, số snapshot đã đánh dấu hỏng |
| `vsf_filter_rebuild_requests_total` | số yêu cầu rebuild pod này đã ghi |

Gợi ý cảnh báo: `vsf_filter_snapshot_consecutive_failures > 3` trong 15 phút (leader không lưu được), `sum(vsf_filter_leader) == 0` quá `2 × FILTER_SNAPSHOT_POLL` (không có leader), `vsf_filter_snapshot_age_seconds > 3 × FILTER_SNAPSHOT_INTERVAL`. Lớp delta (F10): `vsf_filter_delta_fill_ratio` (≥ 0,7 thì leader dựng sớm; > 1 kéo dài nghĩa là leader không dựng được hoặc `FILTER_MIN_REBUILD_GAP` quá dài so với tốc độ import), `vsf_filter_removed_items`, `vsf_filter_pressure_rebuilds_total` (số lần dựng sớm; tăng đều mỗi 5 phút trong lúc import lớn là bình thường). Cảnh báo gợi ý: `vsf_filter_delta_fill_ratio > 1` quá 15 phút.

`/readyz` (chỉ từ loopback) thêm mục `snapshot` (leader, snapshot_id, cursor, snapshot_age, số lỗi, pending_save, fallbacks…) và các cảnh báo `filter_snapshot_failing`, `filter_snapshot_old`. Những cảnh báo này **không** làm pod not-ready: filter đã sẵn sàng thì vẫn phục vụ đúng.

## 10. Nhiều instance và replica: lưu ý đã biết (chưa sửa)

Chi tiết và cách tái hiện ở [SCALE_TEST.md](SCALE_TEST.md) mục 9 và 10.

- **Khóa advisory (F5)**: leader giữ `pg_try_advisory_lock(727275)` trùng khóa của chuỗi audit. Triệu chứng: thao tác ghi ở portal admin (đăng nhập, tạo/sửa entry) treo ~10 s rồi lỗi khi có leader. Kiểm tra: `SELECT pid, wait_event_type, wait_event, left(query,60) FROM pg_stat_activity WHERE wait_event = 'advisory';`. Chưa có workaround trong cấu hình; cần sửa code (đổi khóa leader).
- **`READ_DATABASE_URL` (F6, ĐÃ SỬA)**: message Pub/Sub có thể tới trước khi replica nhận dòng `change_log`. Feed giờ tự thử lại catch-up với backoff 5 ms → 1 s (tối đa 10 s) tới khi đọc được `seq_max` đã báo; trong lúc chờ (`Pending`), checker hỏi lại primary khi replica nói "không khớp" và không cache kết quả âm. Không có cấu hình mới. Theo dõi: `vsf_sync_replica_behind_total` (số lần replica chậm), `vsf_sync_catchup_wait_seconds` (thời gian chờ bắt kịp, p99 nên ≈ độ trễ replica), `vsf_sync_catchup_total{result="timeout"}` (> 0: replica trễ > 10 s, xem `pg_stat_replication`; khi đó quay về safety poll), `vsf_check_negative_uncached_total`.
- **Khởi động lần đầu trên DB rỗng (F7)**: bật pod đầu tiên, chờ `/readyz` = 200, rồi mới bật các pod còn lại; đặt chính sách khởi động lại khi lỗi.
- **Chạy nhiều máy**: xem SCALE_TEST.md mục 5 (biến môi trường, kiểm chứng bằng `go run ./cmd/multitest -nodes ...`).

## 11. Âm tính giả của filter (bộ kiểm tra `internal/verify`)

Mỗi pod, mỗi `FILTER_VERIFY_INTERVAL`, lấy mẫu `FILTER_VERIFY_SAMPLE` hash của dòng `status='BLACKLIST'` chưa hết hạn
(`TABLESAMPLE SYSTEM` trên read pool, không `ORDER BY random()`) và kiểm tra filter trong RAM có chứa chúng. Hash thiếu chỉ
bị tính là âm tính giả sau khi: SyncNow → vẫn thiếu → DB còn dòng hiệu lực (ghi nhận `id:xmin`) → SyncNow lần 2 → vẫn
thiếu → DB đọc lại cho cùng `id:xmin`. Nhờ vậy dòng vừa ghi chưa đồng bộ, dòng vừa bị xóa/WHITELIST, dòng bị sửa giữa
chừng **không** gây báo động giả (được đếm trong `vsf_filter_verify_suspect_discarded_total{reason=synced|gone|changed}`).

Metric:

| Metric | Ý nghĩa |
|---|---|
| `vsf_filter_verify_checked_total` | số hash đã kiểm tra |
| `vsf_filter_verify_false_negative_total` | âm tính giả đã xác nhận. **Phải luôn bằng 0** |
| `vsf_filter_verify_suspect_discarded_total{reason}` | nghi vấn bị loại vì là race (bình thường > 0 khi ghi nhiều) |
| `vsf_filter_verify_errors_total` | chu kỳ lỗi (DB/sync) |
| `vsf_filter_verify_duration_seconds` | thời gian một chu kỳ |

Cảnh báo nên đặt:

- **Page ngay**: `increase(vsf_filter_verify_false_negative_total[10m]) > 0`.
- **Bộ kiểm tra không chạy**: `rate(vsf_filter_verify_checked_total[10m]) == 0` trên pod ready (trong 15 phút), hoặc `increase(vsf_filter_verify_errors_total[15m]) > 5`.
- **Chậm**: `histogram_quantile(0.99, rate(vsf_filter_verify_duration_seconds_bucket[30m])) > 5` (giảm `FILTER_VERIFY_SAMPLE` hoặc xem tải replica).
- Theo dõi (không page): `rate(vsf_filter_verify_suspect_discarded_total{reason="synced"}[1h])` tăng mạnh = đồng bộ trễ (xem mục 7).

Khi phát hiện, pod tự làm (không cần người):

1. Log `ERROR filter FALSE NEGATIVE ... hash=<16 hex>` (chỉ hash, không có số điện thoại/URL).
2. Thêm lại hash đó vào filter (`healed=true`): chặn spam lọt qua cho riêng hash đó ngay lập tức.
3. Ghi một yêu cầu rebuild (`filter_rebuild_requests`): leader dựng snapshot mới từ bảng; các pod nạp snapshot mới sẽ sạch.
4. `/readyz` (loopback) có cảnh báo `filter_verify` trong 1 giờ. Pod **vẫn ready**: gạt nó khỏi load balancer không làm các
   pod khác đúng hơn, và hash bị thiếu đã được vá.

Người trực cần làm:

1. Xem phạm vi: chỉ một pod hay nhiều pod (`sum by (pod) (increase(vsf_filter_verify_false_negative_total[1h]))`).
   Vài hash là đã nghiêm trọng: mẫu 1000/phút trên hàng chục triệu dòng mà vẫn trúng nghĩa là tỉ lệ thiếu thật lớn hơn nhiều.
2. Một pod: khởi động lại pod đó (nạp lại snapshot + replay). Nhiều/tất cả pod: lỗi ở snapshot hoặc ở luồng ghi
   `change_log`: rebuild thủ công (mục 5) và đánh dấu snapshot đang dùng là hỏng (mục 4).
3. Tra hash trong DB (hash là `value_hash` dạng hex của BIGINT): `SELECT id, status, expires_at, updated_at FROM
   blacklist_entries WHERE value_hash = x'<hash>'::bigint;` và `SELECT * FROM change_log WHERE value_hash = x'<hash>'::bigint
   ORDER BY seq;`. Nghi vấn đã biết: `change_log` op=2 gỡ **theo hash**; nếu nhiều dòng chung một `value_hash` mà chỉ
   một dòng bị xóa/WHITELIST, hash bị gỡ dù dòng BLACKLIST còn lại → đúng là âm tính giả (bộ kiểm tra sẽ bắt được).
4. Sau rebuild, xác nhận `vsf_filter_verify_false_negative_total` ngừng tăng ít nhất 3 chu kỳ.

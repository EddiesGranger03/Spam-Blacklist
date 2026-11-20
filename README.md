# VSF – Spam Blacklist (số điện thoại + URL)

Backend Go quản lý danh sách SĐT/URL có nguy cơ spam, có **Admin Portal** (HTMX) và **Check API**
tối ưu cho hàng trăm triệu bản ghi (filter 3 lớp trong RAM + snapshot trong Postgres + Redis + PostgreSQL partition).

## Chạy nhanh (development)

### 1. Khởi động Postgres + Redis

```bash
docker compose -f deploy/docker-compose.yml up -d
```

### 2. Khởi chạy server

**Trên Windows (PowerShell):**
```powershell
$env:SESSION_SECRET = "dev-secret-not-for-production-0123456789"
$env:BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
$env:BOOTSTRAP_ADMIN_PASSWORD = "ChangeMe-12345"
$env:REDIS_ADDR = "localhost:6379"
$env:HTTP_ADDR = "127.0.0.1:8090"          # đổi nếu cổng 8080 đang bận
go run ./cmd/server
```

**Trên Linux / macOS (Bash):**
```bash
export SESSION_SECRET=dev-secret-not-for-production-0123456789
export BOOTSTRAP_ADMIN_EMAIL=admin@example.com
export BOOTSTRAP_ADMIN_PASSWORD='ChangeMe-12345'
export REDIS_ADDR=localhost:6379
export HTTP_ADDR=127.0.0.1:8090          # đổi nếu cổng 8080 đang bận
go run ./cmd/server
```

Mở `http://127.0.0.1:8090/admin/login` → đăng nhập bằng tài khoản bootstrap ở trên.
Vào **API keys** để tạo khóa rồi gọi:
     
```bash
curl -H "X-API-Key: vsf_xxxxxxxx_..." "http://127.0.0.1:8090/v1/check?type=phone&value=0901234567"
curl -H "X-API-Key: ..." -H 'Content-Type: application/json' \
     -d '{"items":[{"type":"phone","value":"0901234567"},{"type":"url","value":"http://evil.com/x"}]}' \
     http://127.0.0.1:8090/v1/check/batch
```

Dev nhanh không cần key (chỉ khi bind localhost): `AUTH_DISABLED=true`.

## Kiểm thử

```bash
# 1. Unit test (không cần DB)
go vet ./... && go test ./...

# 2. Tạo database test
docker compose -f deploy/docker-compose.yml exec postgres psql -U vsf -d vsf -c "CREATE DATABASE vsf_test"
```

**Test tích hợp (Store):**
- *Windows (PowerShell):*
  ```powershell
  $env:TEST_DATABASE_URL = "postgres://vsf:vsf@localhost:5433/vsf_test?sslmode=disable"
  go test ./internal/store/
  ```
- *Linux / macOS (Bash):*
  ```bash
  TEST_DATABASE_URL='postgres://vsf:vsf@localhost:5433/vsf_test?sslmode=disable' go test ./internal/store/
  ```
- *Cụm Postgres riêng cho test (khuyến nghị):*
  ```bash
  docker compose -f deploy/docker-compose.test.yml up -d --wait
  TEST_DATABASE_URL='postgres://vsf:vsf@localhost:5544/vsf_test?sslmode=disable' go test -count=1 -p 1 ./...
  docker compose -f deploy/docker-compose.test.yml down
  ```
  `TestChangeLogHeadAndPurge` tự bỏ qua nếu có transaction mở ở nơi khác trong cụm Postgres (đúng hành vi của `Head`, chỉ trả các dòng trước xmin của cả cụm), nên cần cụm riêng này để nó chạy chắc chắn. Chạy với `-p 1` vì các test store dùng chung database `vsf_test`.
- ⚠️ Test này **xóa sạch mọi bảng** của database được trỏ tới. Nó tự từ chối nếu tên database không kết thúc bằng `_test`. Tuyệt đối không trỏ vào database thật (`vsf`).

**End-to-End test qua HTTP (khi server đang chạy):**
```bash
BASE=http://127.0.0.1:8090 bash scripts/e2e.sh
```

## Benchmark

```bash
go run ./cmd/gencsv -n 1000000 -out data.csv          # sinh dữ liệu giả → import qua portal (Import/Export)
go run ./cmd/bench -url http://127.0.0.1:8090 -key vsf_... -file data.csv -c 64 -d 20s -hit 0.1
```

## Vận hành và đo quy mô

- [docs/RUNBOOK.md](docs/RUNBOOK.md): deploy, snapshot hỏng, Redis down, rebuild thủ công, cấu hình đồng bộ.
- [docs/SCALE_TEST.md](docs/SCALE_TEST.md): số đo filter/khởi động/chaos ở 10 triệu dòng, phần nào đo thật, phần nào ngoại suy. Chạy lại: `scripts/scale-test.sh` (test nặng, build tag `scale`, CI thường không chạy).

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `APP_ENV` | `development` | `production` bật các kiểm tra chặt (secret ≥ 32 ký tự, `COOKIE_SECURE=true`, cấm `AUTH_DISABLED`) |
| `HTTP_ADDR` | `127.0.0.1:8080` | địa chỉ nghe |
| `DATABASE_URL` | `postgres://vsf:vsf@localhost:5433/vsf?sslmode=disable` | Postgres primary (ghi) |
| `READ_DATABASE_URL` | (rỗng = dùng primary) | replica cho đường check + changefeed (phải dùng cùng một node) |
| `TRUSTED_PROXIES` | (rỗng) | Danh sách CIDR/IP reverse proxy, phân cách bằng dấu phẩy (vd `10.0.0.0/8,172.16.0.5`). Chỉ khi kết nối đến từ các địa chỉ này mới đọc `X-Forwarded-For` để lấy IP client (dùng cho throttle đăng nhập, audit, rate limit). Rỗng = luôn dùng địa chỉ kết nối trực tiếp. **Production bắt buộc** đặt biến này hoặc `TRUSTED_PROXIES_NONE=true`, nếu không server từ chối khởi động |
| `TRUSTED_PROXIES_NONE` | `false` | Chỉ dùng ở production: xác nhận rõ ràng là chạy không qua reverse proxy. Đặt cùng lúc với `TRUSTED_PROXIES` bị từ chối |
| `METRICS_TOKEN` | (rỗng) | Bearer token cho `/metrics`, tối thiểu 16 ký tự nếu có đặt. Rỗng = `/metrics` chỉ nhận request từ loopback (production ghi cảnh báo khi khởi động). `/readyz` chỉ hiện chi tiết lỗi cho loopback |
| `REDIS_PASSWORD` | (rỗng) | Mật khẩu Redis (docker-compose dev đặt mặc định `vsf-dev-redis`) |
| `PG_MAX_CONNS` | `32` | kích thước pool |
| `REDIS_ADDR` | (rỗng = tắt cache/quota) | Redis |
| `CACHE_TTL` | `10m` | TTL cache kết quả |
| `SESSION_SECRET` | **bắt buộc** | bí mật phiên |
| `COOKIE_SECURE` | `false` | `true` khi chạy HTTPS |
| `BOOTSTRAP_ADMIN_EMAIL/PASSWORD` | – | tạo admin đầu tiên khi bảng trống (mật khẩu ≥ 10 ký tự) |
| `AUTH_DISABLED` | `false` | bỏ API key (chỉ dev + localhost) |
| `INSPECTOR_SHOW_SOURCE` | `true` ở development, `false` ở production | Live Inspector hiện mã nguồn handler trong chi tiết request |
| `AUDIT_HMAC_KEY` | (dẫn xuất từ `SESSION_SECRET`) | Khóa HMAC nối chuỗi hash cho `audit_logs`. Nên đặt riêng, vì đổi `SESSION_SECRET` sẽ làm không xác minh được bản ghi cũ. Kiểm tra bằng `GET /admin/audit/verify` (admin) |
| `DATA_KEY` | **bắt buộc** | Bí mật ≥ 32 ký tự để mã hóa AES-256-GCM `value/note/source`. **Mất khóa = mất dữ liệu**, hãy sao lưu riêng khỏi DB |
| `DATA_PEPPER` | **bắt buộc** | Bí mật ≥ 32 ký tự, khác `DATA_KEY`, dùng cho blind index HMAC (và `value_hash`) |
| `DATA_KEY_VERSION` | `1` | Phiên bản của `DATA_KEY` hiện tại (1 đến 32767). Mỗi dòng lưu phiên bản của khóa đã mã hóa nó (`key_version`) và dùng đúng khóa đó để đọc |
| `DATA_KEY_V<n>` | – | Khóa **cũ** của phiên bản `<n>` (ví dụ `DATA_KEY_V1`), chỉ để ĐỌC dữ liệu chưa được mã hóa lại. Xem "Xoay khóa mã hóa" |
| `DEFAULT_REGION` | `VN` | mã quốc gia khi SĐT không có dấu `+` |
| `BLOOM_EXPECTED_ITEMS` | `10000000` | gợi ý dung lượng cho lần quét bảng đầu tiên (không còn là giới hạn; lớp static là binary fuse ~1,13 byte/hash) |
| `BLOOM_REBUILD_INTERVAL` | `24h` | **Không còn dùng.** Filter làm mới qua snapshot (`FILTER_SNAPSHOT_INTERVAL`) |
| `POLL_INTERVAL` | `1s` | tần suất đọc `change_log` khi **không có** Redis Pub/Sub (không cấu hình `REDIS_ADDR`, hoặc Redis đang mất): đây là độ trễ đồng bộ tối đa giữa các pod lúc đó |
| `SAFETY_POLL_INTERVAL` | `30s` | khi đang subscribe Redis: poll `change_log` thưa chừng này chỉ để bắt message Pub/Sub bị mất (cận trên độ trễ khi mất message) |
| `SYNC_CHANNEL` | `vsf:changes` | kênh Redis Pub/Sub báo thay đổi giữa các pod; đổi khi nhiều môi trường dùng chung một Redis |
| `FILTER_SNAPSHOT_INTERVAL` | `1h` | leader dựng snapshot filter mới (quét bảng một lần) mỗi chừng này; snapshot được lưu trong Postgres |
| `FILTER_SNAPSHOT_POLL` | `30s` | chu kỳ mỗi pod tìm snapshot mới và thử giành quyền leader (advisory lock `727275`) |
| `FILTER_SNAPSHOT_KEEP` | `3` | số snapshot giữ lại |
| `FILTER_BOOTSTRAP_TIMEOUT` | `10m` | pod chờ snapshot của leader quá lâu thì ghi log lỗi mỗi chừng này (vẫn chờ, `/readyz` 503) |
| `FILTER_RETRY_BASE` / `FILTER_RETRY_MAX` | `5s` / `10m` | backoff mũ (có jitter) sau lần dựng/lưu snapshot lỗi; `Save` lỗi thì chỉ thử lại Save, không quét lại bảng |
| `FILTER_SCAN_BATCH` / `FILTER_SCAN_PAUSE` | `5000` / `2ms` | số dòng mỗi trang (tối đa 5000) và thời gian nghỉ giữa các trang khi leader quét bảng (giảm tải DB) |
| `RATE_LIMIT_RPS` | `100` | giới hạn mặc định mỗi key; có `REDIS_ADDR` thì bộ đếm nằm ở Redis, dùng chung mọi instance (Redis lỗi thì cho qua), không có Redis thì đếm trong bộ nhớ từng instance |
| `DATA_PEPPER_OLD` | – | chỉ cho `cmd/rotate-pepper`: pepper mà dữ liệu đang lưu dưới nó, xem "Xoay DATA_PEPPER" |

## Mã hóa dữ liệu lưu trữ

- `blacklist_entries` không còn cột plaintext: `value_enc`, `note_enc`, `source_enc` là AES-256-GCM; tra cứu dùng `value_blind` = HMAC-SHA256(pepper, type|match_type|value); `value_hash` (khóa partition và filter) là 8 byte đầu của blind index nên không dò ngược được số điện thoại.
- Mọi kiểu khớp (`exact`/`prefix`/`domain`) vẫn hoạt động vì checker chỉ so sánh bằng (đẳng thức) trên các candidate key.
- Khóa nằm trong biến môi trường `DATA_KEY`, `DATA_PEPPER`. Với `start.bat`, đặt chúng trong file `.env.local.bat` (đã nằm trong `.gitignore`, không commit): `set DATA_KEY=...` và `set DATA_PEPPER=...`.
- Lần khởi động đầu tiên sau khi nâng cấp tự chuyển bảng cũ sang bảng mã hóa trong **một transaction** (khoảng 15 giây cho ~1 triệu dòng): sao chép, xác minh số dòng và mẫu giải mã, rồi mới đổi tên bảng và xóa bảng plaintext. Lỗi bất kỳ thì rollback, bảng cũ còn nguyên. Hãy `pg_dump` trước khi nâng cấp.
- Audit log, cache Redis và inspector đều không chứa giá trị gốc (che hoặc mã hóa).
- **Khi khởi động, server tự kiểm tra khóa** trên một mẫu dữ liệu thật (125 dòng: cũ nhất, mới nhất, vài chỗ ngẫu nhiên; 38 ms với 1 triệu dòng) và **từ chối chạy** nếu khóa cấu hình không đọc được dữ liệu: thiếu `DATA_KEY_V<n>`, sai `DATA_KEY`, hoặc sai `DATA_PEPPER` (sai pepper làm mọi tra cứu hỏng một cách âm thầm, nên được chặn ngay lúc khởi động).

## Xoay khóa mã hóa

Chỉ xoay được `DATA_KEY`. **Không** có công cụ xoay `DATA_PEPPER` (nó đổi `value_hash`/`value_blind` của mọi dòng); server chỉ phát hiện và chặn khởi động khi pepper bị đổi nhầm.

Mỗi dòng có **một** `key_version` cho cả ba cột `value_enc`, `note_enc`, `source_enc`. Đổi `DATA_KEY` mà không làm các bước dưới đây thì server từ chối khởi động (trước đây nó vẫn khởi động rồi trả lỗi 500 ở `/v1/check`).

1. **Sao lưu** (`pg_dump`) và sao lưu riêng **cả hai khóa**, ngoài DB.
2. Khai báo khóa mới và giữ khóa cũ, rồi khởi động lại server (giả sử khóa đang dùng là phiên bản 1):
   ```
   DATA_KEY=<khóa mới>
   DATA_KEY_VERSION=2
   DATA_KEY_V1=<khóa cũ>
   ```
   Từ lúc này dòng mới và dòng được sửa hoặc import lại được mã hóa bằng khóa mới; dòng cũ vẫn đọc được. Server báo cảnh báo "some rows are still sealed under an older key".
3. Mã hóa lại dòng cũ bằng `rekey`, **chạy với đúng biến môi trường của server**, được phép chạy khi server đang chạy và chạy lại được nếu bị ngắt:
   ```
   go run ./cmd/rekey -status     # số dòng theo từng phiên bản khóa (quét cả bảng)
   go run ./cmd/rekey -dry-run    # giải mã thử mọi dòng sẽ đổi, không ghi gì
   go run ./cmd/rekey             # mã hóa lại
   ```
   Đo thật: 1 triệu dòng mất khoảng 27 giây (~37.000 dòng/giây); 9,76 triệu dòng mất khoảng 29 phút (~5.600 dòng/giây), tức chậm hơn trên mỗi dòng khi bảng lớn hơn bộ nhớ đệm, nên không ngoại suy tuyến tính. `rekey` chỉ đổi bản mã và `key_version`, không đổi nội dung, `value_hash`, `value_blind` hay `updated_at`.
4. Khi `rekey -status` cho thấy **không còn dòng nào** ở phiên bản cũ thì mới bỏ `DATA_KEY_V1`.

**Cảnh báo:** các bản sao lưu làm *trước* khi xoay khóa vẫn mã hóa bằng khóa cũ. Hãy giữ khóa cũ chừng nào còn có thể cần khôi phục từ chúng. Mất khóa là mất dữ liệu, không công cụ nào cứu được.

## Xoay DATA_PEPPER

Pepper khóa blind index (`value_blind`, `value_hash`) của **mọi** dòng, nên khác với xoay `DATA_KEY`, **phải dừng toàn bộ server** trong lúc xoay: server chạy pepper cũ không tìm thấy dòng đã xoay và sẽ báo số bị chặn là an toàn.

1. `pg_dump` và sao lưu cả hai pepper ngoài DB. **Dừng mọi instance.**
2. Đặt `DATA_PEPPER=<pepper mới>` và `DATA_PEPPER_OLD=<pepper hiện tại>`, cùng các biến còn lại như server.
3. `go run ./cmd/rotate-pepper -dry-run` (giải mã và kiểm tra mọi dòng, không ghi), rồi `go run ./cmd/rotate-pepper -servers-stopped`. Chạy lại được nếu bị ngắt. Đo thật: 300 nghìn dòng mất khoảng 6 giây.
4. Xóa snapshot filter cũ (`DELETE FROM filter_snapshots;`: hash đã đổi nên snapshot cũ không còn dùng được), rồi khởi động lại các instance với `DATA_PEPPER` mới: leader quét bảng và dựng snapshot mới, xem [docs/RUNBOOK.md](docs/RUNBOOK.md) mục 2. Giữ pepper cũ chừng nào còn cần khôi phục từ bản sao lưu trước khi xoay.

Server cấu hình pepper mới trước khi xoay sẽ từ chối khởi động.

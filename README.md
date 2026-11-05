# VSF – Spam Blacklist (số điện thoại + URL)

Backend Go quản lý danh sách SĐT/URL có nguy cơ spam, có **Admin Portal** (HTMX) và **Check API**
tối ưu cho hàng trăm triệu bản ghi (Bloom filter + Redis + PostgreSQL partition).

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

## Biến môi trường

| Biến | Mặc định | Ý nghĩa |
|---|---|---|
| `APP_ENV` | `development` | `production` bật các kiểm tra chặt (secret ≥ 32 ký tự, `COOKIE_SECURE=true`, cấm `AUTH_DISABLED`) |
| `HTTP_ADDR` | `127.0.0.1:8080` | địa chỉ nghe |
| `DATABASE_URL` | `postgres://vsf:vsf@localhost:5433/vsf?sslmode=disable` | Postgres primary (ghi) |
| `READ_DATABASE_URL` | (rỗng = dùng primary) | replica cho đường check + changefeed (phải dùng cùng một node) |
| `PG_MAX_CONNS` | `32` | kích thước pool |
| `REDIS_ADDR` | (rỗng = tắt cache/quota) | Redis |
| `CACHE_TTL` | `10m` | TTL cache kết quả |
| `SESSION_SECRET` | **bắt buộc** | bí mật phiên |
| `COOKIE_SECURE` | `false` | `true` khi chạy HTTPS |
| `BOOTSTRAP_ADMIN_EMAIL/PASSWORD` | – | tạo admin đầu tiên khi bảng trống (mật khẩu ≥ 10 ký tự) |
| `AUTH_DISABLED` | `false` | bỏ API key (chỉ dev + localhost) |
| `DEFAULT_REGION` | `VN` | mã quốc gia khi SĐT không có dấu `+` |
| `BLOOM_EXPECTED_ITEMS` | `10000000` | kích thước Bloom tối thiểu (tự nới theo số dòng ước lượng ×1,3) |
| `BLOOM_REBUILD_INTERVAL` | `24h` | dựng lại Bloom định kỳ |
| `POLL_INTERVAL` | `1s` | tần suất đọc `change_log` |
| `RATE_LIMIT_RPS` | `100` | giới hạn mặc định mỗi key |

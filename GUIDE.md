# HƯỚNG DẪN TỰ CODE: Spam Blacklist (SĐT + URL) bằng Go

> Bạn tự code, mình chỉ hướng dẫn. Mỗi bước có: **Mục tiêu → File → Làm gì → Cạm bẫy → Cách kiểm tra**.
> Làm tuần tự từ Bước 0 đến 9. Xong bước nào hãy chạy kiểm tra của bước đó rồi mới sang bước tiếp.
> Khi kẹt hoặc muốn mình review code, dán đoạn code/lỗi vào chat.

---

## 0. Khái niệm cần nắm trước (đọc 15 phút)

| Khái niệm | Hiểu đơn giản | Dùng ở đâu |
|---|---|---|
| **Normalize** | Đưa dữ liệu về 1 dạng chuẩn: `0901 234 567` và `+84901234567` là cùng 1 số | Cả khi lưu và khi check |
| **Hash (xxhash64)** | Biến chuỗi dài thành số 64-bit; so số nhanh hơn so chuỗi | Cột `value_hash`, index, Bloom |
| **Bloom filter** | Mảng bit trong RAM. Trả lời "CHẮC CHẮN KHÔNG có" hoặc "CÓ THỂ có". Không bao giờ sai kiểu "không" khi thực ra có | Lọc 95%+ request, không cần chạm DB |
| **Singleflight** | 1000 request cùng key đến cùng lúc → chỉ 1 request chạy xuống DB, 999 request còn lại chờ kết quả chung | Chống quá tải DB |
| **Partition** | Chia 1 bảng khổng lồ thành nhiều bảng nhỏ theo hash | Postgres với vài trăm triệu dòng |

**Luồng check (nhớ sơ đồ này):**
```
input → normalize → sinh danh sách key ứng viên → Bloom (loại key chắc chắn không có)
      → hết key? → trả SAFE
      → còn key → Redis cache? → có: trả luôn
                              → không: Postgres (singleflight) → lưu cache → trả kết quả
```

**Nguyên tắc vàng:** Bloom chỉ để *loại bỏ nhanh*. Câu trả lời "bị blacklist" luôn phải được **Postgres xác nhận** → độ chính xác 100%.

---

## Bước 0 — Chuẩn bị môi trường (đã xong một phần)

Đã có sẵn: `go.mod` (module `vsf`), các thư mục rỗng. Máy bạn có Go 1.27 và Docker.

1. Sửa dòng `go` trong `go.mod` thành `go 1.23` (cần ≥ 1.23 vì dùng `atomic.OrUint64`).
2. Cài thư viện:
```bash
go get github.com/go-chi/chi/v5
go get github.com/jackc/pgx/v5
go get github.com/redis/go-redis/v9
go get github.com/nyaruka/phonenumbers
go get golang.org/x/net
go get golang.org/x/crypto
go get golang.org/x/sync
go get golang.org/x/time
go get github.com/cespare/xxhash/v2
go get github.com/prometheus/client_golang
```
3. Tạo `deploy/docker-compose.yml` gồm 2 service: `postgres:16` (port host `5433`→5432, đặt `POSTGRES_USER/PASSWORD/DB`) và `redis:7` (port `6379`). Chạy `docker compose -f deploy/docker-compose.yml up -d`.

**Kiểm tra:** `docker ps` thấy 2 container; kết nối được Postgres bằng `psql` hoặc DBeaver.

---

## Bước 1 — Config (`internal/config/config.go`)

**Mục tiêu:** đọc cấu hình từ biến môi trường, không hard-code mật khẩu trong code.

Làm: struct `Config` + hàm `Load() Config` dùng `os.Getenv` kèm giá trị mặc định. Các trường:

`AppEnv` (`development|production`), `HTTPAddr(:8080)`, `DatabaseURL` (primary, dùng để ghi), `ReadDatabaseURL` (replica, rỗng = dùng primary), `RedisAddr` (rỗng = tắt cache), `SessionSecret` (bắt buộc, dùng ký/mã hoá phụ), `CookieSecure`, `BootstrapAdminEmail/Password` (chỉ dùng để tạo admin đầu tiên), `AuthDisabled` (chỉ hợp lệ khi `AppEnv=development` **và** `HTTPAddr` bind loopback, nếu không thì `log.Fatal`), `DefaultRegion("VN")`, `BloomExpectedItems(10_000_000)`, `BloomRebuildInterval(24h)`, `CacheTTL(10m)`, `PollInterval(1s)`, `RateLimitRPS(0 = tắt)`, `PGMaxConns(32)`.

Mẹo: viết helper nhỏ `getenv(key, def)`, `getenvInt`, `getenvDuration` (`time.ParseDuration`).

**Cạm bẫy:** thiếu `JWTSecret` thì `log.Fatal` ngay lúc khởi động, đừng chạy với secret rỗng.

---

## Bước 2 — Database migration (`internal/store/migrations/001_init.sql`)

**Mục tiêu:** tạo schema chịu được hàng trăm triệu dòng.

Các bảng:

1. **`blacklist_entries`** — `PARTITION BY HASH (value_hash)`
   - Cột: `id BIGINT` (default `nextval` từ 1 sequence riêng), `type` (`phone|url`), `match_type` (`exact|domain|prefix`), `value_normalized TEXT`, `value_hash BIGINT`, `category`, `risk_score SMALLINT (0..100)`, `source`, `note`, `expires_at TIMESTAMPTZ NULL`, `created_by`, `created_at`, `updated_at`.
   - Thêm `CHECK` cho `type`, `match_type`, `risk_score`.
   - **Unique index** `(value_hash, type, match_type, value_normalized)` ← đây là index tra cứu chính. Với bảng partition, unique index **bắt buộc chứa cột partition** (`value_hash`) nên đặt `value_hash` đứng đầu.
   - Index thường trên `(id)` để Get/Update/Delete theo id.
   - Tạo 32 partition bằng 1 khối `DO $$ ... FOR i IN 0..31 LOOP EXECUTE format('CREATE TABLE blacklist_entries_p%s PARTITION OF blacklist_entries FOR VALUES WITH (MODULUS 32, REMAINDER %s)', i, i); END LOOP; $$;`
2. **`change_log`** (transactional outbox — hàng đợi sự kiện bền vững) — `seq BIGSERIAL PK`, `xid xid8 NOT NULL DEFAULT pg_current_xact_id()`, `value_hash BIGINT`, `created_at`; index `(xid, seq)` và `created_at`. (Vì sao cần: xem Bước 6.3. Cột `xid` để tránh bỏ sót sự kiện do commit sai thứ tự.)
3. **`audit_logs`** — `id`, `actor_id`, `actor_email`, `action`, `entry_id`, `detail JSONB`, `ip`, `created_at`.
4. **`admins`** — `id`, `email UNIQUE`, `password_hash`, `role` (`viewer|editor|admin`), `disabled BOOL`, `created_at`.
5. **`sessions`** — `id_hash BYTEA PK` (SHA-256 của cookie, **không lưu cookie gốc**), `admin_id`, `csrf_token`, `ip`, `user_agent`, `created_at`, `last_seen_at`, `expires_at`; index `expires_at`.
6. **`api_keys`** — `id`, `name`, `prefix TEXT UNIQUE` (8 ký tự đầu, dùng để tra), `key_hash BYTEA` (SHA-256 của phần secret), `status` (`active|revoked`), `rps_limit INT`, `daily_quota BIGINT`, `expires_at NULL`, `rotated_from NULL`, `created_by`, `created_at`, `last_used_at`, `revoked_at`. (Chi tiết Bước 8.)

Runner migration (`internal/store/store.go`): dùng `//go:embed migrations/*.sql`; lúc khởi động: lấy 1 connection, `SELECT pg_advisory_lock(727274)` (để nhiều instance không chạy migrate cùng lúc), tạo bảng `schema_migrations(version)`, chạy các file chưa áp dụng theo thứ tự tên, rồi unlock.

**Cạm bẫy:**
- Bảng partition **không dùng được** `GENERATED AS IDENTITY` ở Postgres 16 → dùng sequence + `DEFAULT nextval(...)`.
- `conn.Exec(ctx, sql)` không tham số cho phép nhiều câu lệnh trong 1 chuỗi.

**Kiểm tra:** chạy app, vào DB gõ `\dt` thấy bảng và 32 partition.

---

## Bước 3 — Normalize (`internal/normalize/`) ← QUAN TRỌNG NHẤT, làm kỹ, viết test trước

### 3.1 `key.go`
```go
type Type string      // "phone" | "url"
type MatchType string // "exact" | "domain" | "prefix"
type Key struct { Type Type; MatchType MatchType; Value string; Hash int64 }
func MakeKey(t Type, m MatchType, v string) Key
```
`Hash = int64(xxhash.Sum64String(string(t)+"|"+string(m)+"|"+v))`. **Trộn type và match_type vào hash** để khóa không bao giờ đụng nhau.
Khai báo `var ErrInvalid = errors.New("invalid input")` và luôn bọc lỗi bằng `fmt.Errorf("%w: ...", ErrInvalid)` để handler biết trả 400.

### 3.2 `phone.go`
`func Phone(raw, region string) (string, error)`: dùng `phonenumbers.Parse(raw, region)` → kiểm tra `phonenumbers.IsPossibleNumber(num)` (không dùng `IsValidNumber` vì số spam/đầu số ngắn có thể không "valid" chặt) → `phonenumbers.Format(num, phonenumbers.E164)`.
Test: `0901234567`, `+84 901 234 567`, `84-901-234-567` → cùng `+84901234567`; `abc` → lỗi.

### 3.3 `url.go`
`func ParseURL(raw string) (URLParts, error)` với `URLParts{Host, Hostname, Path, Query string}`. Các bước theo thứ tự:
1. Trim khoảng trắng, giới hạn độ dài (≤ 2048).
2. Nếu bắt đầu `//` thêm `http:`; nếu không chứa `://` thêm `http://`. Chỉ cho `http/https`.
3. `url.Parse`. Lấy `u.Hostname()` → lowercase, bỏ dấu `.` cuối, bỏ tiền tố `www.`.
4. Nếu không phải IP (`net.ParseIP`): `idna.Lookup.ToASCII(host)` (đổi chữ Unicode thành punycode, chống giả mạo ký tự Cyrillic). Host không chứa `.` → lỗi.
5. Port: bỏ nếu 80/443, còn lại giữ (`Host = hostname + ":" + port`).
6. Path: `u.EscapedPath()` rồi `strings.TrimRight(p, "/")` (nên `/` thành rỗng).
7. Query: `q := u.Query()`, xoá tham số tracking (`utm_*`, `fbclid`, `gclid`, `mc_cid`, `mc_eid`, `igshid`, `yclid`, `msclkid`), `q.Encode()` (tự sắp xếp theo key). Bỏ fragment.
8. `Full() = Host + Path + ("?" + Query nếu có)`.

### 3.4 Hai hàm công khai
- **`NormalizeEntry(t, m, raw, region) (Key, error)`** — dùng khi *lưu* entry:
  - phone: match luôn là `exact`, value = E.164.
  - url `domain`: yêu cầu không có path/query/port, value = `Hostname`.
  - url `prefix`: yêu cầu không có query, value = `Host+Path`.
  - url `exact`: value = `Full()`.
- **`Candidates(t, raw, region) (normalized string, []Key, error)`** — dùng khi *check*:
  - phone: 1 key `exact`.
  - url: gồm
    - 1 key `exact` = `Full()`;
    - các key `prefix`: `host`, `host/a`, `host/a/b`, ... (cắt theo từng segment của path);
    - các key `domain`: chuỗi host cha. Ví dụ `a.b.example.com` → `a.b.example.com`, `b.example.com`, `example.com`. Dừng ở eTLD+1 (`publicsuffix.EffectiveTLDPlusOne`); nếu là IP hoặc hàm báo lỗi thì chỉ dùng chính host.

**Vì sao thiết kế vậy:** admin chặn `evil.com` (domain) thì `http://x.evil.com/abc?utm_source=1` cũng bị bắt, nhưng chặn `evil.com/shop` (prefix) thì `evil.com/blog` vẫn an toàn.

**Test (bắt buộc, `normalize_test.go`, table-driven):** 10–15 case SĐT; `HTTPS://WWW.Example.COM/a/?utm_x=1&b=2&a=1#frag` → `example.com/a?a=1&b=2`; domain chain; prefix chain; URL lỗi.
`go test ./internal/normalize/ -v`

---

## Bước 4 — Model (`internal/model/model.go`)

- `Entry` (các trường của bảng, kèm tag `json:"..."`; `ExpiresAt *time.Time`).
- `EntryInput{Category, RiskScore, Source, Note, ExpiresAt}`.
- `func (in *EntryInput) Validate() error`: category thuộc `spam|scam|phishing|malware|telemarketing|other` (mặc định `spam`), score 0..100 (mặc định 50), giới hạn độ dài `note/source`.

---

## Bước 5 — Store Postgres (`internal/store/`)

Dùng `pgxpool`. Chia file: `store.go` (kết nối + migrate), `entries.go`, `import.go`, `admins.go`, `audit.go`, `changes.go`.

**Quy tắc chung:** mọi truy vấn dùng tham số `$1,$2...` (chống SQL injection). Mọi thao tác ghi chạy trong **transaction** gồm: ghi entry + ghi `change_log` + ghi `audit_logs`.

| Hàm | Ghi chú |
|---|---|
| `CreateEntry(ctx, key, input, actor)` | `INSERT ... RETURNING`; bắt lỗi mã `23505` (unique violation) → trả `ErrDuplicate` (dùng `errors.As` với `*pgconn.PgError`) |
| `GetEntry(ctx, id)` | không thấy → `ErrNotFound` (`pgx.ErrNoRows`) |
| `UpdateEntry(ctx, id, input, actor)` | chỉ sửa metadata (category/score/source/note/expires). **Giá trị không sửa** → muốn đổi giá trị thì xoá rồi thêm mới. Dùng `SELECT ... FOR UPDATE` lấy bản "before" cho audit |
| `DeleteEntry(ctx, id, actor)` | `DELETE ... RETURNING` để có hash ghi change_log |
| `ListEntries(ctx, filter)` | phân trang **keyset**: `WHERE id < $cursor ORDER BY id DESC LIMIT n` (không dùng OFFSET, OFFSET chậm kinh khủng với 300M dòng). Lọc theo type/category. Tìm kiếm: handler normalize `q` rồi truyền `SearchKeys`, store thêm điều kiện `value_hash = ANY($) AND value_normalized = ANY($)` |
| `FindMatches(ctx, keys)` | **hàm nóng nhất**. Một câu SQL duy nhất cho cả danh sách key: |

```sql
SELECT <cột entry>
FROM blacklist_entries e
JOIN unnest($1::bigint[], $2::text[], $3::text[], $4::text[]) AS c(h, t, mt, v)
  ON e.value_hash = c.h AND e.type = c.t AND e.match_type = c.mt AND e.value_normalized = c.v
WHERE e.expires_at IS NULL OR e.expires_at > now()
```
(Truyền 4 slice: hash, type, match_type, value.) Một round-trip, đi đúng unique index.

| Hàm | Ghi chú |
|---|---|
| `AllHashes(ctx, emit func(uint64)) error` | `SELECT value_hash FROM blacklist_entries`, duyệt `rows.Next()`, gọi `emit` — dùng dựng Bloom lúc khởi động |
| `ChangesSince(ctx, seq, limit)`, `MaxSeq(ctx)`, `PurgeChanges(ctx, olderThan)` | cho changefeed ở Bước 6 |
| `EstimatedCount(ctx)` | `SELECT COALESCE(SUM(GREATEST(reltuples,0)),0)::bigint FROM pg_class WHERE relname LIKE 'blacklist_entries_p%' AND relkind='r'` (đừng `COUNT(*)` — quét 300M dòng!) |
| Admin: `CountAdmins`, `CreateAdmin`, `GetAdminByEmail` | |
| Audit: `ListAudit(ctx, limit)` | |

**Import CSV (`import.go`):** `COPY` nhanh gấp hàng chục lần INSERT từng dòng.
1. Mở transaction; `CREATE TEMP TABLE import_stage (...) ON COMMIT DROP`.
2. `tx.CopyFrom(ctx, pgx.Identifier{"import_stage"}, cols, source)` — `source` là struct bạn tự viết, cài interface `pgx.CopyFromSource` (`Next() bool`, `Values() ([]any, error)`, `Err() error`), đọc CSV từng dòng (streaming, không nạp cả file vào RAM).
3. `INSERT INTO blacklist_entries (...) SELECT DISTINCT ON (value_hash,type,match_type,value_normalized) ... FROM import_stage ... ON CONFLICT (value_hash,type,match_type,value_normalized) DO UPDATE SET ... RETURNING (xmax = 0) AS inserted` → đếm số dòng mới/số dòng cập nhật (`xmax = 0` nghĩa là dòng mới).
4. `INSERT INTO change_log(value_hash) SELECT value_hash FROM import_stage`.
5. Ghi 1 dòng audit tổng kết; commit.

**Kiểm tra:** viết test nhỏ (hoặc `main` tạm) tạo/sửa/xoá/list/find với Postgres thật ở Docker.

---

## Bước 6 — Bloom filter + Changefeed (phần "ăn tiền")

### 6.1 `internal/bloom/bloom.go` — tự viết, chỉ ~50 dòng
```go
type Filter struct { bits []uint64; m uint64; k uint64 }
func New(expectedItems uint64) *Filter   // m = expectedItems*10 bit (làm tròn lên bội của 64), k = 7
func (f *Filter) Add(h uint64)
func (f *Filter) Test(h uint64) bool
```
- Vì `h` đã là hash 64-bit tốt, dùng **double hashing**: `h1 = h`, `h2 = (h>>32 | h<<32) | 1`, vị trí thứ i = `(h1 + i*h2) % m`.
- `Add`: `atomic.OrUint64(&f.bits[idx/64], 1<<(idx%64))`; `Test`: `atomic.LoadUint64` rồi kiểm tra bit. Dùng atomic để **nhiều goroutine đọc/ghi cùng lúc mà không cần khoá**.
- 10 bit/phần tử + k=7 → tỉ lệ dương tính giả ≈ 1%. 300M phần tử ≈ 375MB RAM.
- Test: thêm 100k hash ngẫu nhiên → `Test` luôn `true` cho tất cả; thử 100k hash khác → tỉ lệ `true` khoảng ≤ 2%. Viết thêm `-race` test với nhiều goroutine.

### 6.2 `Manager` (cùng package)
Bọc `atomic.Pointer[Filter]` để **thay filter mới mà không dừng dịch vụ**:
- `Test(h)`: nếu chưa có filter → trả `true` (thận trọng: cứ hỏi DB, vẫn đúng).
- `Add(h)`: thêm vào filter hiện tại; nếu đang rebuild thì đồng thời nhét vào slice `pending` (bảo vệ bằng mutex).
- `Rebuild(ctx, size, load)`: bật cờ `rebuilding` → tạo filter mới → `load` đổ toàn bộ hash từ DB vào → khoá mutex, áp `pending` vào filter mới, `Store` filter mới, tắt cờ. Nếu `load` lỗi → giữ filter cũ.
- `Ready() bool`.
Vì sao cần `pending`: entry thêm trong lúc đang quét DB có thể bị quét sót → không được để Bloom sót (sẽ trả "safe" sai).

### 6.3 `internal/changefeed/` — đồng bộ nhiều instance
Vấn đề: chạy 3 instance, admin thêm entry ở instance A thì Bloom/cache của B, C phải biết.
Cách đề xuất (thay cho Redis pub/sub vì **pub/sub có thể mất tin → Bloom sót → false negative**): dùng bảng `change_log` ở DB (mẫu *transactional outbox*: ghi sự kiện cùng transaction với dữ liệu nên không thể "ghi entry mà mất sự kiện").
- Mỗi lần ghi entry → ghi 1 dòng `change_log(value_hash)` trong cùng transaction.
- **Cạm bẫy nghiêm trọng:** `BIGSERIAL` cấp số lúc INSERT chứ không phải lúc COMMIT. Transaction A lấy seq=5, transaction B lấy seq=6 và commit trước; poller đọc thấy 6, đặt `lastSeq=6`, rồi A commit seq=5 → **sự kiện 5 bị bỏ sót vĩnh viễn** (Bloom thiếu hash → trả "safe" sai). Cách đúng: chỉ đọc các dòng thuộc transaction *đã chắc chắn kết thúc*:
  ```sql
  SELECT seq, xid, value_hash FROM change_log
  WHERE xid < pg_snapshot_xmin(pg_current_snapshot())
    AND (xid, seq) > ($1::xid8, $2::bigint)
  ORDER BY xid, seq LIMIT 10000
  ```
  Lưu con trỏ `(lastXid, lastSeq)`. (Hãy tự kiểm chứng câu này trên Postgres 16 bằng 2 phiên `psql` commit lệch thứ tự.) Phương án đơn giản hơn nhưng kém chặt: chỉ đọc dòng có `created_at < now() - 5s`, kèm rebuild định kỳ để vá.
- `Feed.Run(ctx, interval)`: mỗi 1 giây chạy câu trên → với mỗi hash gọi `bloom.Add`; cập nhật con trỏ và `epoch`. Nếu nhận đủ 10000 dòng thì lặp tiếp ngay.
- `Feed.SyncNow(ctx)`: chạy poll đồng bộ (có mutex). Handler gọi nó **ngay sau mỗi lần ghi** để admin thêm xong là check thấy liền.
- `Feed.Epoch()`: số seq lớn nhất đã thấy. Dùng làm một phần **key cache** (`chk:<epoch>:<type>:<normalized>`): có thay đổi dữ liệu → epoch tăng → mọi cache cũ tự vô hiệu, không cần xoá thủ công.
- `Feed.Init(ctx, expectedItems)`: lấy `MaxSeq` → `lastSeq` → `Rebuild` Bloom (size = max(cấu hình, ước lượng × 1.3)) → đánh dấu ready.
- Một goroutine định kỳ `PurgeChanges(24h)` và `Rebuild` (mặc định 24h) để dọn các entry đã xoá khỏi Bloom.

**Kiểm tra:** test với store giả: thêm hash → `Test` true; chạy `Rebuild` đồng thời với `Add` (race test) rồi xác nhận không mất hash nào.

---

## Bước 7 — Cache + Checker

### 7.1 `internal/cache/` — interface `Cache{ Get(ctx,key) ([]byte,bool); Set(ctx,key,val) }`
Hai bản cài: `Redis` (mỗi lệnh có timeout ~50ms; lỗi Redis → coi như miss, **không** làm hỏng request) và `Noop` (khi `RedisAddr` rỗng). `Set` kèm TTL.

### 7.2 `internal/checker/checker.go`
Phụ thuộc qua interface nhỏ để dễ test: `EntryFinder{FindMatches}`, `Cache`, `Filter{Test; Ready}`, `Epocher{Epoch}`.

```go
type Match  struct { EntryID int64; MatchType, MatchedValue, Category string; RiskScore int }
type Result struct { Type, Input, Normalized string; Blacklisted bool; Match *Match }
func (c *Checker) Check(ctx, t normalize.Type, raw string) (Result, error)
func (c *Checker) CheckBatch(ctx, items []Item) []BatchResult   // tối đa 100, chạy song song ≤16 goroutine, lỗi từng item không làm hỏng cả batch
```
Thuật toán `Check`:
1. `Candidates()` → lỗi thì bọc `ErrInvalidInput`.
2. Lọc key bằng `filter.Test(uint64(k.Hash))`. Không còn key nào → `Blacklisted=false` (tăng metric `bloom_negative`).
3. Tạo cacheKey có epoch → `cache.Get` → hit thì giải mã JSON (kể cả "không có match" đã được cache âm).
4. Miss → `singleflight.Group.Do(cacheKey, ...)`: gọi `FindMatches(maybeKeys)`; chọn entry có `risk_score` cao nhất (hoà thì id nhỏ); `cache.Set`. Dùng `context.WithoutCancel` + timeout 3s bên trong để 1 client huỷ không làm hỏng các client khác đang chờ chung.
5. Đếm metrics: `bloom_negative`, `cache_hit`, `db_hit`, `db_miss`.

**Test (`checker_test.go`) với fake store/filter/cache:** (a) Bloom nói không → store không được gọi; (b) cache hit → store không được gọi; (c) 100 goroutine cùng key → store chỉ bị gọi 1 lần; (d) chọn đúng entry risk cao nhất.

---

## Bước 8 — Check API: API key, rate limit, quota, metrics (`internal/apikey`, `internal/handler`)

### 8.1 Endpoint công khai
| Endpoint | Ghi chú |
|---|---|
| `GET /v1/check?type=&value=` | trả `{type,input,normalized,blacklisted,match{...}}` |
| `POST /v1/check/batch` | body `{"items":[{"type","value"}]}` ≤100; lỗi từng item không làm hỏng cả batch |
| `GET /healthz`, `GET /readyz` | `readyz` = 503 khi Bloom chưa dựng xong **hoặc** changefeed bị trễ quá ngưỡng (xem Bước 12) |
| `GET /metrics` | chỉ mở trong mạng nội bộ |

Lỗi → HTTP: input sai → 400; thiếu/sai key → 401; key bị thu hồi/hết hạn → 403; vượt rate → 429 (kèm `Retry-After`); vượt quota ngày → 429 (mã lỗi riêng); chưa sẵn sàng → 503; còn lại 500 (log chi tiết, không trả lỗi nội bộ ra ngoài).

### 8.2 Thiết kế API key
- **Định dạng:** `vsf_<prefix8>_<secret32>`; secret sinh bằng `crypto/rand`. **Chỉ hiển thị 1 lần** lúc tạo.
- **Lưu DB:** `prefix` (để tra) + `SHA-256(secret)`. Secret ngẫu nhiên dài nên SHA-256 là đủ (không cần bcrypt như mật khẩu người dùng). So sánh bằng `subtle.ConstantTimeCompare`.
- **Xác thực nhanh:** middleware lấy header `X-API-Key` → tách prefix → tra **cache trong RAM** (TTL ~30s, key = prefix) → miss mới hỏi DB. Hệ quả: *thu hồi key có hiệu lực trong ≤ 30s trên mọi instance* (ghi rõ trong tài liệu; muốn tức thì thì cho `change_log` hoặc Redis broadcast xoá cache).
- **Rotation (xoay key):** tạo key mới có `rotated_from = <id key cũ>`; đặt `expires_at` cho key cũ (ví dụ +7 ngày) để khách kịp đổi; hết hạn tự vô hiệu.
- **Thu hồi:** `status='revoked'`, `revoked_at=now()`, ghi audit.
- **Rate limit (giây):** token bucket `golang.org/x/time/rate` cục bộ theo từng key trên mỗi instance — rẻ, không tốn round-trip. Chú ý: với N instance, tổng giới hạn thực tế ≈ N × giới hạn; chia `rps_limit / số instance` hoặc dùng Redis nếu cần chính xác.
- **Quota (ngày):** Redis `INCR quota:<keyId>:<yyyymmdd>` + `EXPIRE` 48h; mỗi *item* trong batch tính 1 đơn vị. Redis lỗi → **fail-open** (cho qua nhưng tăng metric `quota_backend_errors`) hoặc fail-closed theo cấu hình; nên chọn fail-open để tránh sập dịch vụ vì cache.
- **`last_used_at`:** cập nhật gộp (batch) mỗi ~1 phút, không UPDATE mỗi request.
- **Metrics** (Prometheus; nhớ giới hạn cardinality — label theo `key_id`, không theo IP/value): `check_requests_total{result=safe|blacklisted|invalid|error}`, `check_layer_total{layer=bloom|cache|db}`, `check_duration_seconds` (histogram), `api_key_requests_total{key_id,status}`, `rate_limited_total`, `quota_exceeded_total`, `bloom_items`, `changefeed_lag_seconds`, `db_pool_in_use`.
- **Chế độ dev:** `AuthDisabled=true` chỉ được chấp nhận khi `AppEnv=development` **và** địa chỉ bind là `127.0.0.1`/`localhost`/`::1`; ngược lại `log.Fatal` ngay lúc khởi động. Log cảnh báo to rõ mỗi lần chạy.

Test: key sai/thiếu/hết hạn/thu hồi; 2 key cùng lúc (key cũ và key xoay) đều dùng được trong khoảng chuyển tiếp; vượt rate → 429; vượt quota → 429.

---

## Bước 9 — Admin: session, RBAC, CSRF (`internal/auth`, `internal/handler/admin_*.go`)

Admin Portal **không** dùng JWT; dùng **server-side session** (thu hồi tức thì, dễ kiểm soát).

### 9.1 Đăng nhập & session
- Mật khẩu: `argon2id` (`golang.org/x/crypto/argon2`) hoặc `bcrypt` (cost ≥ 12).
- Login thành công: sinh 32 byte ngẫu nhiên → cookie `__Host-vsf_session` (`HttpOnly`, `Secure` khi production, `SameSite=Lax`, `Path=/`); DB lưu **SHA-256 của cookie** vào `sessions`. **Luôn tạo session mới khi login** (chống session fixation).
- Hết hạn: idle timeout (ví dụ 30 phút, cập nhật `last_seen_at` gộp để không ghi DB mỗi request) + absolute timeout (ví dụ 12 giờ). Logout xoá hàng session. Đổi mật khẩu/vô hiệu hoá user → xoá mọi session của user đó.
- Chống brute-force: giới hạn theo IP **và** theo email (ví dụ 5 lần / 15 phút), thông báo lỗi chung "email hoặc mật khẩu sai" (không lộ email tồn tại). Dùng thời gian xử lý đều nhau (vẫn so hash giả khi email không tồn tại).
- Khởi động: nếu `CountAdmins==0` thì tạo admin từ `BootstrapAdminEmail/Password`; khuyến nghị bắt đổi mật khẩu ở lần đăng nhập đầu.

### 9.2 RBAC (phân quyền)
| Quyền | viewer | editor | admin |
|---|---|---|---|
| Xem/tìm entry, tab Check thử | ✔ | ✔ | ✔ |
| Thêm/sửa/xoá entry, import | ✘ | ✔ | ✔ |
| Export | ✘ | ✔ | ✔ |
| Xem audit log | ✘ | ✔ (chỉ đọc) | ✔ |
| Quản lý user, API key | ✘ | ✘ | ✔ |

Cài bằng middleware `RequireRole(min Role)` bọc từng nhóm route, **và kiểm lại trong handler ghi** (phòng thủ nhiều lớp). Ẩn nút trên giao diện chỉ là tiện ích, **không phải** bảo mật. Test: viewer gọi `POST` entry → 403.

### 9.3 CSRF
- Mỗi session có `csrf_token` ngẫu nhiên (lưu cột `sessions.csrf_token`).
- Mọi request không phải GET/HEAD/OPTIONS phải gửi đúng token trong header `X-CSRF-Token` (HTMX) hoặc field ẩn `csrf_token` (form thường), so sánh bằng `ConstantTimeCompare`.
- Kiểm tra thêm header `Origin`/`Sec-Fetch-Site` khớp host của mình (lớp phòng thủ thứ hai).
- Với HTMX: đặt token một lần ở `<body hx-headers='{"X-CSRF-Token":"{{.CSRF}}"}'>` để mọi request htmx tự gửi kèm.
- **GET không bao giờ được thay đổi dữ liệu.** Xoá/sửa phải là POST/PUT/DELETE.
- Thêm header an toàn cho mọi response HTML: `Content-Security-Policy: default-src 'self'` (tự host file htmx, không dùng CDN), `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `X-Frame-Options: DENY`.

### 9.4 Audit log
Ghi trong **cùng transaction** với thay đổi dữ liệu: ai (`actor`), làm gì (`create|update|delete|import|export|login|apikey.create|apikey.revoke|user.*`), đối tượng, `before/after` dạng JSONB, IP, thời điểm. Audit chỉ thêm, **không có chức năng sửa/xoá** trong portal.

---

## Bước 10 — Admin Portal bằng `html/template` + HTMX (`web/`)

### 10.1 Cấu trúc
```
web/
  embed.go                 // //go:embed templates static ; var FS embed.FS
  templates/
    layout.html            // <head>, nav, <body hx-headers=CSRF>, {{block "content" .}}
    login.html
    entries.html           // trang đầy đủ: thanh tìm kiếm + bảng
    _entries_table.html    // partial: chỉ phần bảng + phân trang  (hx-target)
    _entry_form.html       // partial: form thêm/sửa (hiện trong dialog)
    check.html  import.html  audit.html  users.html  apikeys.html
  static/htmx.min.js       // tải bản cố định (2.0.x) về, tự host; không dùng CDN
  static/style.css
```
Parse bằng `template.ParseFS(web.FS, "templates/*.html")`. `html/template` tự escape HTML nên chống XSS — **tuyệt đối không dùng `template.HTML(...)` với dữ liệu người dùng/DB**.

### 10.2 Mẫu HTMX cần dùng
- **Tìm kiếm:** `<input name="q" hx-get="/admin/entries" hx-trigger="keyup changed delay:300ms, search" hx-target="#table" hx-push-url="true">`
- **Phân trang server-side (keyset):** server trả `NextCursor`; nút "Trang sau" là `hx-get="/admin/entries?after={{.NextCursor}}&q=..." hx-target="#table" hx-push-url="true"`. Quay lại = nút Back của trình duyệt (URL đã được push). Không dùng `OFFSET`.
- **Nhận biết request htmx:** header `HX-Request: true` → trả partial; ngược lại trả cả trang (để F5/link trực tiếp vẫn chạy).
- **Xoá:** `hx-delete="/admin/entries/{{.ID}}" hx-confirm="Xoá mục này?" hx-target="closest tr" hx-swap="outerHTML"`.
- **Form thêm/sửa:** `hx-post`/`hx-put`; lỗi validate trả lại form kèm thông báo với mã 422 (cần `htmx.config.responseHandling` cho phép swap 4xx, hoặc dùng sự kiện `htmx:beforeSwap` để cho phép).
- **Import:** `<form hx-post="/admin/import" hx-encoding="multipart/form-data">`, trả partial báo cáo: số dòng mới / cập nhật / lỗi (20 lỗi đầu kèm số dòng). File lớn (hàng triệu dòng) nên chạy **job nền** (bảng `import_jobs` + trang tiến độ dùng `hx-trigger="every 2s"`) thay vì giữ một request dài.

### 10.3 Routes portal
`GET /admin/login`, `POST /admin/login`, `POST /admin/logout`, `GET /admin/entries` (+partial), `GET /admin/entries/new`, `POST /admin/entries`, `GET /admin/entries/{id}/edit`, `PUT /admin/entries/{id}`, `DELETE /admin/entries/{id}`, `GET/POST /admin/import`, `GET /admin/export`, `GET /admin/audit`, `GET/POST /admin/check`, `GET/POST/DELETE /admin/users...` (admin), `GET/POST /admin/apikeys...` (admin: tạo, xoay, thu hồi; hiển thị key đúng 1 lần trong partial rồi biến mất).

### 10.4 Tìm kiếm cần lưu ý
Tìm theo **giá trị chính xác sau khi normalize** (qua hash index), không phải `LIKE '%abc%'` — với 300M dòng, tìm chứa chuỗi cần hạ tầng riêng (OpenSearch hoặc index trigram) nên hoãn sang giai đoạn sau. Ghi rõ giới hạn này trên giao diện (placeholder: "nhập số điện thoại hoặc URL đầy đủ").

---

## Bước 11 — `cmd/server/main.go` — thứ tự khởi động
1. `config.Load()` → kiểm tra an toàn (production phải có `SessionSecret`, `CookieSecure`, không `AuthDisabled`).
2. `store.New` (pool ghi → primary; pool đọc → replica nếu có) + `Migrate` (chỉ chạy bằng primary) → seed admin.
3. Tạo `bloom.Manager`, `changefeed.Feed` (**đọc `change_log` từ cùng node với `FindMatches`**, xem Bước 12), cache, `checker.Checker`, `apikey.Service`, session store.
4. Khởi động HTTP server **trước** (để `/healthz` sống); `go feed.Init(...)`; `/readyz` 503 đến khi Bloom sẵn sàng; sau đó `go feed.Run(...)` + goroutine rebuild/purge/dọn session hết hạn.
5. `signal.NotifyContext` (SIGINT/SIGTERM) → `server.Shutdown` có timeout; flush batch `last_used_at`.

---

## Bước 12 — Thiết kế production (độc lập DB/cache, backup, replication, scale ngang)

### 12.1 Sơ đồ triển khai
```
          Load balancer (L7, TLS)
           │        │        │
        app-1    app-2    app-N      ← stateless, scale ngang; mỗi instance giữ 1 Bloom trong RAM
         │ ghi        │ đọc
   Postgres PRIMARY ──► Postgres REPLICA(s)   (streaming replication)
         │                    ▲
   WAL archive + base backup  └── check path đọc ở đây
   (S3/GCS, PITR)
              Redis (cache + quota; mất dữ liệu cũng không sao)
```
- **Postgres managed hoặc tự chạy** (không nằm cùng host với app); kết nối qua `DATABASE_URL`/`READ_DATABASE_URL`. Redis tương tự (`REDIS_ADDR`, có thể Sentinel/Cluster). App không giữ trạng thái bền → thêm instance bằng cách chạy thêm container.
- **Backup:** base backup + lưu trữ WAL liên tục (pgBackRest hoặc WAL-G) → khôi phục theo thời điểm (PITR). **Diễn tập restore định kỳ** — backup chưa từng restore thì chưa phải backup. Redis không cần backup (chỉ là cache; quota ngày có thể reset khi mất — chấp nhận và ghi rõ).
- **Quy mô:** 300M dòng × (2 index + dòng dữ liệu) có thể lên hàng trăm GB. Cân nhắc **64 partition** thay vì 32 (không đổi được dễ dàng về sau) và quyết định bằng benchmark.

### 12.2 Vấn đề tính đúng khi đọc từ replica (quan trọng)
Replica luôn trễ một chút. Nếu Bloom được cập nhật từ primary nhưng truy vấn xác nhận đọc replica, ta có thể thấy Bloom nói "có thể có" mà replica chưa có dòng → trả "safe" sai tạm thời. Ngược lại nếu Bloom đọc `change_log` **từ chính replica đó** thì: dòng `change_log` đã hiện ra ⇒ entry cùng transaction cũng đã hiện ⇒ Bloom và dữ liệu luôn **nhất quán với nhau** (chỉ cùng "cũ" một lượng bằng độ trễ replica). Quy tắc:
1. `FindMatches` và `ChangesSince` dùng **cùng một node**.
2. Đo `changefeed_lag_seconds`; vượt ngưỡng (ví dụ > 30s) thì `/readyz` trả 503 để LB rút instance, hoặc chuyển sang đọc primary.
3. Hợp đồng nghiệp vụ cần ghi rõ: sau khi admin thêm entry, hiệu lực trong khoảng "độ trễ replica + poll interval" (thường vài giây). Cần *read-your-writes* tức thì thì cho check đọc primary (đổi cấu hình, đánh đổi tải).

### 12.3 Không để false negative do Bloom
- Bloom thiếu hash ⇒ sai. Các lớp bảo vệ: (a) outbox `change_log` bền vững + đọc theo `xid` (Bước 6.3); (b) chưa sẵn sàng ⇒ `Test()` trả `true` + `/readyz` 503; (c) rebuild định kỳ với `pending` buffer; (d) **job đối chiếu** chạy nền: lấy mẫu ngẫu nhiên 100k hash từ DB, kiểm tra `Test()`; bất kỳ lần nào trả `false` ⇒ báo động (metric `bloom_false_negative_total` phải luôn = 0) và kích hoạt rebuild.
- Startup chậm do quét 300M hash: tối ưu sau khi benchmark bằng cách lưu **snapshot Bloom** (file/object storage) kèm con trỏ `(xid, seq)`; instance mới nạp snapshot rồi đuổi theo `change_log`. Chỉ làm khi số đo cho thấy cần.
- Dọn `change_log` chỉ xoá dòng quá cũ **và** đã nằm sau con trỏ của mọi instance (hoặc giữ ≥ 24h); instance nghỉ lâu hơn mức giữ thì bắt buộc rebuild toàn bộ.

### 12.4 Bảo mật & vận hành
Secrets qua biến môi trường/secret manager; TLS ở LB; chạy container non-root; giới hạn kích thước body; log có `request_id`; không log API key/mật khẩu/số điện thoại đầy đủ nếu không cần (che bớt); dependency scan (`govulncheck ./...`).

---

## Bước 13 — Benchmark (phải đo trước khi cam kết số)

Không đưa ra con số RPS/latency khi chưa đo trên phần cứng mục tiêu. Quy trình:
1. **Dữ liệu:** sinh 10M → 100M → (nếu hạ tầng cho phép) 300M bản ghi, nạp bằng chính chức năng import. Ghi lại thời gian import, kích thước bảng + index, RAM của Bloom.
2. **Kịch bản tải (k6 hoặc vegeta):** tỉ lệ key không có/có = 95/5, 80/20, 50/50; phân bố key nóng (Zipf) để thử cache; batch 1/10/100 mục.
3. **Số cần báo cáo:** RPS bão hoà, p50/p95/p99, tỉ lệ lỗi, CPU/RAM app và DB, tỉ lệ rơi vào từng lớp (bloom/cache/db), tỉ lệ dương tính giả của Bloom đo thực tế.
4. **Kịch bản sự cố:** khởi động lạnh (thời gian tới `ready`), rebuild Bloom khi đang có tải, tắt Redis, replica trễ, restart instance, import lớn song song với check.
5. Mọi con số ghi kèm cấu hình máy; chỉ cam kết SLO sau khi lặp lại ổn định ≥ 3 lần.

---

## Checklist kiểm chứng cuối
- [ ] `go vet ./...`, `govulncheck ./...`, `go test ./... -race` xanh.
- [ ] Thêm entry → check ngay (cùng instance) trả `true`; xoá → trả `false`; 2 instance: thêm ở A, B thấy trong ≤ poll interval.
- [ ] Test commit lệch thứ tự (2 transaction) không làm Bloom sót hash.
- [ ] Domain `evil.com` chặn `http://a.evil.com/x?utm_source=1`; prefix `evil2.com/shop` không chặn `/blog`.
- [ ] `0901234567`, `+84901234567`, `+1 415 555 2671` được chuẩn hoá đúng; số quốc tế không bị gán nhầm +84.
- [ ] Entry hết hạn không còn bị chặn.
- [ ] API key: sai/thu hồi/hết hạn/xoay/rate limit/quota đều đúng; `AuthDisabled` bị từ chối khi `AppEnv=production` hoặc bind `0.0.0.0`.
- [ ] RBAC: viewer không ghi được; editor không vào được users/apikeys. CSRF: POST thiếu token → 403.
- [ ] Import 1M dòng báo đúng mới/cập nhật/lỗi. Audit log ghi đủ mọi thao tác.
- [ ] Benchmark báo cáo theo Bước 13.

## Thứ tự gợi ý để có bản chạy sớm (MVP)
Bước 0 → 1 → 2 (bảng entries, change_log) → 3 → 4 → 5 (Create/Find/Delete) → 6 → 7 → 8 (check + API key cơ bản) → thử `curl`. Sau đó: 9–10 (portal, session, RBAC, CSRF), rồi import/audit, metrics, 12–13.

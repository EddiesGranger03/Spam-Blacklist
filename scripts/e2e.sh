#!/usr/bin/env bash
set -u
BASE=${BASE:-http://127.0.0.1:8080}
ADMIN_EMAIL=${ADMIN_EMAIL:-admin@example.com}
ADMIN_PASSWORD=${ADMIN_PASSWORD:-ChangeMe-12345}
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
PASS=0; FAIL=0

S=$(printf '%07d' $(( (RANDOM << 15 | RANDOM) % 10000000 )))
PH="090$S"
PH_SPACED="${PH:0:4} ${PH:4:3} ${PH:7:3}"
PH_E164="+84${PH:1}"
PH_E164_ENC="%2B84${PH:1}"
PH_EXPIRED="091$S"
PI1="092$S"; PI2="093$S"
EV="evil$S.com"
EV2="evilshop$S.com"
IMP="imp$S.example.com"
VIEWER="viewer$S@example.com"

ok()   { PASS=$((PASS+1)); echo "  ok   - $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL - $1  (got: $2)"; }
expect() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "$2, want $3"; fi; }
contains() { if printf '%s' "$2" | grep -q -- "$3"; then ok "$1"; else bad "$1" "no '$3' in: $(printf '%s' "$2" | head -c 200)"; fi; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
csrf_of() { grep -o 'X-CSRF-Token":"[^"]*' "$1" | head -1 | sed 's/.*"//'; }

echo "== chờ server sẵn sàng (run id $S)"
for i in $(seq 1 60); do [ "$(code "$BASE/readyz")" = 200 ] && break; sleep 1; done
expect "readyz = 200" "$(code "$BASE/readyz")" 200
expect "healthz = 200" "$(code "$BASE/healthz")" 200

echo "== đăng nhập"
J="$TMP/admin.jar"
expect "login sai mật khẩu -> 401" "$(code -c "$TMP/x.jar" -d "email=$ADMIN_EMAIL&password=wrong-password" "$BASE/admin/login")" 401
expect "login đúng -> 303" "$(code -c "$J" -d "email=$ADMIN_EMAIL&password=$ADMIN_PASSWORD" "$BASE/admin/login")" 303
expect "chưa đăng nhập vào /admin/entries -> 303 login" "$(code "$BASE/admin/entries")" 303
curl -s -b "$J" "$BASE/admin/entries" -o "$TMP/entries.html"
CSRF=$(csrf_of "$TMP/entries.html")
[ -n "$CSRF" ] && ok "lấy được CSRF token từ trang" || bad "lấy CSRF token" "rỗng"
contains "trang entries hiển thị" "$(cat "$TMP/entries.html")" "Blacklist"

echo "== CSRF"
expect "POST thiếu token -> 403" "$(code -b "$J" -d "type=phone&value=$PH&category=spam&risk_score=50" "$BASE/admin/entries")" 403
expect "POST sai Origin -> 403" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -H 'Origin: http://evil.example' -d "type=phone&value=$PH&category=spam&risk_score=50" "$BASE/admin/entries")" 403

post() { curl -s -b "$J" -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' "$@"; }

echo "== CRUD entry qua portal"
expect "tạo SĐT (viết có khoảng trắng) -> 204" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' --data-urlencode "type=phone" --data-urlencode "match_type=" --data-urlencode "value=$PH_SPACED" --data-urlencode "category=scam" --data-urlencode "risk_score=80" --data-urlencode "source=e2e" --data-urlencode "note=n" --data-urlencode "expires_at=" "$BASE/admin/entries")" 204
R=$(post --data-urlencode "type=phone" --data-urlencode "value=$PH_E164" --data-urlencode "category=scam" --data-urlencode "risk_score=80" "$BASE/admin/entries")
contains "tạo trùng (khác cách viết) bị báo đã có" "$R" "đã có trong blacklist"
expect "tạo domain $EV" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -d "type=url&match_type=domain&value=https://www.${EV^^}&category=phishing&risk_score=90" "$BASE/admin/entries")" 204
expect "tạo prefix $EV2/shop" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -d "type=url&match_type=prefix&value=http://$EV2/shop/&category=scam&risk_score=70" "$BASE/admin/entries")" 204
R=$(post -d "type=url&match_type=domain&value=other$S.com/path&category=spam&risk_score=10" "$BASE/admin/entries")
contains "domain có path bị từ chối" "$R" "host only"
R=$(post -d 'type=phone&value=abc&category=spam&risk_score=10' "$BASE/admin/entries")
contains "SĐT sai bị từ chối" "$R" "flash err"

echo "== API key"
expect "check không có key -> 401" "$(code "$BASE/v1/check?type=phone&value=$PH")" 401
expect "check key rác -> 401" "$(code -H 'X-API-Key: nope' "$BASE/v1/check?type=phone&value=$PH")" 401
curl -s -b "$J" -H "X-CSRF-Token: $CSRF" -d "name=e2e-key-$S&rps_limit=1000&daily_quota=0&expires_days=" "$BASE/admin/apikeys" -o "$TMP/key.html"
KEY=$(grep -o 'vsf_[a-z0-9]\{8\}_[a-z0-9]\{32\}' "$TMP/key.html" | head -1)
[ -n "$KEY" ] && ok "tạo được API key" || bad "tạo API key" "không thấy key"
H="X-API-Key: $KEY"
chk() { curl -s -H "$H" "$BASE/v1/check?type=$1&value=$2"; }

echo "== Check API"
R=$(chk phone "$PH_E164_ENC"); contains "SĐT bị blacklist (viết khác)" "$R" '"blacklisted":true'; contains "category scam" "$R" '"category":"scam"'
R=$(chk phone 0999999999); contains "SĐT lạ an toàn" "$R" '"blacklisted":false'
R=$(chk url "http%3A%2F%2Fa.b.$EV%2Fx%3Futm_source%3D1"); contains "subdomain + tracking bị chặn bởi domain" "$R" '"blacklisted":true'
R=$(chk url "https%3A%2F%2Fnot$EV%2F"); contains "tên miền chỉ chứa cụm giống nhưng khác domain -> an toàn" "$R" '"blacklisted":false'
R=$(chk url "$EV2%2Fshop%2Fitem1"); contains "prefix /shop chặn /shop/item1" "$R" '"blacklisted":true'
R=$(chk url "$EV2%2Fblog"); contains "prefix /shop không chặn /blog" "$R" '"blacklisted":false'
R=$(chk url "$EV2%2Fshopping"); contains "prefix tôn trọng ranh giới segment" "$R" '"blacklisted":false'
expect "input sai -> 400" "$(code -H "$H" "$BASE/v1/check?type=phone&value=abc")" 400
expect "type sai -> 400" "$(code -H "$H" "$BASE/v1/check?type=email&value=a@b.c")" 400
R=$(curl -s -H "$H" -H 'Content-Type: application/json' -d "{\"items\":[{\"type\":\"phone\",\"value\":\"$PH\"},{\"type\":\"phone\",\"value\":\"zzz\"},{\"type\":\"url\",\"value\":\"$EV\"}]}" "$BASE/v1/check/batch")
contains "batch có kết quả blacklisted" "$R" '"blacklisted":true'; contains "batch có lỗi riêng từng mục" "$R" '"error"'
expect "batch rỗng -> 400" "$(code -H "$H" -H 'Content-Type: application/json' -d '{"items":[]}' "$BASE/v1/check/batch")" 400

echo "== Sửa / xóa có hiệu lực ngay"
ID=$(curl -s -b "$J" -H 'HX-Request: true' "$BASE/admin/entries?q=$EV2/shop&type=url" | grep -o 'hx-delete="/admin/entries/[0-9]*' | head -1 | grep -o '[0-9]*$')
[ -n "$ID" ] && ok "tìm được entry theo giá trị (id=$ID)" || bad "tìm entry" "không thấy id"
expect "sửa entry -> 204" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' -X PUT -d "type=url&match_type=prefix&value=$EV2/shop&category=scam&risk_score=33&source=&note=&expires_at=" "$BASE/admin/entries/$ID")" 204
R=$(chk url "$EV2%2Fshop%2Fx"); contains "risk mới 33 áp dụng ngay (không dính cache cũ)" "$R" '"risk_score":33'
expect "xóa entry -> 200" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -X DELETE "$BASE/admin/entries/$ID")" 200
R=$(chk url "$EV2%2Fshop%2Fx"); contains "sau khi xóa: an toàn ngay" "$R" '"blacklisted":false'

echo "== Entry hết hạn"
expect "tạo entry hết hạn trong quá khứ" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -d "type=phone&value=$PH_EXPIRED&category=spam&risk_score=50&expires_at=2020-01-01" "$BASE/admin/entries")" 204
R=$(chk phone "$PH_EXPIRED"); contains "entry hết hạn không còn bị chặn" "$R" '"blacklisted":false'

echo "== RBAC"
expect "tạo user viewer" "$(code -b "$J" -d "csrf_token=$CSRF&email=$VIEWER&password=Viewer-Pass-123&role=viewer" "$BASE/admin/users")" 303
V="$TMP/viewer.jar"
expect "viewer login" "$(code -c "$V" -d "email=$VIEWER&password=Viewer-Pass-123" "$BASE/admin/login")" 303
curl -s -b "$V" "$BASE/admin/entries" -o "$TMP/v.html"; VC=$(csrf_of "$TMP/v.html")
expect "viewer xem được danh sách" "$(code -b "$V" "$BASE/admin/entries")" 200
expect "viewer KHÔNG tạo được entry -> 403" "$(code -b "$V" -H "X-CSRF-Token: $VC" -d "type=phone&value=$PI1&category=spam&risk_score=1" "$BASE/admin/entries")" 403
expect "viewer KHÔNG vào được users -> 403" "$(code -b "$V" "$BASE/admin/users")" 403
expect "viewer KHÔNG vào được apikeys -> 403" "$(code -b "$V" "$BASE/admin/apikeys")" 403
expect "viewer KHÔNG xem được audit -> 403" "$(code -b "$V" "$BASE/admin/audit")" 403

echo "== Import / Export"
printf 'type,value,match_type,category,risk_score\nphone,%s,,scam,70\nphone,%s,,spam,40\nurl,%s,domain,phishing,90\nphone,not-a-phone,,spam,1\nphone,%s,,scam,99\n' "$PI1" "$PI2" "$IMP" "$PI1" > "$TMP/imp.csv"
R=$(curl -s -b "$J" -H "X-CSRF-Token: $CSRF" -H 'HX-Request: true' -F default_type= -F "file=@$TMP/imp.csv" "$BASE/admin/import")
JOB=$(printf '%s' "$R" | grep -o '/admin/import/[0-9a-f]*' | head -1 | grep -o '[0-9a-f]*$')
[ -n "$JOB" ] && ok "import khởi động job $JOB" || bad "import" "$R"
for i in $(seq 1 30); do
  S2=$(curl -s -b "$J" -H 'HX-Request: true' "$BASE/admin/import/$JOB"); printf '%s' "$S2" | grep -q 'hoàn tất\|thất bại' && break; sleep 1
done
contains "import hoàn tất" "$S2" "hoàn tất"
contains "import: thêm mới 3 (PI1, PI2, domain)" "$S2" "Thêm mới: <strong>3</strong>"
contains "import: cập nhật 0" "$S2" "<strong>0</strong>"
contains "import: báo dòng lỗi (dòng 5)" "$S2" "dòng 5"
R=$(chk phone "$PI1"); contains "mục import có hiệu lực ngay, dòng sau thắng (risk 99)" "$R" '"risk_score":99'
R=$(chk url "http%3A%2F%2Fx.$IMP"); contains "domain import chặn subdomain" "$R" '"blacklisted":true'
curl -s -b "$J" "$BASE/admin/export?type=phone" -o "$TMP/export.csv"
contains "export có header" "$(cat "$TMP/export.csv")" "type,value,match_type"
contains "export có SĐT vừa import" "$(cat "$TMP/export.csv")" "+84${PI1:1}"

echo "== Thu hồi API key"
curl -s -b "$J" "$BASE/admin/apikeys" -o "$TMP/keys.html"
KID=$(grep -o '/admin/apikeys/[0-9]*/revoke' "$TMP/keys.html" | head -1 | grep -o '[0-9]*')
expect "thu hồi key -> 303" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/admin/apikeys/$KID/revoke")" 303
expect "key bị thu hồi -> 403" "$(code -H "$H" "$BASE/v1/check?type=phone&value=$PH")" 403

echo "== Audit & metrics"
curl -s -b "$J" "$BASE/admin/audit" -o "$TMP/audit.html"
contains "audit có entry.create" "$(cat "$TMP/audit.html")" "entry.create"
contains "audit có entry.import" "$(cat "$TMP/audit.html")" "entry.import"
contains "audit có apikey.revoke" "$(cat "$TMP/audit.html")" "apikey.revoke"
M=$(curl -s "$BASE/metrics")
contains "metrics có vsf_check_layer_total" "$M" "vsf_check_layer_total"
contains "metrics có bloom_items" "$M" "vsf_bloom_items"
FN=$(printf '%s' "$M" | grep '^vsf_bloom_false_negative_total' | awk '{print $2}'); expect "bloom false negative = 0" "${FN:-0}" 0

echo "== Đăng xuất"
expect "logout -> 303" "$(code -b "$J" -H "X-CSRF-Token: $CSRF" -X POST "$BASE/admin/logout")" 303
expect "sau logout session vô hiệu -> 303" "$(code -b "$J" "$BASE/admin/entries")" 303

echo
echo "KẾT QUẢ: $PASS pass, $FAIL fail"
[ "$FAIL" -eq 0 ]

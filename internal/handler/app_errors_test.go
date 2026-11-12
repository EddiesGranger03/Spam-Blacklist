package handler

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"vsf/internal/model"
)

// Import hỏng: mỗi loại lỗi phải trả lời rõ ràng (400) hoặc ghi nhận dòng bị loại, không được làm hỏng job khác.
func TestAppImportRejectsBadUploads(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	// loại mặc định sai
	if r := adm.upload("value\n0901234567\n", "fax"); r.Code != 400 || !strings.Contains(r.Body, "không hợp lệ") {
		t.Errorf("bad default type: %d %s", r.Code, r.Body)
	}

	// không có file
	var form = url.Values{"default_type": {"phone"}}
	if r := adm.do("POST", "/admin/import", form, nil); r.Code != 400 {
		t.Errorf("not multipart: %d", r.Code)
	}

	// các lỗi của CSV được báo ở trạng thái job (job hoàn thành nhưng báo lỗi), không phải ở HTTP
	jobBody := func(csv, def string) string {
		r := adm.upload(csv, def)
		if r.Code != 200 {
			return r.Body
		}

		id := ""
		if i := strings.Index(r.Body, "/admin/import/"); i >= 0 {
			rest := r.Body[i+len("/admin/import/"):]
			id = rest[:strings.IndexAny(rest, "\"' <")]
		}

		deadline := time.Now().Add(10 * time.Second)

		for {
			st := adm.get("/admin/import/" + id)
			if !strings.Contains(st.Body, "đang chạy") || time.Now().After(deadline) {
				return st.Body
			}

			time.Sleep(100 * time.Millisecond)
		}
	}

	if body := jobBody("note,category\nx,spam\n", "phone"); !strings.Contains(body, "value") {
		t.Errorf("a CSV without a value column must be explained: %.300s", body)
	}

	if body := jobBody("value\n0901234567\n", ""); !strings.Contains(body, "type") {
		t.Errorf("a CSV without a type column and no default type must be explained: %.300s", body)
	}

	mixed := "value,risk_score,expires_at,category\nnot-a-number,5,,spam\n" + phone9() + ",abc,,spam\n" + phone9() + ",5,not-a-date,spam\n" +
		phone9() + ",5,,notacategory\n" + phone9() + ",5,,spam\n"

	body := jobBody(mixed, "phone")
	if !strings.Contains(body, "dòng") {
		t.Errorf("rejected rows must be listed with their line number: %.400s", body)
	}
}

// Chuỗi hash của audit bị sửa phải bị phát hiện qua endpoint xác minh.
func TestAppAuditVerifyDetectsTampering(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	if err := a.st.WriteAudit(context.Background(), model.Actor{Email: "t"}, "test.tamper", map[string]any{"x": 1}); err != nil {
		t.Fatal(err)
	}

	ok := adm.get("/admin/audit/verify")
	if ok.Code != 200 || !strings.Contains(ok.Body, `"ok":true`) {
		t.Fatalf("an intact chain must verify: %d %s", ok.Code, ok.Body)
	}

	// kẻ có quyền ghi DB sửa một dòng đã nối chuỗi
	if _, err := a.pool.Exec(context.Background(), `UPDATE audit_logs SET detail = '{"x": 2}' WHERE action = 'test.tamper'`); err != nil {
		t.Fatal(err)
	}

	bad := adm.get("/admin/audit/verify")
	if bad.Code != 200 || !strings.Contains(bad.Body, `"ok":false`) || !strings.Contains(bad.Body, "broken_id") {
		t.Fatalf("a tampered chain must be reported: %d %s", bad.Code, bad.Body)
	}

	// dọn: xóa dòng bị sửa và các dòng sau nó để các test sau không thấy chuỗi hỏng
	if _, err := a.pool.Exec(context.Background(), `DELETE FROM audit_logs WHERE id >= (SELECT min(id) FROM audit_logs WHERE action = 'test.tamper')`); err != nil {
		t.Fatal(err)
	}
}

// Database chết giữa chừng: mọi trang trả 500 (trang quản trị) hoặc 503 (xác thực API), không treo và không lộ chi tiết.
func TestAppServerErrorsWhenTheDatabaseIsGone(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	key := ""

	r := adm.do("POST", "/admin/apikeys", url.Values{"name": {uniq("e")}, "rps_limit": {"100"}, "daily_quota": {"0"}}, nil)
	if i := strings.Index(r.Body, "vsf_"); i >= 0 {
		key = r.Body[i : i+45]
	}

	if key == "" {
		t.Fatal("no key created")
	}

	a.st.Close() // mất database

	r = adm.get("/admin/entries")
	if r.Code != 500 || strings.Contains(strings.ToLower(r.Body), "pgx") || strings.Contains(r.Body, "closed pool") {
		t.Errorf("an admin page without a database: %d %.200s", r.Code, r.Body)
	}

	if r := a.anon().do("GET", "/v1/check?type=phone&value=0901234567", nil, map[string]string{"X-API-Key": key}); r.Code != 503 {
		t.Errorf("api authentication without a database: %d, want 503", r.Code)
	}

	if r := a.anon().get("/readyz"); r.Code != 503 {
		t.Errorf("readyz without a database must report not ready: %d", r.Code)
	}

	if r := a.anon().get("/healthz"); r.Code != 200 {
		t.Errorf("healthz is liveness only and must not depend on the database: %d", r.Code)
	}
}

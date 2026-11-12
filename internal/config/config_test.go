package config

import "testing"

const (
	testDataKey = "0123456789abcdef0123456789abcdef-data"
	testPepper  = "fedcba9876543210fedcba9876543210-pepper"
)

// TestValidate kiểm tra các điều kiện hợp lệ của cấu hình (secret, chế độ production, ...).
func TestValidate(t *testing.T) {
	ok := Config{AppEnv: "development", HTTPAddr: "127.0.0.1:8080", SessionSecret: "x",
		DataKey: testDataKey, DataPepper: testPepper, DataKeyVersion: 1}
	if err := ok.validate(); err != nil {
		t.Fatalf("dev config should be valid: %v", err)
	}

	tests := []struct {
		name string
		mut  func(c *Config)
	}{
		{"missing secret", func(c *Config) { c.SessionSecret = "" }},
		{"bad env", func(c *Config) { c.AppEnv = "staging" }},
		{"auth disabled on all interfaces", func(c *Config) { c.AuthDisabled = true; c.HTTPAddr = ":8080" }},
		{"auth disabled on 0.0.0.0", func(c *Config) { c.AuthDisabled = true; c.HTTPAddr = "0.0.0.0:8080" }},
		{"missing data key", func(c *Config) { c.DataKey = "" }},
		{"short pepper", func(c *Config) { c.DataPepper = "short" }},
		{"same key and pepper", func(c *Config) { c.DataPepper = c.DataKey }},
		{"key version zero", func(c *Config) { c.DataKeyVersion = 0 }},
		{"key version negative", func(c *Config) { c.DataKeyVersion = -3 }},
		{"key version overflows smallint", func(c *Config) { c.DataKeyVersion = 70000 }},
		{"prod short secret", func(c *Config) { c.AppEnv = "production"; c.CookieSecure = true }},
		{"prod insecure cookie", func(c *Config) {
			c.AppEnv = "production"
			c.SessionSecret = "0123456789012345678901234567890123"
		}},
		{"metrics token too short", func(c *Config) { c.MetricsToken = "short" }},
		{"prod without proxy declaration", func(c *Config) {
			c.AppEnv = "production"
			c.CookieSecure = true
			c.SessionSecret = "0123456789012345678901234567890123"
		}},
		{"prod proxies and none conflict", func(c *Config) {
			c.AppEnv = "production"
			c.CookieSecure = true
			c.NoProxy = true
			c.TrustedProxies, _ = ParseCIDRs("10.0.0.0/8")
			c.SessionSecret = "0123456789012345678901234567890123"
		}},
		{"prod auth disabled", func(c *Config) {
			c.AppEnv = "production"
			c.CookieSecure = true
			c.AuthDisabled = true
			c.SessionSecret = "0123456789012345678901234567890123"
		}},
	}
	prod := Config{AppEnv: "production", HTTPAddr: "127.0.0.1:8080", CookieSecure: true,
		SessionSecret: "0123456789012345678901234567890123", DataKey: testDataKey, DataPepper: testPepper, DataKeyVersion: 1,
		NoProxy: true}

	if err := (func() Config { c := prod; c.DatabaseURL = "postgres://u:p@db/vsf?sslmode=verify-full"; return c })().validate(); err != nil {
		t.Fatalf("prod with verify-full should be valid: %v", err)
	}

	for _, dsn := range []string{
		"postgres://u:p@db/vsf?sslmode=disable",
		"postgres://u:p@db/vsf",
		"postgres://u:p@db/vsf?sslmode=prefer",
		"host=db user=u sslmode=disable",
	} {
		c := prod
		c.DatabaseURL = dsn
		if err := c.validate(); err == nil {
			t.Errorf("prod should reject DATABASE_URL %q", dsn)
		}
	}

	rc := prod
	rc.DatabaseURL = "postgres://u:p@db/vsf?sslmode=require"
	rc.ReadDatabaseURL = "postgres://u:p@replica/vsf?sslmode=disable"
	if err := rc.validate(); err == nil {
		t.Error("prod should reject insecure READ_DATABASE_URL")
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := ok
			tc.mut(&c)

			if err := c.validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}

	c := ok
	c.AuthDisabled = true

	if err := c.validate(); err != nil {
		t.Fatalf("auth disabled on localhost in dev should be ok: %v", err)
	}
}

// C4: khóa cũ khai báo bằng DATA_KEY_V<n>.
func TestRetiredDataKeys(t *testing.T) {
	got, err := retiredDataKeys([]string{
		"PATH=/usr/bin", "DATA_KEY=current", "DATA_KEY_VERSION=3", "DATA_PEPPER=p", // không phải khóa cũ
		"DATA_KEY_V1=old-one", "data_key_v2=old-two", "DATA_KEY_V7=", // chữ thường vẫn nhận (Windows); rỗng = chưa đặt
		"DATA_KEY_VX=nope", "DATA_KEY_V=nope", "MY_DATA_KEY_V9=nope", // tên không khớp: bỏ qua
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(got) != 2 || got[1] != "old-one" || got[2] != "old-two" {
		t.Fatalf("got %v, want chỉ phiên bản 1 và 2", got)
	}

	for _, env := range [][]string{
		{"DATA_KEY_V0=x"},                   // phiên bản bắt đầu từ 1
		{"DATA_KEY_V99999=x"},               // vượt SMALLINT
		{"DATA_KEY_V1=a", "DATA_KEY_V01=b"}, // hai tên cùng chỉ phiên bản 1: mơ hồ
	} {
		if _, err := retiredDataKeys(env); err == nil {
			t.Errorf("%v phải bị từ chối", env)
		}
	}
}

// TestLoadReadsRetiredKeysFromEnvironment kiểm tra Load đọc các biến DATA_KEY_V<n> thành khóa cũ.
func TestLoadReadsRetiredKeysFromEnvironment(t *testing.T) {
	t.Setenv("SESSION_SECRET", "x")
	t.Setenv("DATA_KEY", testDataKey)
	t.Setenv("DATA_PEPPER", testPepper)
	t.Setenv("DATA_KEY_VERSION", "2")
	t.Setenv("DATA_KEY_V1", "0123456789abcdef-older-key-0123456789abcdef")

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	if c.DataKeyVersion != 2 || len(c.DataKeysRetired) != 1 || c.DataKeysRetired[1] == "" {
		t.Fatalf("DataKeyVersion=%d retired=%v", c.DataKeyVersion, c.DataKeysRetired)
	}

	t.Setenv("DATA_KEY_VERSION", "70000")

	if _, err := Load(); err == nil {
		t.Fatal("phiên bản vượt SMALLINT phải bị từ chối thay vì bị cắt âm thầm")
	}
}

// TestParseCIDRs kiểm tra ParseCIDRs chấp nhận CIDR và IP đơn, từ chối giá trị sai.
func TestParseCIDRs(t *testing.T) {
	got, err := ParseCIDRs("10.0.0.0/8, 192.168.1.5 ,::1")
	if err != nil || len(got) != 3 {
		t.Fatalf("got %v err %v", got, err)
	}

	if got[1].String() != "192.168.1.5/32" || got[2].String() != "::1/128" {
		t.Fatalf("unexpected %v", got)
	}

	if n, err := ParseCIDRs(""); err != nil || len(n) != 0 {
		t.Fatalf("empty list: %v %v", n, err)
	}

	for _, bad := range []string{"abc", "10.0.0.0/99", "1.2.3"} {
		if _, err := ParseCIDRs(bad); err == nil {
			t.Fatalf("%q should fail", bad)
		}
	}
}

// TestProductionProxyAndMetrics kiểm tra các tổ hợp hợp lệ của TRUSTED_PROXIES và METRICS_TOKEN ở production.
func TestProductionProxyAndMetrics(t *testing.T) {
	prod := Config{AppEnv: "production", HTTPAddr: "127.0.0.1:8080", CookieSecure: true,
		SessionSecret: "0123456789012345678901234567890123", DataKey: testDataKey, DataPepper: testPepper, DataKeyVersion: 1}

	withProxies := prod
	withProxies.TrustedProxies, _ = ParseCIDRs("10.0.0.0/8")

	if err := withProxies.validate(); err != nil {
		t.Fatalf("production with TRUSTED_PROXIES should be valid: %v", err)
	}

	noProxy := prod
	noProxy.NoProxy = true
	noProxy.MetricsToken = "0123456789abcdef"

	if err := noProxy.validate(); err != nil {
		t.Fatalf("production with TRUSTED_PROXIES_NONE and a 16-char token should be valid: %v", err)
	}

	if w := noProxy.Warnings(); len(w) != 0 {
		t.Fatalf("no warning expected when METRICS_TOKEN is set, got %v", w)
	}

	noProxy.MetricsToken = ""

	if w := noProxy.Warnings(); len(w) != 1 {
		t.Fatalf("expected one warning for empty METRICS_TOKEN in production, got %v", w)
	}

	dev := Config{AppEnv: "development"}
	if w := dev.Warnings(); len(w) != 0 {
		t.Fatalf("development should not warn, got %v", w)
	}
}

// TestKeyFingerprint kiểm tra vân tay khóa ổn định, ngắn và không chứa khóa.
func TestKeyFingerprint(t *testing.T) {
	if KeyFingerprint("") != "" {
		t.Fatal("empty key must give empty fingerprint")
	}

	a, b := KeyFingerprint(testDataKey), KeyFingerprint(testPepper)
	if len(a) != 16 || a == b || a != KeyFingerprint(testDataKey) {
		t.Fatalf("unexpected fingerprints %q %q", a, b)
	}
}

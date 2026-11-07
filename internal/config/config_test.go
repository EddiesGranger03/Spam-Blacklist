package config

import "testing"

const (
	testDataKey = "0123456789abcdef0123456789abcdef-data"
	testPepper  = "fedcba9876543210fedcba9876543210-pepper"
)

func TestValidate(t *testing.T) {
	ok := Config{AppEnv: "development", HTTPAddr: "127.0.0.1:8080", SessionSecret: "x",
		DataKey: testDataKey, DataPepper: testPepper}
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
		{"prod short secret", func(c *Config) { c.AppEnv = "production"; c.CookieSecure = true }},
		{"prod insecure cookie", func(c *Config) {
			c.AppEnv = "production"
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
		SessionSecret: "0123456789012345678901234567890123", DataKey: testDataKey, DataPepper: testPepper}

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

package config

import "testing"

func TestValidate(t *testing.T) {
	ok := Config{AppEnv: "development", HTTPAddr: "127.0.0.1:8080", SessionSecret: "x"}
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

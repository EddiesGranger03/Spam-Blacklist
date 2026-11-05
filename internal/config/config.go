package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv   string
	HTTPAddr string

	DatabaseURL     string
	ReadDatabaseURL string
	PGMaxConns      int

	RedisAddr string
	CacheTTL  time.Duration

	SessionSecret  string
	CookieSecure   bool
	BootstrapEmail string
	BootstrapPass  string

	AuthDisabled bool

	DefaultRegion string

	BloomExpectedItems   uint64
	BloomRebuildInterval time.Duration
	PollInterval         time.Duration

	RateLimitRPS int
}

func Load() (Config, error) {
	c := Config{
		AppEnv:               getenv("APP_ENV", "development"),
		HTTPAddr:             getenv("HTTP_ADDR", "127.0.0.1:8080"),
		DatabaseURL:          getenv("DATABASE_URL", "postgres://vsf:vsf@localhost:5433/vsf?sslmode=disable"),
		ReadDatabaseURL:      getenv("READ_DATABASE_URL", ""),
		PGMaxConns:           getenvInt("PG_MAX_CONNS", 32),
		RedisAddr:            getenv("REDIS_ADDR", ""),
		CacheTTL:             getenvDuration("CACHE_TTL", 10*time.Minute),
		SessionSecret:        getenv("SESSION_SECRET", ""),
		CookieSecure:         getenvBool("COOKIE_SECURE", false),
		BootstrapEmail:       getenv("BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapPass:        getenv("BOOTSTRAP_ADMIN_PASSWORD", ""),
		AuthDisabled:         getenvBool("AUTH_DISABLED", false),
		DefaultRegion:        strings.ToUpper(getenv("DEFAULT_REGION", "VN")),
		BloomExpectedItems:   uint64(getenvInt("BLOOM_EXPECTED_ITEMS", 10_000_000)),
		BloomRebuildInterval: getenvDuration("BLOOM_REBUILD_INTERVAL", 24*time.Hour),
		PollInterval:         getenvDuration("POLL_INTERVAL", time.Second),
		RateLimitRPS:         getenvInt("RATE_LIMIT_RPS", 100),
	}
	return c, c.validate()
}

func (c Config) validate() error {
	if c.AppEnv != "development" && c.AppEnv != "production" {
		return fmt.Errorf("APP_ENV must be development or production, got %q", c.AppEnv)
	}

	if c.SessionSecret == "" {
		return fmt.Errorf("SESSION_SECRET is required")
	}

	if c.AppEnv == "production" {
		if len(c.SessionSecret) < 32 {
			return fmt.Errorf("SESSION_SECRET must be at least 32 characters in production")
		}

		if !c.CookieSecure {
			return fmt.Errorf("COOKIE_SECURE must be true in production")
		}

		if c.AuthDisabled {
			return fmt.Errorf("AUTH_DISABLED is not allowed in production")
		}
	}

	if c.AuthDisabled && !isLoopbackAddr(c.HTTPAddr) {
		return fmt.Errorf("AUTH_DISABLED requires HTTP_ADDR bound to localhost, got %q", c.HTTPAddr)
	}

	return nil
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}

	return def
}

func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}

	return def
}

func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}

	return def
}

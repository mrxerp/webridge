package config

import (
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration accepts both "30s" strings and bare integers (nanoseconds), so
// pre-existing configs like `write_timeout: 0` still parse.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	if n.Tag == "!!int" {
		var i int64
		if err := n.Decode(&i); err != nil {
			return err
		}
		*d = Duration(i)
		return nil
	}
	var s string
	if err := n.Decode(&s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(v)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	WeTransfer WeTransferConfig `yaml:"wetransfer"`
	Limits     LimitsConfig     `yaml:"limits"`
	Logging    LoggingConfig    `yaml:"logging"`
	UI         UIConfig         `yaml:"ui"`
	Auth       AuthConfig       `yaml:"auth"`
	LDAP       LDAPConfig       `yaml:"ldap"`
}

type AuthConfig struct {
	SessionTTL Duration     `yaml:"session_ttl"`
	Users      []UserConfig `yaml:"users"`
}

type UserConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Role     string `yaml:"role"`
}

type LDAPConfig struct {
	Enabled            bool     `yaml:"enabled" json:"enabled"`
	Host               string   `yaml:"host" json:"host"`
	Port               int      `yaml:"port" json:"port"`
	UseTLS             bool     `yaml:"starttls" json:"starttls"`
	InsecureSkipVerify bool     `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	BindDN             string   `yaml:"bind_dn" json:"bind_dn"`
	BindPassword       string   `yaml:"bind_password" json:"bind_password,omitempty"`
	BaseDN             string   `yaml:"base_dn" json:"base_dn"`
	UserFilter         string   `yaml:"user_filter" json:"user_filter"`
	DefaultGroups      []string `yaml:"default_groups" json:"default_groups,omitempty"`
}

type ServerConfig struct {
	Host           string   `yaml:"host"`
	Port           int      `yaml:"port"`
	ReadTimeout    Duration `yaml:"read_timeout"`
	WriteTimeout   Duration `yaml:"write_timeout"`
	IdleTimeout    Duration `yaml:"idle_timeout"`
	MaxHeaderBytes int      `yaml:"max_header_bytes"`
}

type WeTransferConfig struct {
	UserAgent      string   `yaml:"user_agent"`
	RequestTimeout Duration `yaml:"request_timeout"`
	MaxRedirects   int      `yaml:"max_redirects"`
}

type LimitsConfig struct {
	MaxConcurrentDownloads int `yaml:"max_concurrent_downloads"`
	MaxFileSizeGB          int `yaml:"max_file_size_gb"`
	RateLimitPerMinute     int `yaml:"rate_limit_per_minute"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type UIConfig struct {
	Enabled      bool   `yaml:"enabled"`
	Title        string `yaml:"title"`
	MaxURLLength int    `yaml:"max_url_length"`
}

// Load reads path as YAML over built-in defaults; PROXY_* env vars override.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	} else if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	applyEnv(&cfg)
	return &cfg, nil
}

func defaults() Config {
	return Config{
		Server: ServerConfig{
			Host:           "0.0.0.0",
			Port:           8080,
			ReadTimeout:    Duration(30 * time.Second),
			IdleTimeout:    Duration(120 * time.Second),
			MaxHeaderBytes: 1048576,
		},
		WeTransfer: WeTransferConfig{
			UserAgent:      "Mozilla/5.0 (compatible; ProxyDownloader/1.0)",
			RequestTimeout: Duration(30 * time.Second),
			MaxRedirects:   10,
		},
		Limits:  LimitsConfig{MaxConcurrentDownloads: 50, MaxFileSizeGB: 2, RateLimitPerMinute: 30},
		Logging: LoggingConfig{Level: "info", Format: "json"},
		UI:      UIConfig{Enabled: true, Title: "File Download Portal", MaxURLLength: 2048},
		Auth: AuthConfig{
			SessionTTL: Duration(24 * time.Hour),
			Users: []UserConfig{
				{Username: "admin", Password: "admin123", Role: "admin"},
				{Username: "user", Password: "user123", Role: "user"},
			},
		},
		LDAP: LDAPConfig{Port: 389, UserFilter: "(uid=%s)", DefaultGroups: []string{"users"}},
	}
}

func applyEnv(c *Config) {
	setStr(&c.Server.Host, "PROXY_SERVER_HOST")
	setInt(&c.Server.Port, "PROXY_SERVER_PORT")
	setDur((*time.Duration)(&c.Server.ReadTimeout), "PROXY_SERVER_READ_TIMEOUT")
	setDur((*time.Duration)(&c.Server.WriteTimeout), "PROXY_SERVER_WRITE_TIMEOUT")
	setDur((*time.Duration)(&c.Server.IdleTimeout), "PROXY_SERVER_IDLE_TIMEOUT")
	setInt(&c.Server.MaxHeaderBytes, "PROXY_SERVER_MAX_HEADER_BYTES")

	setStr(&c.WeTransfer.UserAgent, "PROXY_WETRANSFER_USER_AGENT")
	setDur((*time.Duration)(&c.WeTransfer.RequestTimeout), "PROXY_WETRANSFER_REQUEST_TIMEOUT")
	setInt(&c.WeTransfer.MaxRedirects, "PROXY_WETRANSFER_MAX_REDIRECTS")

	setInt(&c.Limits.MaxConcurrentDownloads, "PROXY_LIMITS_MAX_CONCURRENT_DOWNLOADS")
	setInt(&c.Limits.MaxFileSizeGB, "PROXY_LIMITS_MAX_FILE_SIZE_GB")
	setInt(&c.Limits.RateLimitPerMinute, "PROXY_LIMITS_RATE_LIMIT_PER_MINUTE")

	setStr(&c.Logging.Level, "PROXY_LOGGING_LEVEL")
	setStr(&c.Logging.Format, "PROXY_LOGGING_FORMAT")

	setBool(&c.UI.Enabled, "PROXY_UI_ENABLED")
	setStr(&c.UI.Title, "PROXY_UI_TITLE")
	setInt(&c.UI.MaxURLLength, "PROXY_UI_MAX_URL_LENGTH")
}

func setStr(p *string, key string) {
	if v := os.Getenv(key); v != "" {
		*p = v
	}
}

func setInt(p *int, key string) {
	if v, err := strconv.Atoi(os.Getenv(key)); err == nil {
		*p = v
	}
}

func setDur(p *time.Duration, key string) {
	if v, err := time.ParseDuration(os.Getenv(key)); err == nil {
		*p = v
	}
}

func setBool(p *bool, key string) {
	if v, err := strconv.ParseBool(os.Getenv(key)); err == nil {
		*p = v
	}
}

func GetConfigPath() string {
	if p := os.Getenv("CONFIG_PATH"); p != "" {
		return p
	}
	return "config.yaml"
}

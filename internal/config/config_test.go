package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	const config24h = Duration(24 * time.Hour)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("server:\n  port: 9090\nlimits:\n  max_file_size_gb: 5\n"), 0o600)

	t.Setenv("PROXY_SERVER_PORT", "7070")
	t.Setenv("PROXY_LOGGING_LEVEL", "debug")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Server.Port != 7070 {
		t.Errorf("env should override yaml: got port %d", cfg.Server.Port)
	}
	if cfg.Limits.MaxFileSizeGB != 5 {
		t.Errorf("yaml override failed: got %d", cfg.Limits.MaxFileSizeGB)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("env override failed: got %q", cfg.Logging.Level)
	}
	if cfg.Auth.SessionTTL != config24h {
		t.Errorf("default lost: got %s", cfg.Auth.SessionTTL)
	}
	if len(cfg.Auth.Users) != 2 || cfg.Auth.Users[0].Username != "admin" {
		t.Errorf("default users lost: %+v", cfg.Auth.Users)
	}
	if cfg.UI.Title != "File Download Portal" {
		t.Errorf("default title lost: %q", cfg.UI.Title)
	}

	// missing file falls back to defaults
	cfg2, err := Load(filepath.Join(dir, "nope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Server.Port != 7070 { // env still applies
		t.Errorf("missing-file load: got port %d", cfg2.Server.Port)
	}
	if cfg2.WeTransfer.RequestTimeout != Duration(30*time.Second) {
		t.Errorf("missing-file default lost: %s", cfg2.WeTransfer.RequestTimeout)
	}
}

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadRequiresWatchPaths(t *testing.T) {
	path := writeConfig(t, "watch_paths: []\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for empty watch_paths")
	}
}

func TestLoadDefaults(t *testing.T) {
	path := writeConfig(t, `watch_paths:
  - path: /tmp/cache
    ecosystem: pypi
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel default = %q, want info", cfg.LogLevel)
	}
	if cfg.ScanTimeout != 30 {
		t.Errorf("ScanTimeout default = %d, want 30", cfg.ScanTimeout)
	}
	if cfg.WatcherMode != "auto" {
		t.Errorf("WatcherMode default = %q, want auto", cfg.WatcherMode)
	}
	if cfg.Tools.Syft != "syft" || cfg.Tools.Grype != "grype" || cfg.Tools.OsvScanner != "osv-scanner" {
		t.Errorf("unexpected tool defaults: %+v", cfg.Tools)
	}
}

func TestLoadExpandsToolPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir available")
	}

	path := writeConfig(t, `watch_paths:
  - path: /tmp/cache
    ecosystem: pypi
tools:
  syft: ~/.local/bin/syft
  grype: ~/.local/bin/grype
  osv_scanner: ~/.local/bin/osv-scanner
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := filepath.Join(home, ".local/bin/syft")
	if cfg.Tools.Syft != want {
		t.Errorf("Tools.Syft = %q, want %q (expandPath should apply to tool paths)", cfg.Tools.Syft, want)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadRejectsInvalidWatcherMode(t *testing.T) {
	path := writeConfig(t, `watch_paths:
  - path: /tmp/cache
    ecosystem: pypi
watcher_mode: bogus
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for invalid watcher_mode")
	}
}

func TestLoadAcceptsValidWatcherModes(t *testing.T) {
	for _, mode := range []string{"auto", "fanotify", "quarantine"} {
		path := writeConfig(t, `watch_paths:
  - path: /tmp/cache
    ecosystem: pypi
watcher_mode: `+mode+"\n")
		if _, err := Load(path); err != nil {
			t.Errorf("watcher_mode=%q: unexpected error: %v", mode, err)
		}
	}
}

func TestLoadRejectsNonPositiveScanTimeout(t *testing.T) {
	for _, timeout := range []int{0, -1} {
		path := writeConfig(t, `watch_paths:
  - path: /tmp/cache
    ecosystem: pypi
scan_timeout_seconds: `+strconv.Itoa(timeout)+"\n")
		if _, err := Load(path); err == nil {
			t.Errorf("scan_timeout_seconds=%d: expected error", timeout)
		}
	}
}

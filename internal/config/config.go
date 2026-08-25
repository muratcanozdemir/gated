package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	WatchPaths  []WatchPath `yaml:"watch_paths"`
	Tools       Tools       `yaml:"tools"`
	PolicyDir   string      `yaml:"policy_dir"`
	VerdictDir  string      `yaml:"verdict_dir"`
	LogLevel    string      `yaml:"log_level"`
	WarnOnly    bool        `yaml:"warn_only"`
	WatcherMode string      `yaml:"watcher_mode"`
	ScanTimeout int         `yaml:"scan_timeout_seconds"`
}

type WatchPath struct {
	Path      string `yaml:"path"`
	Ecosystem string `yaml:"ecosystem"` // pypi, go, maven, cargo, npm
}

type Tools struct {
	Syft       string `yaml:"syft"`
	Grype      string `yaml:"grype"`
	OsvScanner string `yaml:"osv_scanner"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		LogLevel:    "info",
		ScanTimeout: 30,
		WatcherMode: "auto",
		VerdictDir:  "/var/lib/gated/verdicts",
		PolicyDir:   "/etc/gated/policy",
		Tools: Tools{
			Syft:       "syft",
			Grype:      "grype",
			OsvScanner: "osv-scanner",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Expand ~ and env vars in all paths.
	for i := range cfg.WatchPaths {
		cfg.WatchPaths[i].Path = expandPath(cfg.WatchPaths[i].Path)
	}
	cfg.PolicyDir = expandPath(cfg.PolicyDir)
	cfg.VerdictDir = expandPath(cfg.VerdictDir)
	cfg.Tools.Syft = expandPath(cfg.Tools.Syft)
	cfg.Tools.Grype = expandPath(cfg.Tools.Grype)
	cfg.Tools.OsvScanner = expandPath(cfg.Tools.OsvScanner)

	if len(cfg.WatchPaths) == 0 {
		return nil, fmt.Errorf("no watch_paths configured")
	}

	switch cfg.WatcherMode {
	case "auto", "fanotify", "quarantine":
	default:
		return nil, fmt.Errorf("invalid watcher_mode %q (must be auto, fanotify, or quarantine)", cfg.WatcherMode)
	}

	if cfg.ScanTimeout <= 0 {
		return nil, fmt.Errorf("scan_timeout_seconds must be positive, got %d", cfg.ScanTimeout)
	}

	return cfg, nil
}

func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}
	return os.ExpandEnv(p)
}

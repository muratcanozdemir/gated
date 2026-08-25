package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/muratcanozdemir/gated/internal/config"
	"github.com/muratcanozdemir/gated/internal/policy"
	"github.com/muratcanozdemir/gated/internal/resolver"
	"github.com/muratcanozdemir/gated/internal/scanner"
	"github.com/muratcanozdemir/gated/internal/verdict"
	"github.com/muratcanozdemir/gated/internal/watcher"
)

// Set by -ldflags at build time.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	cfgPath := flag.String("config", "/etc/gated/config.yaml", "path to config file")
	validate := flag.Bool("validate", false, "validate config and policies, then exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("gated %s (commit=%s, built=%s, %s/%s)\n",
			version, commit, buildDate, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	initLogging(cfg.LogLevel)

	// Initialize policy engine.
	policyEngine, err := policy.NewEngine(cfg.PolicyDir)
	if err != nil {
		slog.Error("policy engine init failed", "err", err)
		os.Exit(1)
	}

	if err := policyEngine.ValidatePolicies(); err != nil {
		slog.Error("policy validation failed", "err", err)
		os.Exit(1)
	}
	slog.Info("policies validated", "dir", cfg.PolicyDir)

	if *validate {
		fmt.Println("config and policies OK")
		os.Exit(0)
	}

	// Note: privilege requirements depend on watcher_mode.
	// fanotify needs CAP_SYS_ADMIN; quarantine mode needs nothing.
	// The watcher auto-detects and falls back gracefully.

	// Initialize verdict cache.
	cache, err := verdict.NewCache(cfg.VerdictDir)
	if err != nil {
		slog.Error("verdict cache init failed", "err", err)
		os.Exit(1)
	}

	// Initialize scanner.
	scan := scanner.NewOrchestrator(cfg.Tools, cfg.ScanTimeout)

	// The decision function wired into the fanotify event loop.
	decisionFn := func(path, ecosystem string, pid int32) bool {
		// Fast path: check cache.
		if entry := cache.Lookup(path); entry != nil {
			return entry.Allowed
		}

		// Mark pending so concurrent opens block on us.
		if !cache.MarkPending(path) {
			// Another goroutine is handling this; wait for the verdict.
			if entry := cache.Lookup(path); entry != nil {
				return entry.Allowed
			}
			// If still nil after waiting, fail open.
			slog.Warn("verdict still unavailable after wait, allowing", "path", path)
			return true
		}

		// Resolve path to package identity.
		pkg := resolver.Resolve(path, ecosystem)
		if pkg == nil {
			slog.Debug("unresolvable path, allowing", "path", path)
			entry := &verdict.Entry{
				Ecosystem: ecosystem,
				Name:      "unresolved",
				Version:   "unknown",
				Allowed:   true,
				ScannedAt: time.Now().UTC().Format(time.RFC3339),
			}
			cache.Store(path, entry)
			return true
		}

		slog.Info("scanning", "ecosystem", pkg.Ecosystem, "name", pkg.Name, "version", pkg.Version)

		// Run all scans.
		result, err := scan.Scan(pkg)
		if err != nil {
			slog.Error("scan failed, failing open", "err", err, "pkg", pkg.Name)
			entry := &verdict.Entry{
				Ecosystem: pkg.Ecosystem,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Allowed:   true,
				Reasons:   []string{fmt.Sprintf("scan error: %v", err)},
				ScannedAt: time.Now().UTC().Format(time.RFC3339),
			}
			cache.Store(path, entry)
			return true
		}

		// Evaluate policy.
		inputJSON, err := result.InputJSON()
		if err != nil {
			slog.Error("marshal scan result failed", "err", err)
			cache.Store(path, &verdict.Entry{
				Ecosystem: pkg.Ecosystem,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Allowed:   true,
				ScannedAt: time.Now().UTC().Format(time.RFC3339),
			})
			return true
		}

		v, err := policyEngine.Evaluate(inputJSON)
		if err != nil {
			slog.Error("policy eval failed, failing open", "err", err, "pkg", pkg.Name)
			cache.Store(path, &verdict.Entry{
				Ecosystem: pkg.Ecosystem,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Allowed:   true,
				Reasons:   []string{fmt.Sprintf("policy error: %v", err)},
				ScannedAt: time.Now().UTC().Format(time.RFC3339),
			})
			return true
		}

		entry := &verdict.Entry{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Allowed:   v.Allowed,
			Reasons:   v.Reasons,
			ScannedAt: time.Now().UTC().Format(time.RFC3339),
		}
		cache.Store(path, entry)

		if v.Allowed {
			slog.Info("ALLOWED", "pkg", pkg.Name, "version", pkg.Version)
		} else {
			slog.Warn("DENIED", "pkg", pkg.Name, "version", pkg.Version, "reasons", v.Reasons)
		}

		return v.Allowed
	}

	// Start fanotify watcher.
	w, err := watcher.New(watcher.Config{
		Paths:       cfg.WatchPaths,
		DecisionFn:  decisionFn,
		WarnOnly:    cfg.WarnOnly,
		WatcherMode: watcher.Mode(cfg.WatcherMode),
	})
	if err != nil {
		slog.Error("watcher init failed", "err", err)
		os.Exit(1)
	}
	defer w.Close()

	slog.Info("watcher active", "mode", w.Mode())

	// Handle signals for clean shutdown and policy reload.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				slog.Info("SIGHUP received, reloading policies and invalidating cache")
				if err := policyEngine.ValidatePolicies(); err != nil {
					slog.Error("policy reload validation failed, keeping old policies", "err", err)
				} else {
					cache.InvalidateAll()
					slog.Info("policy reload complete")
				}
			case syscall.SIGINT, syscall.SIGTERM:
				total, allowed, denied := cache.Stats()
				slog.Info("shutting down", "verdicts_total", total, "allowed", allowed, "denied", denied)
				w.Close()
				os.Exit(0)
			}
		}
	}()

	// Periodic cache pruning (verdicts older than 24h).
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			pruned := cache.PruneOlderThan(24 * time.Hour)
			if pruned > 0 {
				slog.Info("pruned stale verdicts", "count", pruned)
			}
		}
	}()

	slog.Info("gated started",
		"version", version,
		"platform", runtime.GOOS+"/"+runtime.GOARCH,
		"watch_paths", len(cfg.WatchPaths),
		"warn_only", cfg.WarnOnly,
		"policy_dir", cfg.PolicyDir,
	)

	if err := w.Run(); err != nil {
		slog.Error("watcher error", "err", err)
		os.Exit(1)
	}
}

func initLogging(level string) {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	slog.SetDefault(slog.New(handler))
}

package quarantine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	quarantineDir  = ".gated-quarantine"
	quarantineSuffix = ".gated-hold"
)

// Engine handles the quarantine-scan-release cycle.
// Works on any platform: rename is atomic on all major OS filesystems.
type Engine struct {
	decisionFn func(path string, ecosystem string, pid int32) bool
	warnOnly   bool

	// Track files we've already processed to avoid re-quarantining
	// on duplicate notifications.
	mu       sync.RWMutex
	seen     map[string]time.Time
	inflight map[string]struct{}
}

func NewEngine(decisionFn func(string, string, int32) bool, warnOnly bool) *Engine {
	return &Engine{
		decisionFn: decisionFn,
		warnOnly:   warnOnly,
		seen:       make(map[string]time.Time),
		inflight:   make(map[string]struct{}),
	}
}

// HandleNewArtifact is called when a new file appears in a watched directory.
// It quarantines the file, runs the decision function, then releases or deletes.
//
// This is the core cross-platform gating mechanism:
//   1. Rename file to quarantine location (atomic, blocks package manager)
//   2. Run scans against quarantined file
//   3. On allow: rename back to original path
//   4. On deny: delete quarantined file (or leave for audit)
//
// The package manager sees the file disappear briefly (quarantine window),
// then either reappear (allowed) or stay gone (denied). Most package managers
// handle "file not found" gracefully with a retry or error.
func (e *Engine) HandleNewArtifact(path, ecosystem string) {
	// Deduplicate: don't re-process files we've already seen.
	e.mu.RLock()
	if _, ok := e.seen[path]; ok {
		e.mu.RUnlock()
		return
	}
	if _, ok := e.inflight[path]; ok {
		e.mu.RUnlock()
		return
	}
	e.mu.RUnlock()

	e.mu.Lock()
	// Double-check after acquiring write lock.
	if _, ok := e.inflight[path]; ok {
		e.mu.Unlock()
		return
	}
	e.inflight[path] = struct{}{}
	e.mu.Unlock()

	defer func() {
		e.mu.Lock()
		delete(e.inflight, path)
		e.seen[path] = time.Now()
		e.mu.Unlock()
	}()

	// Verify the file still exists (might have been cleaned up already).
	if _, err := os.Stat(path); err != nil {
		return
	}

	holdPath := quarantinePath(path)

	// Ensure quarantine directory exists.
	holdDir := filepath.Dir(holdPath)
	if err := os.MkdirAll(holdDir, 0o700); err != nil {
		slog.Error("failed to create quarantine dir", "dir", holdDir, "err", err)
		return
	}

	// Step 1: Quarantine — atomic rename.
	if err := os.Rename(path, holdPath); err != nil {
		// Rename failed — file may have been consumed already. Not an error.
		slog.Debug("quarantine rename failed (likely already consumed)", "path", path, "err", err)
		return
	}

	slog.Info("quarantined", "path", path, "ecosystem", ecosystem)

	// Step 2: Run scans against the quarantined file.
	// The decision function gets the quarantined path so it can scan the actual bytes.
	// We pass the original path for package identity resolution.
	allowed := e.decisionFn(holdPath, ecosystem, -1)

	// Step 3: Release or delete.
	if allowed || e.warnOnly {
		if !allowed {
			slog.Warn("WARN_ONLY: would deny, releasing anyway", "path", path)
		}
		if err := os.Rename(holdPath, path); err != nil {
			slog.Error("failed to release from quarantine", "hold", holdPath, "original", path, "err", err)
			// Last resort: try to put it back somehow.
			return
		}
		slog.Info("released", "path", path)
	} else {
		// Denied: move to a permanent quarantine location for audit trail,
		// or delete based on config.
		auditPath := auditQuarantinePath(path)
		auditDir := filepath.Dir(auditPath)
		if err := os.MkdirAll(auditDir, 0o700); err == nil {
			if err := os.Rename(holdPath, auditPath); err == nil {
				slog.Warn("DENIED — quarantined for audit", "original", path, "audit", auditPath)
				return
			}
		}
		// Fallback: just delete.
		os.Remove(holdPath)
		slog.Warn("DENIED — deleted", "path", path)
	}
}

// PruneSeen removes entries from the seen map older than maxAge.
// Call periodically to prevent unbounded memory growth.
func (e *Engine) PruneSeen(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	pruned := 0

	e.mu.Lock()
	defer e.mu.Unlock()

	for k, t := range e.seen {
		if t.Before(cutoff) {
			delete(e.seen, k)
			pruned++
		}
	}
	return pruned
}

// quarantinePath computes the hold path for a file.
// Keeps it on the same filesystem (same parent directory) to ensure
// rename is atomic and doesn't cross mount boundaries.
func quarantinePath(original string) string {
	dir := filepath.Dir(original)
	base := filepath.Base(original)
	return filepath.Join(dir, quarantineDir, base+quarantineSuffix)
}

// auditQuarantinePath puts denied artifacts in a persistent audit location.
func auditQuarantinePath(original string) string {
	dir := filepath.Dir(original)
	base := filepath.Base(original)
	ts := time.Now().Format("20060102-150405")
	return filepath.Join(dir, quarantineDir, "denied",
		fmt.Sprintf("%s_%s%s", ts, base, quarantineSuffix))
}

// IsQuarantinePath returns true if the path is inside a quarantine directory.
// Used by watchers to skip events on quarantined files.
func IsQuarantinePath(path string) bool {
	return strings.Contains(path, quarantineDir)
}

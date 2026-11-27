package quarantine

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/muratcanozdemir/gated/internal/installer"
	"github.com/muratcanozdemir/gated/internal/resolver"
)

const (
	quarantineDir = ".gated-quarantine"
	// deniedSuffix marks denied artifacts kept for audit, so that nothing
	// mistakes them for usable packages. Hold files (being scanned) keep
	// their name: scanners recognize artifacts by it.
	deniedSuffix = ".gated-hold"
)

// Engine handles the quarantine-scan-release cycle.
// Works on any platform: rename is atomic on all major OS filesystems.
type Engine struct {
	decisionFn func(path string, ecosystem string, pid int32) bool
	warnOnly   bool

	// Explain, if set, names the package judged at a path and why it was
	// denied, for the warning written to a package manager that gated could
	// not stop (see installer).
	Explain func(path string) (pkg string, reasons []string)

	// Track what we've already processed to avoid re-quarantining on
	// duplicate notifications, including the one our own release raises.
	mu       sync.RWMutex
	seen     map[string]seenEntry
	inflight map[string]struct{}

	// Package managers seen working in each cache, for HandleInPlace.
	installers installerRegistry
}

// seenEntry records an artifact gated and left in place (released or
// allowed). Only that same file is a duplicate: a new file at the same path
// is a new download (a retry after a deny, say) and is gated again.
type seenEntry struct {
	at   time.Time
	file os.FileInfo
}

func NewEngine(decisionFn func(string, string, int32) bool, warnOnly bool) *Engine {
	return &Engine{
		decisionFn: decisionFn,
		warnOnly:   warnOnly,
		seen:       make(map[string]seenEntry),
		inflight:   make(map[string]struct{}),
	}
}

// HandleNewArtifact is called when a new file appears in a watched directory.
// It quarantines the file, runs the decision function, then releases or deletes.
//
// This is the core cross-platform gating mechanism:
//  1. Rename file to quarantine location (atomic, blocks package manager)
//  2. Run scans against quarantined file
//  3. On allow: rename back to original path
//  4. On deny: delete quarantined file (or leave for audit)
//
// The package manager sees the file disappear briefly (quarantine window),
// then either reappear (allowed) or stay gone (denied). Most package managers
// handle "file not found" gracefully with a retry or error.
func (e *Engine) HandleNewArtifact(path, ecosystem string) {
	if !e.begin(path) {
		return
	}
	kept := false // left at path (released): our own MOVED_TO must not re-gate it
	defer func() { e.end(path, kept) }()

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

	// Did we lose the race? A package manager that opened the file before
	// the rename keeps reading it through its open descriptor.
	readers := installer.Using(holdPath)
	defer installer.CloseAll(readers)

	// Step 2: Run scans against the quarantined file.
	// The decision function gets the hold path so it can scan the actual
	// bytes; it resolves package identity from OriginalPath(holdPath).
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
		kept = true
		slog.Info("released", "path", path)
		if !allowed {
			e.warnInstallers(readers, holdPath, "would be denied (warn-only mode, allowed anyway)", "")
		}
	} else {
		if len(readers) > 0 {
			e.warnInstallers(readers, holdPath, "DENIED",
				"%s opened it before gated could hold it: gated removed it, but it may have been used already.")
		}
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
		if err := os.Remove(holdPath); err != nil {
			slog.Error("DENIED — failed to delete quarantined file, orphaned", "path", holdPath, "err", err)
		} else {
			slog.Warn("DENIED — deleted", "path", path)
		}
	}
}

// begin claims path for processing; false means it is a duplicate (being
// processed, or the very file processed and left in place).
func (e *Engine) begin(path string) bool {
	fi, err := os.Stat(path)
	if err != nil {
		return false // gone already: consumed, or removed on a deny
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.inflight[path]; ok {
		return false
	}
	if s, ok := e.seen[path]; ok && os.SameFile(s.file, fi) {
		return false
	}
	e.inflight[path] = struct{}{}
	return true
}

// end releases path. kept records the file now at path as processed, so the
// event our own release raises (or a duplicate) is ignored; otherwise path
// is forgotten, and whatever appears there next is gated.
func (e *Engine) end(path string, kept bool) {
	var fi os.FileInfo
	if kept {
		fi, _ = os.Stat(path)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.inflight, path)
	if fi != nil {
		e.seen[path] = seenEntry{at: time.Now(), file: fi}
	} else {
		delete(e.seen, path)
	}
}

// HandleInPlace gates an artifact the package manager uses as soon as it
// lands (resolver.InPlace): it is scanned where it lies, never held. gated
// races the package manager here. On a deny it removes the artifact and what
// the package manager unpacked from it, so the next install fetches it again
// (and gated denies it before anything unpacks it, from the verdict cache),
// and it warns the package manager processes it found when the artifact
// appeared: whatever they did with it in the meantime stands.
func (e *Engine) HandleInPlace(ip *resolver.InPlace, ecosystem string) {
	path := ip.Pkg.Path
	if !e.begin(path) {
		return
	}
	kept := false
	defer func() { e.end(path, kept) }()

	// Who is installing it: found now, or already when it started working
	// in the cache (NoteActivity); by the time the verdict is in, it may be done.
	e.NoteActivity(ip.Root)
	procs, release := e.installersOf(ip.Root)
	defer release()

	slog.Info("gating in place", "path", path, "ecosystem", ecosystem, "installers", describe(procs))
	if e.decisionFn(path, ecosystem, -1) {
		kept = true
		return
	}
	if e.warnOnly {
		kept = true
		slog.Warn("WARN_ONLY: would deny, leaving in place", "path", path)
		e.warnInstallers(procs, path, "would be denied (warn-only mode, allowed anyway)", "")
		return
	}

	var failed []string
	for _, p := range ip.Remove {
		if err := removeAll(p); err != nil {
			failed = append(failed, p)
			slog.Error("DENIED — failed to remove", "path", p, "err", err)
		}
	}
	slog.Warn("DENIED — lost the race to the package manager, removed from its cache",
		"path", path, "removed", ip.Remove, "installers", describe(procs))
	if len(failed) > 0 {
		e.warnInstallers(procs, path, "DENIED",
			"%s unpacked it before gated could stop it, and gated could not remove it from the cache ("+strings.Join(failed, ", ")+"): delete it by hand.")
		return
	}
	e.warnInstallers(procs, path, "DENIED",
		"%s unpacked it before gated could stop it. gated removed it from the cache, but whatever this run built or installed from it stays: remove that, then rerun.")
}

// warnInstallers writes the verdict into each package manager's output.
// what says what happened ("DENIED"); advice is a sentence about the race,
// where %s stands for the process ("uv (pid 42)").
func (e *Engine) warnInstallers(procs []*installer.Process, path, what, advice string) {
	if len(procs) == 0 {
		return
	}
	name, reasons := filepath.Base(path), []string(nil)
	if e.Explain != nil {
		if n, r := e.Explain(path); n != "" {
			name, reasons = n, r
		}
	}
	for _, p := range procs {
		lines := []string{fmt.Sprintf("%s %s", name, what)}
		for _, r := range reasons {
			lines = append(lines, "  - "+r)
		}
		if advice != "" {
			lines = append(lines, fmt.Sprintf(advice, fmt.Sprintf("%s (pid %d)", p.Comm, p.PID)))
		}
		if err := p.Warn(lines...); err != nil {
			slog.Warn("could not warn package manager", "pid", p.PID, "comm", p.Comm, "err", err)
			continue
		}
		slog.Info("warned package manager", "pid", p.PID, "comm", p.Comm, "path", path)
	}
}

func describe(procs []*installer.Process) []string {
	out := make([]string, 0, len(procs))
	for _, p := range procs {
		out = append(out, fmt.Sprintf("%s[%d]", p.Comm, p.PID))
	}
	return out
}

// removeRetries and removeRetryDelay bound how long a deny keeps trying to
// remove what the package manager is still writing: with a cached verdict,
// the deny comes while go is unpacking the module, and a directory being
// filled cannot be removed ("directory not empty").
var (
	removeRetries    = 20
	removeRetryDelay = 250 * time.Millisecond
)

// removeAll deletes path, making directories writable first: go leaves the
// module cache read-only, and a directory's entries cannot be removed
// without write permission on it. It retries while the package manager is
// still writing there.
func removeAll(path string) error {
	var err error
	for range removeRetries {
		if err = removeOnce(path); err == nil {
			return nil
		}
		time.Sleep(removeRetryDelay)
	}
	return err
}

func removeOnce(path string) error {
	_ = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700) //nolint:gosec // G302: a directory about to be deleted, owner only
		}
		return nil
	})
	return os.RemoveAll(path)
}

// PruneSeen removes entries from the seen map older than maxAge.
// Call periodically to prevent unbounded memory growth.
func (e *Engine) PruneSeen(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	pruned := 0

	e.mu.Lock()
	defer e.mu.Unlock()

	for k, s := range e.seen {
		if s.at.Before(cutoff) {
			delete(e.seen, k)
			pruned++
		}
	}
	return pruned
}

// quarantinePath computes the hold path for a file: the same name in a
// quarantine directory next to it. Same filesystem (same parent directory),
// so the rename is atomic and doesn't cross mount boundaries. The name must
// not change: syft and grype decide what a file is (jar, wheel, sdist) by its
// name, and catalog nothing in, say, "x-1.0.jar.gated-hold".
func quarantinePath(original string) string {
	return filepath.Join(filepath.Dir(original), quarantineDir, filepath.Base(original))
}

// OriginalPath maps a hold path (quarantinePath) back to the artifact's
// original path. The decision function receives the hold path, where the
// bytes are; package identity comes from the original path, since resolvers
// read the file name and directory layout (e.g. Maven's group/artifact/version).
func OriginalPath(hold string) (string, bool) {
	dir := filepath.Dir(hold)
	if filepath.Base(dir) != quarantineDir || filepath.Base(hold) == quarantineDir {
		return "", false
	}
	return filepath.Join(filepath.Dir(dir), filepath.Base(hold)), true
}

// auditQuarantinePath puts denied artifacts in a persistent audit location.
func auditQuarantinePath(original string) string {
	dir := filepath.Dir(original)
	base := filepath.Base(original)
	ts := time.Now().Format("20060102-150405")
	return filepath.Join(dir, quarantineDir, "denied",
		fmt.Sprintf("%s_%s%s", ts, base, deniedSuffix))
}

// IsQuarantinePath returns true if the path is inside a quarantine directory.
// Used by watchers to skip events on quarantined files.
func IsQuarantinePath(path string) bool {
	return strings.Contains(path, quarantineDir)
}

package watcher

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/internal/gate-daemon/internal/config"
	"github.com/internal/gate-daemon/internal/quarantine"
)

// resolveEcosystem returns the ecosystem for the first configured watch
// path that prefixes path, or "" if none match.
func resolveEcosystem(paths []config.WatchPath, path string) string {
	for _, wp := range paths {
		if strings.HasPrefix(path, wp.Path) {
			return wp.Ecosystem
		}
	}
	return ""
}

// isMetadataFile filters out lockfiles, manifests, and dotfiles that
// accompany a package download but aren't themselves artifacts to gate.
func isMetadataFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	switch {
	case lower == "go.sum", lower == "go.mod":
		return true
	case lower == "package-lock.json", lower == "yarn.lock":
		return true
	case lower == "cargo.lock", lower == "cargo.toml":
		return true
	case lower == "requirements.txt", lower == "pyproject.toml":
		return true
	case strings.HasSuffix(lower, ".pom"), strings.HasSuffix(lower, ".xml"):
		return true
	case strings.HasPrefix(lower, "."):
		return true
	}
	return false
}

// isArtifactFile returns true for file extensions we should gate.
func isArtifactFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".whl", ".tar", ".gz", ".zip", ".jar", ".crate", ".tgz", ".egg":
		return true
	}
	// Handle .tar.gz (double extension).
	return strings.HasSuffix(strings.ToLower(path), ".tar.gz")
}

// startSeenPruner periodically prunes a quarantine.Engine's dedup cache so
// it doesn't grow unboundedly on a long-running daemon watching high-churn
// package caches. Stops when done is closed. The maxAge is short relative
// to the verdict cache's 24h — "seen" only needs to survive duplicate
// notifications for the same path shortly after processing, not long-term
// caching (the verdict cache handles that).
func startSeenPruner(done <-chan struct{}, qEngine *quarantine.Engine) {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				qEngine.PruneSeen(30 * time.Minute)
			}
		}
	}()
}

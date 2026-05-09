package watcher

import (
	"github.com/internal/gate-daemon/internal/config"
)

// DecisionFunc is called with the file path, ecosystem, and PID.
// Returns true to allow, false to deny.
// PID is -1 on platforms that don't provide process attribution.
type DecisionFunc func(path string, ecosystem string, pid int32) bool

// WatcherMode controls which interception mechanism to use.
type Mode string

const (
	ModeAuto       Mode = "auto"       // Try strongest available, fall back gracefully.
	ModeFanotify   Mode = "fanotify"   // Linux only. Kernel-enforced synchronous gate.
	ModeQuarantine Mode = "quarantine" // All platforms. Atomic rename, no privileges.
)

// Watcher intercepts file operations on watched directories.
// Platform-specific implementations provide the interception mechanism.
type Watcher interface {
	// Run blocks and processes filesystem events until an error or Close().
	Run() error

	// Close tears down the watcher and releases resources.
	Close() error

	// Mode returns the active interception mode for logging/diagnostics.
	Mode() string
}

// Config bundles the common parameters all platform watchers need.
type Config struct {
	Paths        []config.WatchPath
	DecisionFn   DecisionFunc
	WarnOnly     bool
	WatcherMode  Mode
}

//go:build linux

package watcher

import (
	"log/slog"

	"golang.org/x/sys/unix"
)

// New creates the strongest available watcher for this Linux machine.
//
// Mode selection:
//   - "fanotify":   force fanotify (fails if no CAP_SYS_ADMIN)
//   - "quarantine": force inotify + quarantine rename (no privileges)
//   - "auto":       try fanotify, fall back to inotify + quarantine
func New(wcfg Config) (Watcher, error) {
	mode := wcfg.WatcherMode
	if mode == "" {
		mode = ModeAuto
	}

	switch mode {
	case ModeFanotify:
		return newFanotifyWatcher(wcfg)

	case ModeQuarantine:
		return newInotifyQuarantineWatcher(wcfg)

	case ModeAuto:
		if canUseFanotify() {
			slog.Info("auto-detected fanotify capability, using kernel-enforced gating")
			return newFanotifyWatcher(wcfg)
		}
		slog.Info("fanotify unavailable (no CAP_SYS_ADMIN), falling back to inotify+quarantine")
		return newInotifyQuarantineWatcher(wcfg)

	default:
		slog.Warn("unknown watcher_mode, using auto", "mode", mode)
		wcfg.WatcherMode = ModeAuto
		return New(wcfg)
	}
}

// canUseFanotify probes whether this process can create a fanotify
// file descriptor with permission event support (FAN_CLASS_CONTENT).
// This requires CAP_SYS_ADMIN. The probe is non-destructive.
func canUseFanotify() bool {
	fd, err := unix.FanotifyInit(
		fanClassContent|fanUnlimitedQueue,
		unix.O_RDONLY,
	)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

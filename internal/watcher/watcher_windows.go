//go:build windows

package watcher

import (
	"fmt"
	"log/slog"
	"runtime"

	"github.com/internal/gate-daemon/internal/quarantine"
)

// WindowsWatcher uses ReadDirectoryChangesW + quarantine-rename.
//
// Implementation strategy (not yet built):
//
// 1. ReadDirectoryChangesW on each watch path with FILE_NOTIFY_CHANGE_FILE_NAME
//    and FILE_NOTIFY_CHANGE_LAST_WRITE. This is the Win32 equivalent of
//    inotify/FSEvents for directory monitoring.
//
// 2. On FILE_ACTION_ADDED or FILE_ACTION_MODIFIED, quarantine the artifact
//    (rename to .gated-quarantine/) and run scans.
//
// 3. Release or delete based on verdict.
//
// Alternative with stronger guarantees:
//
//   Windows minifilter driver — intercepts IRP_MJ_CREATE (file open) in
//   kernel mode and returns STATUS_ACCESS_DENIED. This is the true equivalent
//   of Linux fanotify permission events. Requires:
//   - C driver code (WDM or WDF framework)
//   - WHQL signing for production deployment
//   - Communication with userspace daemon via FilterConnectCommunicationPort
//
//   For internal tooling where you control the machines, test-signing mode
//   is sufficient. For broad deployment, WHQL is non-negotiable.
//
// Third alternative:
//
//   Windows Projected File System (ProjFS) — virtualizes a directory so
//   reads are served by your provider process. You project the package
//   cache and gate every file materialization. This is how VFS for Git
//   works. Userspace only, no kernel driver, no signing. Worth evaluating
//   if minifilter is too heavyweight.

type WindowsWatcher struct {
	qEngine *quarantine.Engine
}

func New(wcfg Config) (Watcher, error) {
	slog.Warn("Windows watcher is a stub — quarantine+ReadDirectoryChangesW not yet implemented",
		"platform", runtime.GOOS,
	)

	_ = quarantine.NewEngine(wcfg.DecisionFn, wcfg.WarnOnly)

	return nil, fmt.Errorf(
		"gated on Windows is not yet implemented; "+
			"see watcher_windows.go for implementation strategy "+
			"(ReadDirectoryChangesW + quarantine, minifilter, or ProjFS)",
	)
}

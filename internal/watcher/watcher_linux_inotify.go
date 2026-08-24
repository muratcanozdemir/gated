//go:build linux

package watcher

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/internal/gate-daemon/internal/config"
	"github.com/internal/gate-daemon/internal/quarantine"
)

// InotifyQuarantineWatcher uses inotify for file notifications and the
// quarantine engine for gating. No privileges required.
//
// Trade-off vs fanotify:
//   - fanotify: synchronous kernel gate, zero race window.
//   - inotify+quarantine: tiny race between file landing and rename.
//     In practice, package managers close-then-reopen, so the quarantine
//     rename completes before the package manager reads the file.
//
// inotify limitations this implementation works around:
//   - Not recursive: we walk the tree on startup and add watches per-dir.
//   - New subdirectories: we watch IN_CREATE|IN_ISDIR and add watches dynamically.
//   - Watch descriptor limit: we bump /proc/sys/fs/inotify/max_user_watches
//     if possible, or log a warning.
type InotifyQuarantineWatcher struct {
	fd       int
	qEngine  *quarantine.Engine
	paths    []config.WatchPath
	warnOnly bool

	// Map from watch descriptor to (directory path, ecosystem).
	mu      sync.RWMutex
	watches map[int]watchEntry

	done chan struct{}
}

type watchEntry struct {
	dir       string
	ecosystem string
}

func newInotifyQuarantineWatcher(wcfg Config) (Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}

	qEngine := quarantine.NewEngine(wcfg.DecisionFn, wcfg.WarnOnly)

	w := &InotifyQuarantineWatcher{
		fd:       fd,
		qEngine:  qEngine,
		paths:    wcfg.Paths,
		warnOnly: wcfg.WarnOnly,
		watches:  make(map[int]watchEntry),
		done:     make(chan struct{}),
	}

	// Walk each watch path and add inotify watches recursively.
	for _, wp := range wcfg.Paths {
		if _, err := os.Stat(wp.Path); os.IsNotExist(err) {
			slog.Warn("watch path does not exist, creating", "path", wp.Path)
			if mkErr := os.MkdirAll(wp.Path, 0o755); mkErr != nil {
				slog.Error("failed to create watch path", "path", wp.Path, "err", mkErr)
				continue
			}
		}

		count, err := w.addWatchRecursive(wp.Path, wp.Ecosystem)
		if err != nil {
			slog.Error("failed to add watches", "path", wp.Path, "err", err)
			continue
		}
		slog.Info("watching", "path", wp.Path, "ecosystem", wp.Ecosystem,
			"mode", "inotify+quarantine", "watches", count)
	}

	startSeenPruner(w.done, qEngine)

	return w, nil
}

func (w *InotifyQuarantineWatcher) Mode() string { return "inotify+quarantine" }

// addWatchRecursive walks a directory tree and adds inotify watches.
// Returns the number of watches added.
func (w *InotifyQuarantineWatcher) addWatchRecursive(root, ecosystem string) (int, error) {
	count := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip inaccessible dirs
		}
		if !d.IsDir() {
			return nil
		}

		// Skip quarantine directories.
		if quarantine.IsQuarantinePath(path) {
			return filepath.SkipDir
		}

		// Skip hidden directories (e.g. .git).
		base := filepath.Base(path)
		if base != "." && strings.HasPrefix(base, ".") && base != ".m2" && base != ".cache" && base != ".cargo" && base != ".npm" {
			return filepath.SkipDir
		}

		if err := w.addWatch(path, ecosystem); err != nil {
			slog.Debug("inotify_add_watch failed", "path", path, "err", err)
			return nil // non-fatal, continue walking
		}
		count++
		return nil
	})

	return count, err
}

func (w *InotifyQuarantineWatcher) addWatch(dir, ecosystem string) error {
	// IN_CLOSE_WRITE: file finished being written (download complete).
	// IN_MOVED_TO: file moved into the directory (atomic rename by package manager).
	// IN_CREATE|IN_ISDIR: new subdirectory, need to add a watch for it.
	mask := uint32(unix.IN_CLOSE_WRITE | unix.IN_MOVED_TO | unix.IN_CREATE)

	wd, err := unix.InotifyAddWatch(w.fd, dir, mask)
	if err != nil {
		return fmt.Errorf("inotify_add_watch(%s): %w", dir, err)
	}

	w.mu.Lock()
	w.watches[wd] = watchEntry{dir: dir, ecosystem: ecosystem}
	w.mu.Unlock()

	return nil
}

func (w *InotifyQuarantineWatcher) Run() error {
	// Use epoll to multiplex inotify fd with the done channel.
	// Since done is a Go channel and not an fd, we use a pipe as
	// the cancellation signal.
	cancelR, cancelW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer cancelR.Close()
	defer cancelW.Close()

	go func() {
		<-w.done
		cancelW.Write([]byte{0})
	}()

	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return fmt.Errorf("epoll_create1: %w", err)
	}
	defer unix.Close(epfd)

	// Register inotify fd.
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, w.fd, &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(w.fd),
	}); err != nil {
		return fmt.Errorf("epoll_ctl inotify: %w", err)
	}

	// Register cancel pipe.
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, int(cancelR.Fd()), &unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(cancelR.Fd()),
	}); err != nil {
		return fmt.Errorf("epoll_ctl cancel: %w", err)
	}

	events := make([]unix.EpollEvent, 2)
	buf := make([]byte, 4096*(unix.SizeofInotifyEvent+unix.NAME_MAX+1))

	slog.Info("inotify+quarantine event loop started")

	for {
		n, err := unix.EpollWait(epfd, events, -1)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("epoll_wait: %w", err)
		}

		for i := 0; i < n; i++ {
			if events[i].Fd == int32(cancelR.Fd()) {
				slog.Info("inotify watcher shutting down")
				return nil
			}

			if events[i].Fd == int32(w.fd) {
				w.readEvents(buf)
			}
		}
	}
}

func (w *InotifyQuarantineWatcher) readEvents(buf []byte) {
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return // no more events
			}
			slog.Error("inotify read", "err", err)
			return
		}
		if n <= 0 {
			return
		}

		offset := 0
		for offset+unix.SizeofInotifyEvent <= n {
			// Parse the inotify_event struct.
			wd := int(int32(
				uint32(buf[offset]) |
					uint32(buf[offset+1])<<8 |
					uint32(buf[offset+2])<<16 |
					uint32(buf[offset+3])<<24,
			))
			mask := uint32(buf[offset+4]) |
				uint32(buf[offset+5])<<8 |
				uint32(buf[offset+6])<<16 |
				uint32(buf[offset+7])<<24
			// cookie at offset+8 (unused)
			nameLen := uint32(buf[offset+12]) |
				uint32(buf[offset+13])<<8 |
				uint32(buf[offset+14])<<16 |
				uint32(buf[offset+15])<<24

			eventSize := unix.SizeofInotifyEvent + int(nameLen)
			if offset+eventSize > n {
				break
			}

			// Extract the filename (null-terminated within the nameLen buffer).
			var name string
			if nameLen > 0 {
				nameBytes := buf[offset+unix.SizeofInotifyEvent : offset+eventSize]
				// Trim null bytes.
				if idx := indexOf(nameBytes, 0); idx >= 0 {
					nameBytes = nameBytes[:idx]
				}
				name = string(nameBytes)
			}

			w.handleInotifyEvent(wd, mask, name)
			offset += eventSize
		}
	}
}

func (w *InotifyQuarantineWatcher) handleInotifyEvent(wd int, mask uint32, name string) {
	w.mu.RLock()
	entry, ok := w.watches[wd]
	w.mu.RUnlock()
	if !ok {
		return
	}

	if name == "" {
		return
	}

	fullPath := filepath.Join(entry.dir, name)

	// New subdirectory: add a watch for it dynamically.
	if mask&unix.IN_CREATE != 0 && mask&unix.IN_ISDIR != 0 {
		if quarantine.IsQuarantinePath(fullPath) {
			return
		}
		slog.Debug("new directory, adding watch", "path", fullPath, "ecosystem", entry.ecosystem)
		if err := w.addWatch(fullPath, entry.ecosystem); err != nil {
			slog.Debug("failed to add watch for new dir", "path", fullPath, "err", err)
		}
		return
	}

	// File events: IN_CLOSE_WRITE or IN_MOVED_TO on a file.
	if mask&(unix.IN_CLOSE_WRITE|unix.IN_MOVED_TO) == 0 {
		return
	}

	// Skip directories, metadata, quarantine artifacts, non-artifact files.
	if mask&unix.IN_ISDIR != 0 {
		return
	}
	if quarantine.IsQuarantinePath(fullPath) {
		return
	}
	if isMetadataFile(fullPath) {
		return
	}
	if !isArtifactFile(fullPath) {
		return
	}

	slog.Info("detected", "path", fullPath, "ecosystem", entry.ecosystem, "event", maskStr(mask))

	// Hand off to quarantine engine — rename, scan, release/deny.
	// Run async so the inotify event loop isn't blocked.
	go w.qEngine.HandleNewArtifact(fullPath, entry.ecosystem)
}

func (w *InotifyQuarantineWatcher) Close() error {
	select {
	case <-w.done:
		// Already closed.
	default:
		close(w.done)
	}

	// Remove all watches.
	w.mu.RLock()
	for wd := range w.watches {
		unix.InotifyRmWatch(w.fd, uint32(wd))
	}
	w.mu.RUnlock()

	return unix.Close(w.fd)
}

// --- helpers ---

func indexOf(b []byte, val byte) int {
	for i, v := range b {
		if v == val {
			return i
		}
	}
	return -1
}

func maskStr(mask uint32) string {
	var parts []string
	if mask&unix.IN_CLOSE_WRITE != 0 {
		parts = append(parts, "CLOSE_WRITE")
	}
	if mask&unix.IN_MOVED_TO != 0 {
		parts = append(parts, "MOVED_TO")
	}
	if mask&unix.IN_CREATE != 0 {
		parts = append(parts, "CREATE")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0x%x", mask)
	}
	return strings.Join(parts, "|")
}

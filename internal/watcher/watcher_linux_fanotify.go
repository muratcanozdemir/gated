//go:build linux

package watcher

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/internal/gate-daemon/internal/config"
)

const (
	fanOpenPerm     = 0x00010000
	fanCloseWrite   = 0x00000008
	fanEventOnChild = 0x08000000

	fanClassContent   = 0x00000004
	fanUnlimitedQueue = 0x00000010
	fanUnlimitedMarks = 0x00000020

	fanMarkAdd   = 0x00000001
	fanMarkMount = 0x00000010

	fanAllow = 0x01
	fanDeny  = 0x02

	metadataLen = 24
)

type fanotifyEventMetadata struct {
	EventLen    uint32
	Vers        uint8
	Reserved    uint8
	MetadataLen uint16
	Mask        uint64
	Fd          int32
	Pid         int32
}

type fanotifyResponse struct {
	Fd       int32
	Response uint32
}

// FanotifyWatcher intercepts file operations via fanotify permission events.
// The target process is frozen in kernel space until we respond with
// FAN_ALLOW or FAN_DENY. No race conditions, no bypass.
type FanotifyWatcher struct {
	fd         int
	paths      []config.WatchPath
	decisionFn DecisionFunc
	warnOnly   bool
	selfPid    int32
}

func newFanotifyWatcher(wcfg Config) (Watcher, error) {
	fd, err := unix.FanotifyInit(
		fanClassContent|fanUnlimitedQueue|fanUnlimitedMarks,
		unix.O_RDONLY|unix.O_LARGEFILE,
	)
	if err != nil {
		return nil, fmt.Errorf("fanotify_init: %w (are you root / CAP_SYS_ADMIN?)", err)
	}

	w := &FanotifyWatcher{
		fd:         fd,
		paths:      wcfg.Paths,
		decisionFn: wcfg.DecisionFn,
		warnOnly:   wcfg.WarnOnly,
		selfPid:    int32(os.Getpid()),
	}

	for _, wp := range wcfg.Paths {
		if _, err := os.Stat(wp.Path); os.IsNotExist(err) {
			slog.Warn("watch path does not exist, creating", "path", wp.Path)
			if mkErr := os.MkdirAll(wp.Path, 0o755); mkErr != nil {
				slog.Error("failed to create watch path", "path", wp.Path, "err", mkErr)
				continue
			}
		}

		mask := uint64(fanOpenPerm | fanCloseWrite | fanEventOnChild)
		if err := unix.FanotifyMark(fd, fanMarkAdd|fanMarkMount, mask, unix.AT_FDCWD, wp.Path); err != nil {
			slog.Error("fanotify_mark failed", "path", wp.Path, "err", err)
			continue
		}
		slog.Info("watching", "path", wp.Path, "ecosystem", wp.Ecosystem, "mode", "fanotify")
	}

	return w, nil
}

func (w *FanotifyWatcher) Mode() string { return "fanotify" }

func (w *FanotifyWatcher) Run() error {
	buf := make([]byte, 4096*metadataLen)

	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("fanotify read: %w", err)
		}

		offset := 0
		for offset < n {
			if offset+metadataLen > n {
				break
			}

			var event fanotifyEventMetadata
			event.EventLen = binary.LittleEndian.Uint32(buf[offset:])
			event.Vers = buf[offset+4]
			event.Reserved = buf[offset+5]
			event.MetadataLen = binary.LittleEndian.Uint16(buf[offset+6:])
			event.Mask = binary.LittleEndian.Uint64(buf[offset+8:])
			event.Fd = int32(binary.LittleEndian.Uint32(buf[offset+16:]))
			event.Pid = int32(binary.LittleEndian.Uint32(buf[offset+20:]))

			if event.EventLen < metadataLen {
				break
			}

			w.handleEvent(&event)
			offset += int(event.EventLen)
		}
	}
}

func (w *FanotifyWatcher) handleEvent(event *fanotifyEventMetadata) {
	if event.Fd < 0 {
		return
	}
	defer unix.Close(int(event.Fd))

	// Never gate our own operations — deadlock prevention.
	if event.Pid == w.selfPid {
		if event.Mask&fanOpenPerm != 0 {
			w.respond(event.Fd, fanAllow)
		}
		return
	}

	path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", event.Fd))
	if err != nil {
		if event.Mask&fanOpenPerm != 0 {
			w.respond(event.Fd, fanAllow)
		}
		return
	}

	ecosystem := w.resolveEcosystem(path)

	// FAN_CLOSE_WRITE: fire-and-forget pre-scan to warm the verdict cache.
	if event.Mask&fanCloseWrite != 0 && event.Mask&fanOpenPerm == 0 {
		if ecosystem != "" {
			go w.decisionFn(path, ecosystem, event.Pid)
		}
		return
	}

	// FAN_OPEN_PERM: must respond with allow/deny.
	if event.Mask&fanOpenPerm != 0 {
		if ecosystem == "" || isMetadataFile(path) {
			w.respond(event.Fd, fanAllow)
			return
		}

		comm := readComm(event.Pid)
		slog.Info("intercepted", "path", path, "ecosystem", ecosystem, "pid", event.Pid, "comm", comm)

		allowed := w.decisionFn(path, ecosystem, event.Pid)
		if allowed || w.warnOnly {
			if !allowed {
				slog.Warn("WARN_ONLY: would deny", "path", path, "ecosystem", ecosystem)
			}
			w.respond(event.Fd, fanAllow)
		} else {
			slog.Warn("DENIED", "path", path, "ecosystem", ecosystem, "pid", event.Pid, "comm", comm)
			w.respond(event.Fd, fanDeny)
		}
	}
}

func (w *FanotifyWatcher) respond(fd int32, response uint32) {
	resp := fanotifyResponse{Fd: fd, Response: response}
	respBytes := (*[unsafe.Sizeof(resp)]byte)(unsafe.Pointer(&resp))[:]
	if _, err := unix.Write(w.fd, respBytes); err != nil {
		slog.Error("fanotify response write failed", "err", err)
	}
}

func (w *FanotifyWatcher) resolveEcosystem(path string) string {
	for _, wp := range w.paths {
		if strings.HasPrefix(path, wp.Path) {
			return wp.Ecosystem
		}
	}
	return ""
}

func (w *FanotifyWatcher) Close() error {
	return unix.Close(w.fd)
}

// --- shared helpers (used by both backends) ---

func readComm(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

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

func isArtifactFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".whl", ".tar", ".gz", ".zip", ".jar", ".crate", ".tgz", ".egg":
		return true
	}
	if strings.HasSuffix(strings.ToLower(path), ".tar.gz") {
		return true
	}
	return false
}

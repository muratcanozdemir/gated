//go:build linux

package watcher

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
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
	closed     atomic.Bool
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

	ecosystem := resolveEcosystem(w.paths, path)

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

		// readComm does a synchronous /proc/<pid>/comm read purely for
		// log attribution — only pay for it when Info logging is
		// actually enabled, since this runs before the kernel unfreezes
		// the calling process.
		if slog.Default().Enabled(context.Background(), slog.LevelInfo) {
			slog.Info("intercepted", "path", path, "ecosystem", ecosystem, "pid", event.Pid, "comm", readComm(event.Pid))
		}

		allowed := w.decisionFn(path, ecosystem, event.Pid)
		if allowed || w.warnOnly {
			if !allowed {
				slog.Warn("WARN_ONLY: would deny", "path", path, "ecosystem", ecosystem)
			}
			w.respond(event.Fd, fanAllow)
		} else {
			slog.Warn("DENIED", "path", path, "ecosystem", ecosystem, "pid", event.Pid, "comm", readComm(event.Pid))
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

func (w *FanotifyWatcher) Close() error {
	if !w.closed.CompareAndSwap(false, true) {
		return nil // already closed
	}
	return unix.Close(w.fd)
}

// readComm reads /proc/<pid>/comm for logging. Callers on the fanotify hot
// path must only call this when Info-level logging is actually enabled —
// it's a synchronous procfs read on every intercepted event otherwise.
func readComm(pid int32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(data))
}

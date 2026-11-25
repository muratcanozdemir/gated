//go:build linux

package installer

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// procRoot is where process information lives; a variable for tests.
var procRoot = "/proc"

// Using returns the processes (other than gated) that have path, or a file
// below it, open, with their stderr opened for Warn. Only processes gated may
// inspect are considered: the same user's, or anyone's when gated runs as
// root. Processes whose stderr cannot be opened are left out.
func Using(path string) []*Process {
	path = filepath.Clean(path)
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return nil
	}
	self := os.Getpid()
	uid := os.Getuid()

	var found []*Process
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		dir := filepath.Join(procRoot, e.Name())
		if uid != 0 && ownerUID(dir) != uid {
			continue
		}
		if !hasOpenUnder(filepath.Join(dir, "fd"), path) {
			continue
		}
		out, err := os.OpenFile(filepath.Join(dir, "fd", "2"), os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			continue
		}
		found = append(found, &Process{PID: pid, Comm: comm(dir), out: out})
	}
	return found
}

// Alive reports whether the process is still running (and is still the
// same program: a reused PID runs something else, most likely).
func (p *Process) Alive() bool {
	return p != nil && comm(filepath.Join(procRoot, strconv.Itoa(p.PID))) == p.Comm
}

func ownerUID(procDir string) int {
	fi, err := os.Stat(procDir)
	if err != nil {
		return -1
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Uid)
}

// hasOpenUnder reports whether any of the process's file descriptors points
// at path or below it.
func hasOpenUnder(fdDir, path string) bool {
	fds, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
		if err != nil {
			continue
		}
		if target == path || strings.HasPrefix(target, path+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func comm(procDir string) string {
	b, err := os.ReadFile(filepath.Join(procDir, "comm"))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

//go:build linux

package quarantine

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A package manager whose stderr is a pipe (`uv ... | tee`, `$(go ...)`, an
// IDE running go): gated holds the pipe's write end to warn it, and the
// reader gets no end-of-file until gated lets go. 1.0.0 held it until the
// next activity in the cache plus two minutes, so `uv pip install ... | cut`
// hung. It must be released once the process has exited and no verdict in
// its cache is pending.
func TestReapReleasesExitedInstallersPipe(t *testing.T) {
	cache := t.TempDir()
	lock := filepath.Join(cache, ".lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pr.Close()

	cmd := exec.CommandContext(t.Context(), "sh", "-c", `exec 3<"$1"; echo ready; read _`, "sh", lock)
	cmd.Stderr = pw
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = pw.Close() // the child (and soon gated) hold the only write ends
	if _, err := stdout.Read(make([]byte, 6)); err != nil {
		t.Fatal(err)
	}

	e := NewEngine(nil, false)
	e.NoteActivity(cache)
	procs, release := e.installersOf(cache) // a verdict it is to be told about is pending
	if len(procs) != 1 {
		t.Fatal("the process holding the cache lock was not found")
	}

	_ = stdin.Close()
	_ = cmd.Wait() // the package manager is done

	later := time.Now().Add(installerRecent + time.Second)
	e.reapInstallers(later)
	if eof(t, pr, 200*time.Millisecond) {
		t.Fatal("stream released while a verdict was pending: its warning would be lost")
	}

	release()
	e.reapInstallers(later)
	if !eof(t, pr, 2*time.Second) {
		t.Fatal("pipe still open after the process exited and nothing was pending: its reader hangs")
	}
}

// eof reports whether the pipe reaches end-of-file within d.
func eof(t *testing.T, r *os.File, d time.Duration) bool {
	t.Helper()
	if err := r.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatal(err)
	}
	for {
		_, err := r.Read(make([]byte, 256))
		switch {
		case errors.Is(err, io.EOF):
			return true
		case errors.Is(err, os.ErrDeadlineExceeded):
			return false
		case err != nil:
			t.Fatal(err)
		}
	}
}

// yarn classic creates a cache entry before it opens anything there, and a
// cached deny comes milliseconds after the entry is done: a scan that found
// nobody must not keep the next one from finding the installer.
func TestNoteActivityRescansSoonAfterFindingNobody(t *testing.T) {
	cache := t.TempDir()
	e := NewEngine(nil, false)
	e.NoteActivity(cache) // the entry appears; nothing is open yet

	file := filepath.Join(cache, "entry")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "-c", `exec 3<"$1"; echo ready; read _`, "sh", file)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	if _, err := stdout.Read(make([]byte, 6)); err != nil {
		t.Fatal(err)
	}

	time.Sleep(20 * time.Millisecond) // well within activityRescan
	e.NoteActivity(cache)
	procs, release := e.installersOf(cache)
	defer release()
	if len(procs) != 1 {
		t.Fatalf("found %d installers: the scan that found nobody hid the one that came after", len(procs))
	}
}

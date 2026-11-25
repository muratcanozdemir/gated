//go:build linux

package installer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A process with a file open under the path is found, and a warning lands
// in its stderr, also after it has exited.
func TestUsingFindsProcessAndWarnsIntoItsStderr(t *testing.T) {
	cache := t.TempDir()
	lock := filepath.Join(cache, "sub", "x.lock")
	if err := os.MkdirAll(filepath.Dir(lock), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	stderr := filepath.Join(t.TempDir(), "stderr.log")
	errf, err := os.Create(stderr)
	if err != nil {
		t.Fatal(err)
	}
	defer errf.Close()

	// Holds the lock open, like a package manager working in its cache.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", `exec 3<"$1"; echo ready; read _`, "sh", lock)
	cmd.Stderr = errf
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := stdout.Read(buf); err != nil {
		t.Fatal(err)
	}

	procs := Using(cache)
	defer CloseAll(procs)
	var p *Process
	for _, q := range procs {
		if q.PID == cmd.Process.Pid {
			p = q
		}
	}
	if p == nil {
		t.Fatalf("process %d holding %s not found in %v", cmd.Process.Pid, lock, procs)
	}
	if len(Using(t.TempDir())) != 0 {
		t.Error("found a process for a directory nobody uses")
	}

	_ = stdin.Close() // let it exit first: the warning still gets through
	_ = cmd.Wait()
	if err := p.Warn("x@1.0 DENIED", "  - critical vulnerability"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, _ := os.ReadFile(stderr)
		if strings.Contains(string(b), "gated: x@1.0 DENIED\ngated:   - critical vulnerability\n") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("stderr = %q", b)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestNilProcessIsSafe(t *testing.T) {
	var p *Process
	if err := p.Warn("x"); err != nil {
		t.Fatal(err)
	}
	p.Close()
}

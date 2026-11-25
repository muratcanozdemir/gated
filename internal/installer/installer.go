// Package installer finds the package manager that is using an artifact, so
// that gated can tell it when a verdict comes too late to stop it.
//
// In quarantine mode gated races the package manager: it notices a download
// only after it lands. Most of the time it wins (it holds the file before the
// package manager reads it). When it loses, because the package manager had
// the file open already or unpacked it straight into its cache, a deny cannot
// undo what the package manager did with it. gated then writes a warning into
// the package manager's own output (its stderr: the terminal, CI log or file
// the person running it is reading), since gated's log is not where they look.
package installer

import (
	"fmt"
	"os"
	"strings"
)

// Process is a package manager process, with its stderr open for writing.
type Process struct {
	PID  int
	Comm string
	out  *os.File
}

// Warn writes a warning into the process's stderr. The stream was opened
// when the process was found, so it works after the process has exited, as
// long as its output (a terminal, a pipe being read, a log file) remains.
func (p *Process) Warn(lines ...string) error {
	if p == nil || p.out == nil {
		return nil
	}
	var b strings.Builder
	b.WriteString("\n")
	for _, l := range lines {
		fmt.Fprintf(&b, "gated: %s\n", strings.TrimRight(l, "\n"))
	}
	_, err := p.out.WriteString(b.String())
	return err
}

// Close releases the stream.
func (p *Process) Close() {
	if p != nil && p.out != nil {
		_ = p.out.Close()
	}
}

// CloseAll closes every process's stream.
func CloseAll(ps []*Process) {
	for _, p := range ps {
		p.Close()
	}
}

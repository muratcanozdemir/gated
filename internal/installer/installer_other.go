//go:build !linux

package installer

// Using finds package manager processes on Linux only (through /proc).
// Elsewhere it finds none, and a lost race is reported in gated's log alone.
func Using(string) []*Process { return nil }

// Alive is unknown off Linux; no process is ever found there anyway.
func (p *Process) Alive() bool { return false }

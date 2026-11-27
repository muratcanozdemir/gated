package quarantine

import (
	"testing"
	"time"

	"github.com/muratcanozdemir/gated/internal/installer"
)

// A package manager that has exited is blamed for a package only if it was
// working in the cache moments before: the ride showed a later uv run's
// denial reported to an earlier run's output otherwise.
func TestInstallersOfSkipsEarlierRuns(t *testing.T) {
	e := NewEngine(nil, false)
	now := time.Now()
	e.installers.caches = map[string]*cacheActivity{"/cache": {procs: map[int]*seenProcess{
		// PIDs that run nothing: both have exited.
		1 << 30:   {Process: &installer.Process{PID: 1 << 30, Comm: "uv"}, seen: now.Add(-100 * time.Millisecond)},
		1<<30 + 1: {Process: &installer.Process{PID: 1<<30 + 1, Comm: "uv"}, seen: now.Add(-30 * time.Second)},
		1<<30 + 2: {Process: &installer.Process{PID: 1<<30 + 2, Comm: "uv"}, seen: now.Add(-time.Hour)},
	}}}
	got, release := e.installersOf("/cache")
	defer release()
	if len(got) != 1 || got[0].PID != 1<<30 {
		t.Fatalf("installersOf = %v, want only the one seen just now", got)
	}
	if _, ok := e.installers.caches["/cache"].procs[1<<30+2]; ok {
		t.Error("a process unseen for longer than installerTTL was not expired")
	}
	if got, _ := e.installersOf("/elsewhere"); got != nil {
		t.Errorf("unknown cache: %v", got)
	}
}

// A verdict pending for one process keeps only that process's stream open.
// In the ride, another uv busy in the same cache held a finished
// `uv pip install ... | cat` for 110 s, until all of its own scans were done.
func TestReapHoldsOnlyProcessesWithPendingVerdicts(t *testing.T) {
	e := NewEngine(nil, false)
	old := time.Now().Add(-time.Minute)
	waiting := &seenProcess{Process: &installer.Process{PID: 1 << 30, Comm: "uv"}, seen: old, pending: 1}
	done := &seenProcess{Process: &installer.Process{PID: 1<<30 + 1, Comm: "uv"}, seen: old}
	e.installers.caches = map[string]*cacheActivity{"/cache": {procs: map[int]*seenProcess{
		waiting.PID: waiting, done.PID: done,
	}}}
	e.reapInstallers(time.Now())
	procs := e.installers.caches["/cache"].procs
	if _, ok := procs[done.PID]; ok {
		t.Error("an exited process with nothing pending was kept: its pipe stays open")
	}
	if _, ok := procs[waiting.PID]; !ok {
		t.Error("a process with a pending verdict was released: its warning would be lost")
	}
}

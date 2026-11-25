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
	got := e.installersOf("/cache")
	if len(got) != 1 || got[0].PID != 1<<30 {
		t.Fatalf("installersOf = %v, want only the one seen just now", got)
	}
	if _, ok := e.installers.caches["/cache"].procs[1<<30+2]; ok {
		t.Error("a process unseen for longer than installerTTL was not expired")
	}
	if got := e.installersOf("/elsewhere"); got != nil {
		t.Errorf("unknown cache: %v", got)
	}
}

package quarantine

import (
	"sync"
	"time"

	"github.com/muratcanozdemir/gated/internal/installer"
)

// A package manager can be done with a package within milliseconds of it
// landing: uv installs from an unpacked wheel and exits before a scan of
// /proc (about 10 ms) completes. So installers are found as soon as one
// starts working in a cache (NoteActivity, on any event under it), and kept
// for the verdicts that follow.
const (
	// activityRescan limits /proc scans for one cache: events come in bursts.
	activityRescan = 100 * time.Millisecond
	// installerTTL is how long a process found in a cache is kept after it
	// was last seen there: longer than any scan.
	installerTTL = 2 * time.Minute
	// installerRecent: a process that has exited is blamed for a package
	// only if it was working in the cache this shortly before; otherwise a
	// later run in the same cache would be reported to an earlier one.
	installerRecent = 2 * time.Second
)

type cacheActivity struct {
	scanned time.Time
	procs   map[int]*seenProcess
}

type seenProcess struct {
	*installer.Process
	seen time.Time
}

type installerRegistry struct {
	mu     sync.Mutex
	caches map[string]*cacheActivity
}

// NoteActivity records the processes that have files open in a package
// manager cache (root): something there just changed, so a package manager
// is likely at work. Cheap to call on every event: one scan per burst.
func (e *Engine) NoteActivity(root string) {
	r := &e.installers
	now := time.Now()
	r.mu.Lock()
	if r.caches == nil {
		r.caches = make(map[string]*cacheActivity)
	}
	a := r.caches[root]
	if a == nil {
		a = &cacheActivity{procs: make(map[int]*seenProcess)}
		r.caches[root] = a
	}
	if now.Sub(a.scanned) < activityRescan {
		r.mu.Unlock()
		return
	}
	a.scanned = now
	r.mu.Unlock()

	found := installer.Using(root)

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range found {
		if old, ok := a.procs[p.PID]; ok && old.Comm == p.Comm {
			old.seen = now
			p.Close()
			continue
		}
		if old, ok := a.procs[p.PID]; ok {
			old.Close() // the PID was reused
		}
		a.procs[p.PID] = &seenProcess{Process: p, seen: now}
	}
	r.expire(a, now)
}

// installersOf returns the processes that can be the one installing a
// package that just appeared in root: still running, or seen working there
// moments ago. They stay owned by the registry: callers must not close them.
func (e *Engine) installersOf(root string) []*installer.Process {
	r := &e.installers
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.caches[root]
	if a == nil {
		return nil
	}
	now := time.Now()
	r.expire(a, now)
	out := make([]*installer.Process, 0, len(a.procs))
	for _, p := range a.procs {
		if now.Sub(p.seen) <= installerRecent || p.Alive() {
			out = append(out, p.Process)
		}
	}
	return out
}

// expire closes and forgets processes not seen for installerTTL. r.mu held.
func (r *installerRegistry) expire(a *cacheActivity, now time.Time) {
	for pid, p := range a.procs {
		if now.Sub(p.seen) > installerTTL {
			p.Close()
			delete(a.procs, pid)
		}
	}
}

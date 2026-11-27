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
//
// Holding a process's stderr has a cost: when it is a pipe (`uv ... | tee`,
// `$(go ...)`, an IDE running go), whatever reads it gets no end-of-file
// while gated holds it, and waits. So a stream is held only while it may
// still be needed: the process is running, or it was seen moments ago
// (installerRecent: a package of its may be about to be judged), or a verdict
// it is to be warned about is pending. Only those verdicts: another process
// busy in the same cache does not keep it waiting. ReapInstallers closes the
// rest.
const (
	// activityRescan limits /proc scans for one cache: events come in bursts.
	activityRescan = 100 * time.Millisecond
	// installerTTL is how long a process found in a cache is kept after it
	// was last seen there: longer than any scan.
	installerTTL = 2 * time.Minute
	// installerRecent: a process that has exited is blamed for a package
	// only if it was working in the cache this shortly before; otherwise a
	// later run in the same cache would be reported to an earlier one.
	installerRecent = 500 * time.Millisecond
)

type cacheActivity struct {
	scanMu  sync.Mutex // one scan at a time; later callers wait for its result
	scanned time.Time
	procs   map[int]*seenProcess
}

type seenProcess struct {
	*installer.Process
	seen    time.Time
	pending int // verdicts in flight that this process is to be told about
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
	r.mu.Lock()
	if r.caches == nil {
		r.caches = make(map[string]*cacheActivity)
	}
	a := r.caches[root]
	if a == nil {
		a = &cacheActivity{procs: make(map[int]*seenProcess)}
		r.caches[root] = a
	}
	r.mu.Unlock()

	// A caller that finds a scan running waits for it rather than reading
	// the registry before that scan has recorded what it found.
	a.scanMu.Lock()
	defer a.scanMu.Unlock()
	r.mu.Lock()
	if time.Since(a.scanned) < activityRescan {
		r.mu.Unlock()
		return
	}
	r.mu.Unlock()

	found := installer.Using(root)
	now := time.Now()

	r.mu.Lock()
	defer r.mu.Unlock()
	a.scanned = now
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
// release ends their hold for this verdict; until it is called, they stay
// open (see ReapInstallers).
func (e *Engine) installersOf(root string) (procs []*installer.Process, release func()) {
	r := &e.installers
	r.mu.Lock()
	defer r.mu.Unlock()
	a := r.caches[root]
	if a == nil {
		return nil, func() {}
	}
	now := time.Now()
	r.expire(a, now)
	var held []*seenProcess
	for _, p := range a.procs {
		if now.Sub(p.seen) <= installerRecent || p.Alive() {
			p.pending++
			held = append(held, p)
			procs = append(procs, p.Process)
		}
	}
	return procs, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, p := range held {
			p.pending--
		}
	}
}

// ReapInstallers closes the streams of processes that have exited and can
// no longer be blamed for a package: not seen for installerRecent, and no
// verdict they are to be told about pending. Call it often (the watchers do, four times a
// second): until then, a pipe the process wrote to stays open.
func (e *Engine) ReapInstallers() { e.reapInstallers(time.Now()) }

func (e *Engine) reapInstallers(now time.Time) {
	r := &e.installers
	r.mu.Lock()
	defer r.mu.Unlock()
	for root, a := range r.caches {
		r.expire(a, now)
		for pid, p := range a.procs {
			if p.pending == 0 && now.Sub(p.seen) > installerRecent && !p.Alive() {
				p.Close()
				delete(a.procs, pid)
			}
		}
		if len(a.procs) == 0 && now.Sub(a.scanned) > installerTTL {
			delete(r.caches, root)
		}
	}
}

// expire closes and forgets processes not seen for installerTTL. r.mu held.
func (r *installerRegistry) expire(a *cacheActivity, now time.Time) {
	for pid, p := range a.procs {
		if p.pending == 0 && now.Sub(p.seen) > installerTTL {
			p.Close()
			delete(a.procs, pid)
		}
	}
}

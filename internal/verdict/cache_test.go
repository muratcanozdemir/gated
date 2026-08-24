package verdict

import (
	"testing"
	"time"
)

func TestStoreAndLookup(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	path := "/cache/uv/requests-2.31.0.whl"
	if entry := c.Lookup(path); entry != nil {
		t.Fatalf("expected no cached entry, got %+v", entry)
	}

	c.Store(path, &Entry{Name: "requests", Version: "2.31.0", Allowed: true, ScannedAt: time.Now().UTC().Format(time.RFC3339)})
	time.Sleep(20 * time.Millisecond)

	entry := c.Lookup(path)
	if entry == nil {
		t.Fatal("expected cached entry after Store")
	}
	if !entry.Allowed {
		t.Fatal("expected Allowed=true")
	}
}

func TestMarkPendingDedup(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	path := "/cache/uv/pkg.whl"
	if ok := c.MarkPending(path); !ok {
		t.Fatal("expected first MarkPending to return true")
	}
	if ok := c.MarkPending(path); ok {
		t.Fatal("expected second MarkPending to return false (already pending)")
	}
}

func TestLookupBlocksUntilStore(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	path := "/cache/uv/blocked.whl"
	if ok := c.MarkPending(path); !ok {
		t.Fatal("expected MarkPending to return true")
	}

	done := make(chan *Entry, 1)
	go func() {
		done <- c.Lookup(path) // should block until Store
	}()

	select {
	case <-done:
		t.Fatal("Lookup returned before Store — should have blocked on pending scan")
	case <-time.After(50 * time.Millisecond):
	}

	c.Store(path, &Entry{Name: "blocked", Allowed: false, ScannedAt: time.Now().UTC().Format(time.RFC3339)})
	time.Sleep(20 * time.Millisecond)

	select {
	case entry := <-done:
		if entry == nil || entry.Allowed {
			t.Fatalf("expected denied entry after Store, got %+v", entry)
		}
	case <-time.After(time.Second):
		t.Fatal("Lookup did not unblock after Store")
	}
}

func TestPruneOlderThan(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	old := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	fresh := time.Now().UTC().Format(time.RFC3339)

	c.Store("/cache/old.whl", &Entry{Name: "old", Allowed: true, ScannedAt: old})
	time.Sleep(20 * time.Millisecond)
	c.Store("/cache/fresh.whl", &Entry{Name: "fresh", Allowed: true, ScannedAt: fresh})
	time.Sleep(20 * time.Millisecond)

	pruned := c.PruneOlderThan(24 * time.Hour)
	if pruned != 1 {
		t.Fatalf("expected 1 pruned entry, got %d", pruned)
	}

	if c.Lookup("/cache/old.whl") != nil {
		t.Fatal("expected old entry to be pruned")
	}
	if c.Lookup("/cache/fresh.whl") == nil {
		t.Fatal("expected fresh entry to survive prune")
	}
}

func TestInvalidateAll(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	c.Store("/cache/a.whl", &Entry{Name: "a", Allowed: true, ScannedAt: time.Now().UTC().Format(time.RFC3339)})
	time.Sleep(20 * time.Millisecond)
	c.Store("/cache/b.whl", &Entry{Name: "b", Allowed: false, ScannedAt: time.Now().UTC().Format(time.RFC3339)})
	time.Sleep(20 * time.Millisecond)

	c.InvalidateAll()

	if c.Lookup("/cache/a.whl") != nil || c.Lookup("/cache/b.whl") != nil {
		t.Fatal("expected all entries removed after InvalidateAll")
	}
}

func TestStats(t *testing.T) {
	c, err := NewCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}

	c.Store("/cache/a.whl", &Entry{Name: "a", Allowed: true, ScannedAt: time.Now().UTC().Format(time.RFC3339)})
	time.Sleep(20 * time.Millisecond)
	c.Store("/cache/b.whl", &Entry{Name: "b", Allowed: false, ScannedAt: time.Now().UTC().Format(time.RFC3339)})
	time.Sleep(20 * time.Millisecond)

	total, allowed, denied := c.Stats()
	if total != 2 || allowed != 1 || denied != 1 {
		t.Fatalf("expected total=2 allowed=1 denied=1, got total=%d allowed=%d denied=%d", total, allowed, denied)
	}
}

func TestNewCacheLoadsFromDisk(t *testing.T) {
	dir := t.TempDir()

	c1, err := NewCache(dir)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	c1.Store("/cache/persisted.whl", &Entry{Name: "persisted", Allowed: true, ScannedAt: time.Now().UTC().Format(time.RFC3339)})

	// Store persists asynchronously — poll briefly for the file to land.
	deadline := time.Now().Add(time.Second)
	for {
		if c1.Lookup("/cache/persisted.whl") != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("entry never became visible")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // let the async saveToDisk goroutine finish

	c2, err := NewCache(dir)
	if err != nil {
		t.Fatalf("second NewCache: %v", err)
	}
	if entry := c2.Lookup("/cache/persisted.whl"); entry == nil {
		t.Fatal("expected entry to be loaded from disk by a fresh Cache")
	}
}

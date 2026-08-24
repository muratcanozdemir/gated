package verdict

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry stores a cached verdict for an artifact.
type Entry struct {
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Allowed   bool     `json:"allowed"`
	Reasons   []string `json:"reasons,omitempty"`
	ScannedAt string   `json:"scanned_at"`
	Hash      string   `json:"hash"`
}

// Cache provides fast verdict lookups backed by filesystem persistence.
// In-memory map for hot path; files for durability across restarts.
type Cache struct {
	dir     string
	mu      sync.RWMutex
	entries map[string]*Entry        // keyed by file content hash
	pending map[string]chan struct{} // signals when a scan completes
}

func NewCache(dir string) (*Cache, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create verdict dir: %w", err)
	}

	c := &Cache{
		dir:     dir,
		entries: make(map[string]*Entry),
		pending: make(map[string]chan struct{}),
	}

	// Load existing verdicts from disk on startup.
	if err := c.loadFromDisk(); err != nil {
		slog.Warn("failed to load some verdicts from disk", "err", err)
	}

	return c, nil
}

// Lookup returns a cached verdict by file path.
// Returns nil if not cached. If a scan is in progress, blocks until complete.
func (c *Cache) Lookup(filePath string) *Entry {
	hash := hashPath(filePath)

	c.mu.RLock()
	entry, ok := c.entries[hash]
	ch, pending := c.pending[hash]
	c.mu.RUnlock()

	if ok {
		return entry
	}

	if pending {
		// Another goroutine is scanning this file. Wait for it.
		<-ch
		c.mu.RLock()
		entry = c.entries[hash]
		c.mu.RUnlock()
		return entry
	}

	return nil
}

// MarkPending signals that a scan is in progress for this path.
// Returns true if this caller should perform the scan, false if already pending.
func (c *Cache) MarkPending(filePath string) bool {
	hash := hashPath(filePath)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries[hash]; ok {
		return false // already cached
	}
	if _, ok := c.pending[hash]; ok {
		return false // already being scanned
	}

	c.pending[hash] = make(chan struct{})
	return true
}

// Store saves a verdict and notifies any waiting goroutines.
func (c *Cache) Store(filePath string, entry *Entry) {
	hash := hashPath(filePath)
	entry.Hash = hash

	c.mu.Lock()
	c.entries[hash] = entry
	ch, pending := c.pending[hash]
	delete(c.pending, hash)
	c.mu.Unlock()

	if pending {
		close(ch) // unblock waiters
	}

	// Persist to disk asynchronously.
	go c.saveToDisk(hash, entry)
}

// Invalidate removes a verdict. Used when policy changes.
func (c *Cache) Invalidate(filePath string) {
	hash := hashPath(filePath)

	c.mu.Lock()
	delete(c.entries, hash)
	c.mu.Unlock()

	os.Remove(filepath.Join(c.dir, hash+".json"))
}

// InvalidateAll clears the entire cache. Use on policy reload.
func (c *Cache) InvalidateAll() {
	c.mu.Lock()
	c.entries = make(map[string]*Entry)
	c.mu.Unlock()

	entries, _ := os.ReadDir(c.dir)
	for _, e := range entries {
		os.Remove(filepath.Join(c.dir, e.Name()))
	}
	slog.Info("verdict cache invalidated")
}

// Stats returns cache metrics.
func (c *Cache) Stats() (total, allowed, denied int) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for _, e := range c.entries {
		total++
		if e.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	return
}

func (c *Cache) saveToDisk(hash string, entry *Entry) {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		slog.Error("marshal verdict", "err", err)
		return
	}
	path := filepath.Join(c.dir, hash+".json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		slog.Error("write verdict", "path", path, "err", err)
	}
}

func (c *Cache) loadFromDisk() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}

	loaded := 0
	for _, e := range entries {
		if !e.Type().IsRegular() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(c.dir, e.Name()))
		if err != nil {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(data, &entry); err != nil {
			continue
		}
		hash := e.Name()[:len(e.Name())-5] // strip .json
		c.entries[hash] = &entry
		loaded++
	}

	if loaded > 0 {
		slog.Info("loaded cached verdicts", "count", loaded)
	}
	return nil
}

func hashPath(path string) string {
	h := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars, enough for dedup
}

// PruneOlderThan removes verdicts older than the given duration.
func (c *Cache) PruneOlderThan(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	pruned := 0

	c.mu.Lock()
	defer c.mu.Unlock()

	for hash, entry := range c.entries {
		t, err := time.Parse(time.RFC3339, entry.ScannedAt)
		if err != nil || t.Before(cutoff) {
			delete(c.entries, hash)
			os.Remove(filepath.Join(c.dir, hash+".json"))
			pruned++
		}
	}
	return pruned
}

package quarantine

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestHandleNewArtifact_Allow(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "requests-2.31.0-py3-none-any.whl")
	if err := os.WriteFile(artifact, []byte("fake wheel"), 0o644); err != nil {
		t.Fatal(err)
	}

	alwaysAllow := func(path, ecosystem string, pid int32) bool {
		return true
	}

	engine := NewEngine(alwaysAllow, false)
	engine.HandleNewArtifact(artifact, "pypi")

	// File should be back at original location.
	if _, err := os.Stat(artifact); err != nil {
		t.Errorf("artifact should exist after allow: %v", err)
	}
}

func TestHandleNewArtifact_Deny(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "malicious-1.0.0.whl")
	if err := os.WriteFile(artifact, []byte("bad content"), 0o644); err != nil {
		t.Fatal(err)
	}

	alwaysDeny := func(path, ecosystem string, pid int32) bool {
		return false
	}

	engine := NewEngine(alwaysDeny, false)
	engine.HandleNewArtifact(artifact, "pypi")

	// Original file should be gone.
	if _, err := os.Stat(artifact); !os.IsNotExist(err) {
		t.Errorf("artifact should not exist after deny")
	}
}

func TestHandleNewArtifact_WarnOnly(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "sketchy-0.1.0.whl")
	if err := os.WriteFile(artifact, []byte("suspicious"), 0o644); err != nil {
		t.Fatal(err)
	}

	alwaysDeny := func(path, ecosystem string, pid int32) bool {
		return false
	}

	engine := NewEngine(alwaysDeny, true) // warn_only = true
	engine.HandleNewArtifact(artifact, "pypi")

	// File should still exist despite policy denial.
	if _, err := os.Stat(artifact); err != nil {
		t.Errorf("artifact should exist in warn-only mode: %v", err)
	}
}

func TestHandleNewArtifact_Deduplication(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "dup-1.0.0.whl")
	if err := os.WriteFile(artifact, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	var callCount atomic.Int32
	counter := func(path, ecosystem string, pid int32) bool {
		callCount.Add(1)
		time.Sleep(10 * time.Millisecond) // simulate scan
		return true
	}

	engine := NewEngine(counter, false)

	// First call processes normally.
	engine.HandleNewArtifact(artifact, "pypi")

	// Second call should be deduped (already in seen map).
	engine.HandleNewArtifact(artifact, "pypi")

	if callCount.Load() != 1 {
		t.Errorf("decision function called %d times, want 1 (dedup failed)", callCount.Load())
	}
}

func TestIsQuarantinePath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/home/user/.cache/uv/wheels/requests-2.31.0.whl", false},
		{"/home/user/.cache/uv/wheels/.gated-quarantine/requests-2.31.0.whl.gated-hold", true},
		{"/tmp/.gated-quarantine/denied/something.whl.gated-hold", true},
	}

	for _, tt := range tests {
		got := IsQuarantinePath(tt.path)
		if got != tt.want {
			t.Errorf("IsQuarantinePath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestPruneSeen(t *testing.T) {
	engine := NewEngine(nil, false)

	// Inject old entries.
	engine.mu.Lock()
	engine.seen["/old/path"] = time.Now().Add(-2 * time.Hour)
	engine.seen["/new/path"] = time.Now()
	engine.mu.Unlock()

	pruned := engine.PruneSeen(1 * time.Hour)
	if pruned != 1 {
		t.Errorf("pruned %d, want 1", pruned)
	}
}

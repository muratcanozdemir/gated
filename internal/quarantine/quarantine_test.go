package quarantine

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/muratcanozdemir/gated/internal/resolver"
)

func TestHandleNewArtifact_Allow(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "requests-2.31.0-py3-none-any.whl")
	if err := os.WriteFile(artifact, []byte("fake wheel"), 0o644); err != nil {
		t.Fatal(err)
	}

	alwaysAllow := func(_, _ string, _ int32) bool {
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

	alwaysDeny := func(_, _ string, _ int32) bool {
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

	alwaysDeny := func(_, _ string, _ int32) bool {
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
	counter := func(_, _ string, _ int32) bool {
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
		{"/home/user/.cache/uv/wheels/.gated-quarantine/requests-2.31.0.whl", true},
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

func TestOriginalPath(t *testing.T) {
	for _, original := range []string{
		"/home/u/.m2/repository/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
		"/home/u/.cache/pip/requests-2.32.3-py3-none-any.whl",
		"relative/dir/PyYAML-5.3.1.tar.gz",
	} {
		got, ok := OriginalPath(quarantinePath(original))
		if !ok || got != original {
			t.Errorf("OriginalPath(quarantinePath(%q)) = %q, %v", original, got, ok)
		}
	}
	for _, notHold := range []string{
		"/home/u/.m2/repository/x/1.0/x-1.0.jar",                     // not in a quarantine dir
		"/tmp/" + quarantineDir + "/denied/x-1.0.jar" + deniedSuffix, // denied, kept for audit
		"/tmp/" + quarantineDir,                                      // the quarantine dir itself
	} {
		if got, ok := OriginalPath(notHold); ok {
			t.Errorf("OriginalPath(%q) = %q, want not a hold path", notHold, got)
		}
	}
}

// Scanners recognize artifacts by file name: the hold file must keep it.
func TestQuarantinePathKeepsName(t *testing.T) {
	for _, original := range []string{"/c/x-1.0.jar", "/c/requests-2.32.3-py3-none-any.whl", "/c/PyYAML-5.3.1.tar.gz"} {
		hold := quarantinePath(original)
		if filepath.Base(hold) != filepath.Base(original) {
			t.Errorf("quarantinePath(%q) = %q: name changed", original, hold)
		}
		if !IsQuarantinePath(hold) {
			t.Errorf("quarantinePath(%q) = %q: not recognized as a quarantine path", original, hold)
		}
	}
}

// The decision function receives the hold path and resolves identity from
// OriginalPath(hold): resolving the hold path itself breaks layout-based
// resolvers (Maven reads group/artifact/version from the directories), which
// made quarantine mode allow artifacts as "unresolved" without scanning them.
func TestHoldPathResolvesThroughOriginalPath(t *testing.T) {
	cases := map[string]struct{ path, eco, name, version string }{
		"maven": {"/r/.m2/repository/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar", "maven", "org.apache.commons:commons-lang3", "3.14.0"},
		"wheel": {"/r/.cache/pip/requests-2.32.3-py3-none-any.whl", "pypi", "requests", "2.32.3"},
		"sdist": {"/r/.cache/pip/PyYAML-5.3.1.tar.gz", "pypi", "pyyaml", "5.3.1"},
	}
	for name, c := range cases {
		hold := quarantinePath(c.path)
		orig, ok := OriginalPath(hold)
		if !ok {
			t.Fatalf("%s: OriginalPath(%q) failed", name, hold)
		}
		pkg := resolver.Resolve(orig, c.eco)
		if pkg == nil || pkg.Name != c.name || pkg.Version != c.version {
			t.Errorf("%s: Resolve(OriginalPath(hold)) = %+v, want %s %s", name, pkg, c.name, c.version)
		}
	}
}

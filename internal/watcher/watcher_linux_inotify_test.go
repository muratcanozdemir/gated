//go:build linux

package watcher

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/muratcanozdemir/gated/internal/config"
)

// startInotify runs an inotify+quarantine watcher on root that allows
// everything and reports the file name of each artifact it gates (the
// decision function sees the quarantine hold path; the name is the original).
func startInotify(t *testing.T, root, ecosystem string) <-chan string {
	t.Helper()
	gated := make(chan string, 16)
	var once sync.Map
	w, err := newInotifyQuarantineWatcher(Config{
		Paths: []config.WatchPath{{Path: root, Ecosystem: ecosystem}},
		DecisionFn: func(path, _ string, _ int32) bool {
			name := filepath.Base(path) // hold files keep the artifact's name
			if _, dup := once.LoadOrStore(name, true); !dup {
				gated <- name
			}
			return true
		},
	})
	if err != nil {
		t.Fatalf("newInotifyQuarantineWatcher: %v", err)
	}
	errc := make(chan error, 1)
	go func() { errc <- w.Run() }()
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
		select {
		case err := <-errc:
			if err != nil {
				t.Errorf("Run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("watcher did not stop")
		}
	})
	return gated
}

func expectGated(t *testing.T, gated <-chan string, name string) {
	t.Helper()
	select {
	case got := <-gated:
		if got != name {
			t.Fatalf("gated %s, want %s", got, name)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s was never gated", name)
	}
}

func writeArtifact(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("PK\x03\x04 not really a jar"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInotify_FileInWatchedDir(t *testing.T) {
	root := t.TempDir()
	gated := startInotify(t, root, "maven")
	writeArtifact(t, filepath.Join(root, "a-1.0.jar"))
	expectGated(t, gated, "a-1.0.jar")
}

// Package managers create nested directories in one go (mkdir -p) and write
// into the deepest one before the watcher has seen the first IN_CREATE:
// every level, and files already in it, must still be gated.
func TestInotify_NestedDirsCreatedAtOnce(t *testing.T) {
	root := t.TempDir()
	gated := startInotify(t, root, "maven")
	dir := filepath.Join(root, "org", "apache", "commons", "commons-lang3", "3.14.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(dir, "commons-lang3-3.14.0.jar"))
	expectGated(t, gated, "commons-lang3-3.14.0.jar")

	// The new subtree is watched from now on.
	writeArtifact(t, filepath.Join(dir, "commons-lang3-3.14.0-sources.jar"))
	expectGated(t, gated, "commons-lang3-3.14.0-sources.jar")
}

// A directory prepared elsewhere and renamed into place (IN_MOVED_TO on a
// directory), with the artifact already inside.
func TestInotify_DirMovedIn(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	gated := startInotify(t, root, "cargo")
	src := filepath.Join(staging, "serde-1.0.0")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(src, "serde-1.0.0.crate"))
	if err := os.Rename(src, filepath.Join(root, "serde-1.0.0")); err != nil {
		t.Fatal(err)
	}
	expectGated(t, gated, "serde-1.0.0.crate")
}

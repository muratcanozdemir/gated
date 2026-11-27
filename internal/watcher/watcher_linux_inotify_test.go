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

// uv unpacks a download into its cache and renames the directory into
// archive-v0: the directory is the artifact, gated in place (not held), and
// what is inside it is not gated file by file.
func TestInotify_UVArchiveGatedInPlace(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "archive-v0")
	if err := os.MkdirAll(archive, 0o755); err != nil {
		t.Fatal(err)
	}
	gated := startInotify(t, root, "pypi")

	tmp := filepath.Join(root, ".tmpAbC")
	info := filepath.Join(tmp, "urllib3-1.26.4.dist-info")
	if err := os.MkdirAll(filepath.Join(tmp, "urllib3", "contrib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(info, "METADATA"), []byte("Metadata-Version: 2.1\nName: urllib3\nVersion: 1.26.4\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(tmp, "urllib3", "contrib", "fixture.gz")) // part of the package
	if err := os.Rename(tmp, filepath.Join(archive, "Xy12")); err != nil {
		t.Fatal(err)
	}
	expectGated(t, gated, "Xy12") // the directory, where it lies
	select {
	case got := <-gated:
		t.Fatalf("also gated %s: content of an unpacked package is not an artifact", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// go writes the module zip and unpacks it at once: the zip is gated where it
// lies, not held, or go fails to unpack it even when it is allowed.
func TestInotify_GoZipGatedInPlace(t *testing.T) {
	root := t.TempDir()
	gated := startInotify(t, root, "go")
	v := filepath.Join(root, "cache", "download", "github.com", "google", "uuid", "@v")
	if err := os.MkdirAll(v, 0o755); err != nil {
		t.Fatal(err)
	}
	zip := filepath.Join(v, "v1.6.0.zip")
	writeArtifact(t, zip)
	expectGated(t, gated, "v1.6.0.zip")
	if _, err := os.Stat(zip); err != nil {
		t.Fatalf("an allowed module zip must stay where go wrote it: %v", err)
	}
}

// A package manager's hidden staging directory (uv's .tmpXXXX) is never
// gated, even when it already holds a finished-looking artifact by the time
// the watcher sees it appear: what lands in the cache arrives by a rename.
func TestInotify_HiddenStagingDirNotGated(t *testing.T) {
	root := t.TempDir()
	staging := t.TempDir()
	gated := startInotify(t, root, "cargo")
	src := filepath.Join(staging, ".tmpAbC")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(src, "serde-1.0.0.crate"))
	if err := os.Rename(src, filepath.Join(root, ".tmpAbC")); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(root, "after.crate")) // the watcher is live
	expectGated(t, gated, "after.crate")
}

// yarn classic creates its cache entry where it stays and fills it file by
// file: the entry is gated in place only once yarn writes .yarn-metadata.json,
// its last file, and what yarn writes before is not gated at all.
func TestInotify_YarnClassicGatedWhenComplete(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "v6")
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	gated := startInotify(t, root, "npm")

	entry := filepath.Join(cache, "npm-@babel-x-1.0.0-533f36457a25814cf1df6488523ad547d784a99f-integrity")
	pkg := filepath.Join(entry, "node_modules", "@babel", "x")
	if err := os.MkdirAll(filepath.Join(pkg, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(pkg, ".yarn-tarball.tgz"))
	writeArtifact(t, filepath.Join(pkg, "lib", "fixture.zip"))
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name": "@babel/x", "version": "1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-gated:
		t.Fatalf("gated %s before yarn finished the entry", got)
	case <-time.After(300 * time.Millisecond):
	}
	if err := os.WriteFile(filepath.Join(pkg, ".yarn-metadata.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	expectGated(t, gated, filepath.Base(entry))
	select {
	case got := <-gated:
		t.Fatalf("also gated %s: content of a yarn entry is not an artifact", got)
	case <-time.After(300 * time.Millisecond):
	}
}

// bun unpacks a package elsewhere and renames it into its cache, under a
// scope directory it creates just before: gated in place, once.
func TestInotify_BunScopedGatedInPlace(t *testing.T) {
	root := t.TempDir()
	gated := startInotify(t, root, "npm")
	tmp := filepath.Join(root, ".tmp", ".e7151c597de0f0b4-2.x")
	if err := os.MkdirAll(filepath.Join(tmp, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "package.json"), []byte(`{"name": "@babel/x", "version": "1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeArtifact(t, filepath.Join(tmp, "lib", "fixture.tgz"))
	if err := os.Mkdir(filepath.Join(root, "@babel"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, filepath.Join(root, "@babel", "x@1.0.0@@@1")); err != nil {
		t.Fatal(err)
	}
	expectGated(t, gated, "x@1.0.0@@@1")
	select {
	case got := <-gated:
		t.Fatalf("also gated %s", got)
	case <-time.After(300 * time.Millisecond):
	}
}

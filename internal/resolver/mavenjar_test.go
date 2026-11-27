package resolver

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func writeJar(t *testing.T, path string, entries map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

const log4jProps = "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"

// A repository at /build/m2 (no "repository/" in the path): the layout alone
// does not give the group, and the jar was allowed unscanned.
func TestResolveMavenJar(t *testing.T) {
	root := filepath.Join(t.TempDir(), "build", "m2")
	id := filepath.Join(root, "org", "apache", "logging", "log4j", "log4j-core", "2.14.1", "log4j-core-2.14.1.jar")
	if Resolve(id, "maven") != nil {
		t.Fatal("precondition: the path alone resolves; this test needs a layout it cannot")
	}
	hold := filepath.Join(t.TempDir(), "log4j-core-2.14.1.jar") // the bytes, held elsewhere
	writeJar(t, hold, map[string]string{
		log4jProps: "#Created by Apache Maven\nversion=2.14.1\ngroupId=org.apache.logging.log4j\nartifactId=log4j-core\n",
		"org/apache/logging/log4j/core/Logger.class": "x",
	})
	pkg := ResolveMavenJar(id, hold)
	if pkg == nil || pkg.Name != "org.apache.logging.log4j:log4j-core" || pkg.Version != "2.14.1" {
		t.Fatalf("ResolveMavenJar = %+v", pkg)
	}
}

func TestResolveMavenJarRefusesDisagreement(t *testing.T) {
	root := filepath.Join(t.TempDir(), "m2")
	for name, c := range map[string]struct{ path, props string }{
		"other version in the jar": {"x/log4j-core/2.17.1/log4j-core-2.17.1.jar",
			"version=2.14.1\ngroupId=org.apache.logging.log4j\nartifactId=log4j-core\n"},
		"other artifact in the jar": {"x/commons-text/1.12.0/commons-text-1.12.0.jar",
			"version=1.12.0\ngroupId=org.apache.commons\nartifactId=log4j-core\n"},
		"file name not artifact-version": {"x/log4j-core/2.14.1/evil.jar",
			"version=2.14.1\ngroupId=org.apache.logging.log4j\nartifactId=log4j-core\n"},
		"no group": {"x/log4j-core/2.14.1/log4j-core-2.14.1.jar",
			"version=2.14.1\nartifactId=log4j-core\n"},
	} {
		id := filepath.Join(root, filepath.FromSlash(c.path))
		jar := filepath.Join(t.TempDir(), filepath.Base(id))
		writeJar(t, jar, map[string]string{log4jProps: c.props})
		if pkg := ResolveMavenJar(id, jar); pkg != nil {
			t.Errorf("%s: resolved %+v", name, pkg)
		}
	}
	if ResolveMavenJar(filepath.Join(root, "a/1.0/a-1.0.jar"), filepath.Join(root, "missing.jar")) != nil {
		t.Error("an unreadable jar resolved")
	}
}

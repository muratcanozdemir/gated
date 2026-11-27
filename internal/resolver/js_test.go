package resolver

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func manifest(name, version string) string {
	return `{"name": "` + name + `", "version": "` + version + `", "license": "MIT"}`
}

func TestResolveInPlaceBun(t *testing.T) {
	cache := t.TempDir()
	plain := filepath.Join(cache, "lodash@4.17.20@@@1")
	writeFile(t, filepath.Join(plain, "package.json"), manifest("lodash", "4.17.20"))
	scoped := filepath.Join(cache, "@babel", "helper-string-parser@7.22.5@@@1")
	writeFile(t, filepath.Join(scoped, "package.json"), manifest("@babel/helper-string-parser", "7.22.5"))
	registry := filepath.Join(cache, "ms@2.1.3@a1b2c3d4@@@1") // from a registry other than the default
	writeFile(t, filepath.Join(registry, "package.json"), manifest("ms", "2.1.3"))

	for _, c := range []struct {
		dir, name, version, link string
	}{
		{plain, "lodash", "4.17.20", filepath.Join(cache, "lodash", "4.17.20@@@1")},
		{scoped, "@babel/helper-string-parser", "7.22.5", filepath.Join(cache, "@babel", "helper-string-parser", "7.22.5@@@1")},
		{registry, "ms", "2.1.3", filepath.Join(cache, "ms", "2.1.3@a1b2c3d4@@@1")},
	} {
		ip := ResolveInPlace(c.dir, "npm")
		if ip == nil {
			t.Errorf("%s: not resolved", c.dir)
			continue
		}
		if ip.Pkg.Name != c.name || ip.Pkg.Version != c.version || ip.Pkg.Path != c.dir || ip.Root != cache {
			t.Errorf("%s: %+v, root %s", c.dir, ip.Pkg, ip.Root)
		}
		if want := []string{c.dir, c.link}; !reflect.DeepEqual(ip.Remove, want) {
			t.Errorf("%s: remove %v, want %v", c.dir, ip.Remove, want)
		}
	}

	// A package.json naming another package or version: not bun's entry
	// for it (a git dependency, say).
	other := filepath.Join(cache, "left-pad@1.3.0@@@1")
	writeFile(t, filepath.Join(other, "package.json"), manifest("left-pad", "1.2.0"))
	if ip := ResolveInPlace(other, "npm"); ip != nil {
		t.Errorf("a mismatched package.json resolved: %+v", ip.Pkg)
	}
	if ip := ResolveInPlace(filepath.Join(cache, "lodash", "4.17.20@@@1"), "npm"); ip != nil {
		t.Errorf("bun's link to an entry resolved: %+v", ip.Pkg)
	}
}

func writeZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestResolveInPlaceYarnZip(t *testing.T) {
	cache := t.TempDir()
	for _, c := range []struct{ file, name, version string }{
		{"lodash-npm-4.17.20-c0db62021c-10c0.zip", "lodash", "4.17.20"},
		{"@babel-helper-string-parser-npm-7.22.5-448ff0e489-10c0.zip", "@babel/helper-string-parser", "7.22.5"},
		{"my-npm-tool-npm-1.0.0-rc.1-0123456789-10c0.zip", "my-npm-tool", "1.0.0-rc.1"},
	} {
		path := filepath.Join(cache, c.file)
		writeZip(t, path, map[string]string{
			"node_modules/" + c.name + "/package.json": manifest(c.name, c.version),
			"node_modules/" + c.name + "/index.js":     "",
		})
		ip := ResolveInPlace(path, "npm")
		if ip == nil {
			t.Errorf("%s: not resolved", c.file)
			continue
		}
		if ip.Pkg.Name != c.name || ip.Pkg.Version != c.version || ip.Root != cache || !reflect.DeepEqual(ip.Remove, []string{path}) {
			t.Errorf("%s: %+v, root %s, remove %v", c.file, ip.Pkg, ip.Root, ip.Remove)
		}
		if IsDerived(path, "npm") {
			t.Errorf("%s: a registry package taken for derived", c.file)
		}
	}

	// yarn's patched typescript: derived from the typescript zip, not judged
	// on its own, and never held.
	patch := filepath.Join(cache, "typescript-patch-6fda4d02cf-10c0.zip")
	writeZip(t, patch, map[string]string{"node_modules/typescript/package.json": manifest("typescript", "5.4.5")})
	if ip := ResolveInPlace(patch, "npm"); ip != nil {
		t.Errorf("a patch: zip resolved: %+v", ip.Pkg)
	}
	if !IsDerived(patch, "npm") {
		t.Error("a patch: zip is not derived")
	}
	// A zip whose name claims another package than the one inside.
	liar := filepath.Join(cache, "lodash-npm-4.17.21-c0db62021c-10c0.zip")
	writeZip(t, liar, map[string]string{"node_modules/evil/package.json": manifest("evil", "1.0.0")})
	if ip := ResolveInPlace(liar, "npm"); ip != nil {
		t.Errorf("a zip holding another package resolved: %+v", ip.Pkg)
	}
	if IsDerived(filepath.Join(cache, "v1.0.0.zip"), "npm") {
		t.Error("a zip not named like yarn's is derived")
	}
}

func TestResolveInPlaceYarnClassic(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "v6")
	entry := filepath.Join(cache, "npm-@babel-helper-string-parser-7.22.5-533f36457a25814cf1df6488523ad547d784a99f-integrity")
	pkgDir := filepath.Join(entry, "node_modules", "@babel", "helper-string-parser")
	writeFile(t, filepath.Join(pkgDir, "package.json"), manifest("@babel/helper-string-parser", "7.22.5"))

	if ip := ResolveInPlace(entry, "npm"); ip != nil {
		t.Errorf("an unfinished entry (no .yarn-metadata.json) resolved: %+v", ip.Pkg)
	}
	writeFile(t, filepath.Join(pkgDir, ".yarn-metadata.json"), "{}")
	for _, p := range []string{entry, filepath.Join(pkgDir, ".yarn-metadata.json")} {
		ip := ResolveInPlace(p, "npm")
		if ip == nil {
			t.Errorf("%s: not resolved", p)
			continue
		}
		if ip.Pkg.Name != "@babel/helper-string-parser" || ip.Pkg.Version != "7.22.5" || ip.Pkg.Path != entry ||
			ip.Root != cache || !reflect.DeepEqual(ip.Remove, []string{entry}) {
			t.Errorf("%s: %+v, root %s, remove %v", p, ip.Pkg, ip.Root, ip.Remove)
		}
	}

	plain := filepath.Join(cache, "npm-lodash-4.17.20-b44a9b6297bcb698f1c51a3545a2b3b368d59c52-integrity")
	writeFile(t, filepath.Join(plain, "node_modules", "lodash", "package.json"), manifest("lodash", "4.17.20"))
	writeFile(t, filepath.Join(plain, "node_modules", "lodash", ".yarn-metadata.json"), "{}")
	if ip := ResolveInPlace(plain, "npm"); ip == nil || ip.Pkg.Name != "lodash" || ip.Pkg.Version != "4.17.20" {
		t.Errorf("unscoped entry: %+v", ip)
	}

	// Only under yarn's versioned cache directory.
	elsewhere := filepath.Join(t.TempDir(), "npm-lodash-4.17.20-b44a9b6297bcb698f1c51a3545a2b3b368d59c52-integrity")
	writeFile(t, filepath.Join(elsewhere, "node_modules", "lodash", "package.json"), manifest("lodash", "4.17.20"))
	writeFile(t, filepath.Join(elsewhere, "node_modules", "lodash", ".yarn-metadata.json"), "{}")
	if ip := ResolveInPlace(elsewhere, "npm"); ip != nil {
		t.Errorf("an entry outside a yarn cache resolved: %+v", ip.Pkg)
	}
}

func TestJSUnpackedContentAndCacheRoot(t *testing.T) {
	const y = "/c/yarn/v6/npm-@babel-x-1.0.0-533f36457a25814cf1df6488523ad547d784a99f-integrity"
	for _, c := range []struct {
		path string
		want bool
	}{
		{"/c/bun/lodash@4.17.20@@@1", false}, // the package itself
		{"/c/bun/lodash@4.17.20@@@1/package.json", true},
		{"/c/bun/@babel/x@1.0.0@@@1/lib/a.tgz", true},
		{"/c/bun/lodash/4.17.20@@@1", false}, // bun's link to it
		{"/c/bun/@babel", false},
		{y, false},
		{y + "/node_modules", false},
		{y + "/node_modules/@babel", false},
		{y + "/node_modules/@babel/x", false},
		{y + "/node_modules/@babel/x/.yarn-metadata.json", false}, // yarn is done: judge it
		{y + "/node_modules/@babel/x/.yarn-tarball.tgz", true},
		{y + "/node_modules/@babel/x/lib", true},
		{"/c/yarn/v6/npm-ms-2.1.3-574c8138ce1d2b5861f0b44579dbadd60c6615b2-integrity/node_modules/ms/index.js", true},
		{"/c/yarn/v6/npm-ms-2.1.3-574c8138ce1d2b5861f0b44579dbadd60c6615b2-integrity/node_modules/ms/.yarn-metadata.json", false},
		{"/c/berry/cache/lodash-npm-4.17.20-c0db62021c-10c0.zip", false},
		{"/p/node_modules/npm-run-all/index.js", false},
	} {
		if got := IsUnpackedContent(c.path, "npm"); got != c.want {
			t.Errorf("IsUnpackedContent(%s) = %v, want %v", c.path, got, c.want)
		}
	}
	for _, c := range []struct{ path, want string }{
		{"/c/bun/046a1b2753a6c525.npm", "/c/bun"},
		{"/c/bun/lodash@4.17.20@@@1", "/c/bun"},
		{"/c/bun/@babel/x@1.0.0@@@1", "/c/bun"},
		{"/c/bun/@babel", ""},
		{"/c/yarn/v6/.tmp", "/c/yarn/v6"},
		{y + "/node_modules/@babel/x/.yarn-metadata.json", "/c/yarn/v6"},
		{"/c/berry/cache/lodash-npm-4.17.20-c0db62021c-10c0.zip", "/c/berry/cache"},
		{"/c/berry/cache/lodash-npm-4.17.20-c0db62021c-10c0.zip-a0187e63165b0981.tmp", "/c/berry/cache"},
		{"/c/npm/lodash-4.17.20.tgz", ""},
	} {
		if got := CacheRoot(c.path, "npm"); got != c.want {
			t.Errorf("CacheRoot(%s) = %q, want %q", c.path, got, c.want)
		}
	}
}

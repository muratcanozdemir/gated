package resolver

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// InPlace is an artifact that gated must judge where it lies instead of
// holding it: the package manager uses it the moment it lands.
//
//   - go: the module zip in cache/download. go unpacks it into the module
//     cache right after writing it, and fails if it is gone; holding it
//     would break every first download, allowed or not.
//   - pypi (uv): uv never writes a wheel to disk. It unpacks the download
//     into <cache>/archive-v0/<id>/ and installs from that directory.
//
// gated races the package manager for these: on a deny it removes Remove,
// so the next install fetches (and gated judges) the package again, and
// warns the package manager processes that have files open under Root.
type InPlace struct {
	Pkg *Package
	// Root is the package manager's cache: a process with a file open
	// below it at download time is the one installing the package.
	Root string
	// Remove lists what to delete on a deny, the artifact itself first.
	Remove []string
}

// ResolveInPlace identifies an artifact gated in place, or returns nil.
func ResolveInPlace(path, ecosystem string) *InPlace {
	switch ecosystem {
	case "go":
		return goModuleZip(path)
	case "pypi":
		return uvArchive(path)
	}
	return nil
}

// CacheRoot returns the cache of a package manager whose artifacts are
// gated in place, if path lies in one: where its processes keep files open
// while they work (go: lock files in cache/download; uv: <cache>/.lock and
// its temporary extraction directories). "" otherwise.
func CacheRoot(path, ecosystem string) string {
	switch ecosystem {
	case "go":
		if root, _, ok := strings.Cut(filepath.ToSlash(path), "/cache/download/"); ok {
			return filepath.FromSlash(root)
		}
	case "pypi":
		// The uv cache is the directory holding archive-v0; events come from
		// archive-v0 itself, its packages, or the cache's own top level.
		for dir, i := filepath.Dir(path), 0; i < 3; dir, i = filepath.Dir(dir), i+1 {
			if filepath.Base(dir) == "archive-v0" {
				return filepath.Dir(dir)
			}
			if fi, err := os.Stat(filepath.Join(dir, "archive-v0")); err == nil && fi.IsDir() {
				return dir
			}
		}
	}
	return ""
}

// IsUnpackedContent reports whether path lies inside a package a package
// manager unpacked into its cache (or the temporary directory it unpacks
// into first). Its files are part of that package, judged with it, not
// artifacts of their own: a .gz test fixture in a Go module is no package.
func IsUnpackedContent(path, ecosystem string) bool {
	slash := filepath.ToSlash(path)
	switch ecosystem {
	case "go":
		// <GOMODCACHE>/<module>@<version>[.tmp-N]/...; the download cache
		// (cache/download/<module>/@v/) holds the archives themselves.
		if strings.Contains(slash, "/cache/download/") {
			return false
		}
		for elem := range strings.SplitSeq(slash, "/") {
			if strings.Contains(elem, "@") {
				return true
			}
		}
	case "pypi":
		// <uv cache>/archive-v0/<id>/...: below the package directory.
		_, rest, ok := strings.Cut(slash, "/archive-v0/")
		return ok && strings.Contains(rest, "/")
	}
	return false
}

// goModuleZip: <GOMODCACHE>/cache/download/<escaped module>/@v/<version>.zip,
// unpacked by go into <GOMODCACHE>/<escaped module>@<version>.
func goModuleZip(path string) *InPlace {
	pkg := resolveGo(path)
	if pkg == nil || !strings.HasSuffix(path, ".zip") {
		return nil
	}
	root, rest, ok := strings.Cut(filepath.ToSlash(path), "/cache/download/")
	if !ok {
		return nil
	}
	escModule, file, ok := strings.Cut(rest, "/@v/")
	if !ok {
		return nil
	}
	escVersion := strings.TrimSuffix(file, ".zip")
	root = filepath.FromSlash(root)
	return &InPlace{
		Pkg:  pkg,
		Root: root,
		Remove: []string{
			path,
			strings.TrimSuffix(path, ".zip") + ".ziphash",
			filepath.Join(root, filepath.FromSlash(escModule)+"@"+escVersion),
		},
	}
}

// uvArchive: <uv cache>/archive-v0/<id>/, holding <name>-<version>.dist-info.
func uvArchive(dir string) *InPlace {
	parent := filepath.Dir(dir)
	if filepath.Base(parent) != "archive-v0" {
		return nil
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil
	}
	metas, _ := filepath.Glob(filepath.Join(dir, "*.dist-info", "METADATA"))
	if len(metas) != 1 {
		return nil
	}
	name, version := metadataNameVersion(metas[0])
	if name == "" || version == "" {
		return nil
	}
	return &InPlace{
		Pkg:    &Package{Ecosystem: "pypi", Name: normalizePyPIName(name), Version: version, Path: dir},
		Root:   filepath.Dir(parent),
		Remove: []string{dir},
	}
}

// unescapeGoPath undoes the module cache's case encoding: "!a" is "A"
// (golang.org/x/mod/module.EscapePath), so that a module path matches the
// one advisories are filed under (github.com/Azure/..., not .../!azure/...).
func unescapeGoPath(s string) string {
	if !strings.Contains(s, "!") {
		return s
	}
	var b strings.Builder
	upper := false
	for _, r := range s {
		switch {
		case r == '!':
			upper = true
		case upper:
			b.WriteString(strings.ToUpper(string(r)))
			upper = false
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// metadataNameVersion reads Name and Version from a core metadata file's
// header block.
func metadataNameVersion(path string) (name, version string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() && sc.Text() != "" {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(k) {
		case "name":
			name = strings.TrimSpace(v)
		case "version":
			version = strings.TrimSpace(v)
		}
	}
	return name, version
}

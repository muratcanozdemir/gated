package resolver

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// JavaScript package managers other than npm keep packages in caches of
// their own, under the "npm" ecosystem (they install from the npm
// registry). Each uses a package the moment it lands, so all are gated in
// place (InPlace); their cache layouts tell them apart:
//
//   - bun: <cache>/[@scope/]<name>@<version>[@<registry>]@@@<n>/, unpacked
//     elsewhere and renamed into place, then copied or linked into
//     node_modules at once. Next to it, <cache>/[@scope/]<name>/<version>@@@<n>
//     links to it.
//   - yarn (berry, 2+): <cache>/<ident>-npm-<version>-<hash>-<cache key>.zip,
//     written to a temporary name, renamed into place and opened right away;
//     under Plug'n'Play, the project runs from that zip.
//   - yarn classic (1.x): <cache>/v6/npm-<ident>-<version>-<sha1>[-integrity]/
//     node_modules/<name>/, created and filled in place; .yarn-metadata.json,
//     in the package directory, is written last: yarn itself takes an entry
//     without it for unfinished.

var (
	bunEntry       = regexp.MustCompile(`@@@[0-9]+$`)
	bunManifest    = regexp.MustCompile(`^[0-9a-f]{16}\.npm$`)
	yarnZipName    = regexp.MustCompile(`-([0-9a-f]{10})-[0-9a-z]+\.zip$`)
	yarnZipTemp    = regexp.MustCompile(`-[0-9a-f]{10}-[0-9a-z]+\.zip-[0-9a-f]+\.tmp$`)
	yarnClassicDir = regexp.MustCompile(`^v[0-9]+$`)
	hexSHA1        = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

const yarnClassicDone = ".yarn-metadata.json"

// jsInPlace identifies a bun, yarn or yarn classic package, or returns nil.
func jsInPlace(path string) *InPlace {
	if ip := bunPackage(path); ip != nil {
		return ip
	}
	if ip := yarnZip(path); ip != nil {
		return ip
	}
	return yarnClassic(path)
}

// bunPackage: <cache>/[@scope/]<name>@<version>[@...]@@@<n>/, whose
// package.json must name that package.
func bunPackage(dir string) *InPlace {
	base := filepath.Base(dir)
	if !bunEntry.MatchString(base) {
		return nil
	}
	short, rest, ok := strings.Cut(bunEntry.ReplaceAllString(base, ""), "@")
	if !ok || short == "" {
		return nil
	}
	version, _, _ := strings.Cut(rest, "@") // then the registry, if not the default
	name, root := short, filepath.Dir(dir)
	if scope := filepath.Base(root); strings.HasPrefix(scope, "@") {
		name, root = scope+"/"+short, filepath.Dir(root)
	}
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return nil
	}
	if n, v := manifestNameVersion(filepath.Join(dir, "package.json")); n != name || v != version {
		return nil // a git or tarball dependency, or not bun's
	}
	return &InPlace{
		Pkg:  &Package{Ecosystem: "npm", Name: name, Version: version, Path: dir},
		Root: root,
		Remove: []string{
			dir,
			filepath.Join(root, filepath.FromSlash(name), strings.TrimPrefix(base, short+"@")),
		},
	}
}

// yarnZip: <cache>/<ident>-npm-<version>-<hash>-<cache key>.zip. The name
// comes from the zip (node_modules/<name>/), as the file name flattens
// "@scope/name" to "@scope-name"; it must agree with the file name.
func yarnZip(path string) *InPlace {
	base := filepath.Base(path)
	m := yarnZipName.FindStringIndex(base)
	if m == nil {
		return nil
	}
	name := yarnZipPackage(path)
	if name == "" {
		return nil
	}
	version, ok := strings.CutPrefix(base[:m[0]], strings.Replace(name, "/", "-", 1)+"-npm-")
	if !ok || version == "" {
		return nil // another protocol (patch:, git:, file:): see IsDerived
	}
	return &InPlace{
		Pkg:    &Package{Ecosystem: "npm", Name: name, Version: version, Path: path},
		Root:   filepath.Dir(path),
		Remove: []string{path},
	}
}

// yarnZipPackage returns the package a yarn cache zip holds: the one
// node_modules/<name>/package.json in it, or "".
func yarnZipPackage(path string) string {
	z, err := zip.OpenReader(path)
	if err != nil {
		return ""
	}
	defer z.Close()
	found := ""
	for _, f := range z.File {
		rest, ok := strings.CutPrefix(f.Name, "node_modules/")
		if !ok {
			continue
		}
		name, ok := strings.CutSuffix(rest, "/package.json")
		if !ok || !validNPMName(name) {
			continue
		}
		if found != "" && found != name {
			return "" // more than one package: not a yarn cache zip
		}
		found = name
	}
	return found
}

// yarnClassic: an entry of yarn classic's cache, given as its directory or
// as the .yarn-metadata.json that completes it.
func yarnClassic(path string) *InPlace {
	entry, pkgDir := path, ""
	if filepath.Base(path) == yarnClassicDone {
		pkgDir = filepath.Dir(path)
		entry = filepath.Dir(filepath.Dir(pkgDir))
		if strings.HasPrefix(filepath.Base(filepath.Dir(pkgDir)), "@") {
			entry = filepath.Dir(entry)
		}
	}
	base := filepath.Base(entry)
	if !strings.HasPrefix(base, "npm-") || !yarnClassicDir.MatchString(filepath.Base(filepath.Dir(entry))) {
		return nil
	}
	if pkgDir == "" {
		done, _ := filepath.Glob(filepath.Join(entry, "node_modules", "*", yarnClassicDone))
		scoped, _ := filepath.Glob(filepath.Join(entry, "node_modules", "@*", "*", yarnClassicDone))
		if done = append(done, scoped...); len(done) != 1 {
			return nil // unfinished: judged when yarn completes it
		}
		pkgDir = filepath.Dir(done[0])
	}
	rel, err := filepath.Rel(filepath.Join(entry, "node_modules"), pkgDir)
	if err != nil {
		return nil
	}
	name := filepath.ToSlash(rel)
	if !validNPMName(name) {
		return nil
	}
	if _, err := os.Stat(filepath.Join(pkgDir, yarnClassicDone)); err != nil {
		return nil
	}
	// npm-<ident>-<version>-<sha1>[-integrity], ident with "/" as "-".
	version, ok := strings.CutPrefix(base, "npm-"+strings.Replace(name, "/", "-", 1)+"-")
	if !ok {
		return nil
	}
	version = strings.TrimSuffix(version, "-integrity")
	if i := strings.LastIndex(version, "-"); i > 0 && hexSHA1.MatchString(version[i+1:]) {
		version = version[:i]
	}
	if n, v := manifestNameVersion(filepath.Join(pkgDir, "package.json")); n != name || v != version {
		return nil
	}
	return &InPlace{
		Pkg:    &Package{Ecosystem: "npm", Name: name, Version: version, Path: entry},
		Root:   filepath.Dir(entry),
		Remove: []string{entry},
	}
}

// jsCacheRoot: the cache a bun, yarn or yarn classic event happened in,
// from the path alone (it runs on every event).
func jsCacheRoot(path string) string {
	elems := strings.Split(filepath.ToSlash(path), "/")
	for i, e := range elems {
		switch {
		case bunEntry.MatchString(e):
			if i > 0 && strings.HasPrefix(elems[i-1], "@") {
				i--
			}
			return filepath.FromSlash(strings.Join(elems[:i], "/"))
		case i > 0 && yarnClassicDir.MatchString(elems[i-1]) && (strings.HasPrefix(e, "npm-") || e == ".tmp"):
			return filepath.FromSlash(strings.Join(elems[:i], "/"))
		}
	}
	base := elems[len(elems)-1]
	if bunManifest.MatchString(base) || yarnZipName.MatchString(base) || yarnZipTemp.MatchString(base) {
		return filepath.Dir(path)
	}
	return ""
}

// jsUnpackedContent: below a bun package, or below a yarn classic package
// directory (whose .yarn-metadata.json, and the directories leading to it,
// are not content: gated watches them for yarn to finish the entry).
func jsUnpackedContent(path string) bool {
	elems := strings.Split(filepath.ToSlash(path), "/")
	for i, e := range elems {
		if bunEntry.MatchString(e) && i < len(elems)-1 {
			return true
		}
		if i == 0 || !strings.HasPrefix(e, "npm-") || !yarnClassicDir.MatchString(elems[i-1]) {
			continue
		}
		rel := elems[i+1:]
		if len(rel) == 0 {
			return false
		}
		if rel[0] != "node_modules" {
			return true
		}
		depth := 2 // node_modules/<name>
		if len(rel) > 1 && strings.HasPrefix(rel[1], "@") {
			depth = 3 // node_modules/@scope/<name>
		}
		return len(rel) > depth && (len(rel) != depth+1 || rel[depth] != yarnClassicDone)
	}
	return false
}

// jsDerived: a zip in a yarn cache that holds no npm registry package of its
// own: a patched copy of one (patch:, as yarn does to typescript), or a git,
// file or tarball dependency. gated does not judge it, and must not hold it:
// yarn opens it as soon as it lands.
func jsDerived(path string) bool {
	return yarnZipName.MatchString(filepath.Base(path)) && yarnZip(path) == nil
}

// manifestNameVersion reads name and version from a package.json.
func manifestNameVersion(path string) (name, version string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	var m struct{ Name, Version string }
	if json.Unmarshal(b, &m) != nil {
		return "", ""
	}
	return m.Name, m.Version
}

// validNPMName: "name" or "@scope/name", neither part empty or a path.
func validNPMName(name string) bool {
	scope, rest, scoped := strings.Cut(name, "/")
	if scoped {
		return strings.HasPrefix(scope, "@") && len(scope) > 1 && rest != "" && !strings.Contains(rest, "/") && rest != "." && rest != ".."
	}
	return name != "" && !strings.HasPrefix(name, "@") && name != "." && name != ".."
}

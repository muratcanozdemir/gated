package resolver

import (
	"path/filepath"
	"strings"
)

// Package represents an identified artifact.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Path      string `json:"path"`
}

// Resolve maps a filesystem path + ecosystem hint to a Package identity.
// Returns nil if the path doesn't look like a scannable artifact.
func Resolve(path, ecosystem string) *Package {
	switch ecosystem {
	case "pypi":
		return resolvePyPI(path)
	case "go":
		return resolveGo(path)
	case "maven":
		return resolveMaven(path)
	case "cargo":
		return resolveCargo(path)
	case "npm":
		return resolveNPM(path)
	default:
		return nil
	}
}

// resolvePyPI handles:
//
//	~/.cache/uv/wheels-v1/{hash}/{name}-{version}-{abi}-{platform}.whl
//	~/.cache/pip/wheels/{a}/{b}/{hash}/{name}-{version}-*.whl
//	~/.cache/uv/archive-v0/{hash}/{name}-{version}.tar.gz
func resolvePyPI(path string) *Package {
	base := filepath.Base(path)

	if strings.HasSuffix(base, ".whl") {
		// Wheel filenames: {distribution}-{version}(-{build})?-{python}-{abi}-{platform}.whl
		parts := strings.SplitN(base, "-", 3)
		if len(parts) >= 2 {
			return &Package{
				Ecosystem: "pypi",
				Name:      normalizePyPIName(parts[0]),
				Version:   parts[1],
				Path:      path,
			}
		}
	}

	if strings.HasSuffix(base, ".tar.gz") {
		trimmed := strings.TrimSuffix(base, ".tar.gz")
		if idx := strings.LastIndex(trimmed, "-"); idx > 0 {
			return &Package{
				Ecosystem: "pypi",
				Name:      normalizePyPIName(trimmed[:idx]),
				Version:   trimmed[idx+1:],
				Path:      path,
			}
		}
	}

	return nil
}

// resolveGo handles:
//
//	$GOPATH/pkg/mod/cache/download/{module}/@v/{version}.zip
//	$GOPATH/pkg/mod/cache/download/{module}/@v/{version}.mod
//	$GOPATH/pkg/mod/cache/download/{module}/@v/{version}.info
func resolveGo(path string) *Package {
	base := filepath.Base(path)

	// Only gate .zip (actual source) and .mod (dependency declaration).
	if !strings.HasSuffix(base, ".zip") && !strings.HasSuffix(base, ".mod") {
		return nil
	}

	// Walk up to find @v marker.
	dir := filepath.Dir(path)
	if filepath.Base(dir) != "@v" {
		return nil
	}

	// Everything between cache/download/ and /@v/ is the module path.
	modCacheDir := filepath.Dir(dir)
	idx := strings.Index(modCacheDir, "cache/download/")
	if idx < 0 {
		return nil
	}
	modulePath := modCacheDir[idx+len("cache/download/"):]

	// Version is the filename without extension.
	ext := filepath.Ext(base)
	version := strings.TrimSuffix(base, ext)

	return &Package{
		Ecosystem: "go",
		Name:      modulePath,
		Version:   version,
		Path:      path,
	}
}

// resolveMaven handles:
//
//	~/.m2/repository/{groupId-as-path}/{artifactId}/{version}/{artifactId}-{version}.jar
func resolveMaven(path string) *Package {
	base := filepath.Base(path)

	if !strings.HasSuffix(base, ".jar") {
		return nil
	}

	// directory structure: .../{artifactId}/{version}/{file}
	dir := filepath.Dir(path)
	version := filepath.Base(dir)
	artifactDir := filepath.Dir(dir)
	artifactID := filepath.Base(artifactDir)

	// Everything above the artifactId dir is the groupId path.
	groupDir := filepath.Dir(artifactDir)
	repoIdx := strings.Index(groupDir, ".m2/repository/")
	if repoIdx < 0 {
		// Try alternate Artifactory-style local cache.
		repoIdx = strings.Index(groupDir, "repository/")
		if repoIdx < 0 {
			return nil
		}
		groupDir = groupDir[repoIdx+len("repository/"):]
	} else {
		groupDir = groupDir[repoIdx+len(".m2/repository/"):]
	}

	groupID := strings.ReplaceAll(groupDir, "/", ".")

	return &Package{
		Ecosystem: "maven",
		Name:      groupID + ":" + artifactID,
		Version:   version,
		Path:      path,
	}
}

// resolveCargo handles:
//
//	~/.cargo/registry/cache/{registry-hash}/{name}-{version}.crate
//	~/.cargo/registry/src/{registry-hash}/{name}-{version}/...
func resolveCargo(path string) *Package {
	base := filepath.Base(path)

	if strings.HasSuffix(base, ".crate") {
		trimmed := strings.TrimSuffix(base, ".crate")
		if idx := strings.LastIndex(trimmed, "-"); idx > 0 {
			return &Package{
				Ecosystem: "cargo",
				Name:      trimmed[:idx],
				Version:   trimmed[idx+1:],
				Path:      path,
			}
		}
	}

	return nil
}

// resolveNPM handles npm's content-addressable cache.
// This is best-effort: npm uses SHA-based paths, so we fall back to
// scanning the tarball metadata.
func resolveNPM(path string) *Package {
	base := filepath.Base(path)

	// npm tarballs in some cache layouts:
	// ~/.npm/_cacache/tmp/{hash}/{name}-{version}.tgz
	if strings.HasSuffix(base, ".tgz") {
		trimmed := strings.TrimSuffix(base, ".tgz")
		if idx := strings.LastIndex(trimmed, "-"); idx > 0 {
			return &Package{
				Ecosystem: "npm",
				Name:      trimmed[:idx],
				Version:   trimmed[idx+1:],
				Path:      path,
			}
		}
	}

	// For content-addressed files, return a generic entry.
	// The scanner will use syft to identify the package from contents.
	if strings.Contains(path, "_cacache/content") {
		return &Package{
			Ecosystem: "npm",
			Name:      "unknown",
			Version:   "unknown",
			Path:      path,
		}
	}

	return nil
}

func normalizePyPIName(name string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(name, "_", "-"), ".", "-"))
}

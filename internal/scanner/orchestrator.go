package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/muratcanozdemir/gated/internal/config"
	"github.com/muratcanozdemir/gated/internal/resolver"
)

// ScanResult aggregates all tool outputs for policy evaluation.
type ScanResult struct {
	Package         *resolver.Package `json:"package"`
	SBOM            *SyftOutput       `json:"sbom,omitempty"`
	Vulnerabilities []Vulnerability   `json:"vulnerabilities"`
	Licenses        []string          `json:"licenses"`
	ScannedAt       string            `json:"scanned_at"`
	Errors          []string          `json:"errors,omitempty"`
}

// Orchestrator runs all scan tools and aggregates results.
type Orchestrator struct {
	tools   config.Tools
	timeout time.Duration
	dbFresh atomic.Bool // grype's database is kept current by KeepDBFresh
	slots   chan struct{}
}

// maxConcurrentScans bounds how many scans run at once. Each runs syft and
// grype twice; a project install can land 40 packages within a second, and
// 40 scans at once took 27 s each instead of 2 in the ride (and starved the
// machine). Queued scans wait their turn, so does the package manager
// waiting for their verdict, but the queue drains faster than the stampede.
func maxConcurrentScans() int {
	return min(max(runtime.NumCPU()/2, 2), 8)
}

func NewOrchestrator(tools config.Tools, timeoutSec int) *Orchestrator {
	return &Orchestrator{
		tools:   tools,
		timeout: time.Duration(timeoutSec) * time.Second,
		slots:   make(chan struct{}, maxConcurrentScans()),
	}
}

// Scan runs all tools against the artifact and returns aggregated results.
func (o *Orchestrator) Scan(pkg *resolver.Package) (*ScanResult, error) {
	o.slots <- struct{}{} // the timeout covers the scan, not the wait for a slot
	defer func() { <-o.slots }()
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	result := &ScanResult{
		Package:   pkg,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// What the scanners read: the artifact itself (jars), or its unpacked
	// contents for archives syft cannot read as a file (wheels, sdists, npm
	// tarballs, crates). If unpacking fails, scan the file and say why.
	// A package a package manager unpacked itself (uv) is a directory.
	target := pkg.Path
	dir, cleanup, err := unpack(pkg.Path)
	defer cleanup()
	switch {
	case err != nil:
		slog.Warn("unpack failed, scanning the file as is", "path", pkg.Path, "err", err)
		result.Errors = append(result.Errors, err.Error())
	case dir != "":
		target = "dir:" + dir
	case isDir(pkg.Path):
		dir, target = pkg.Path, "dir:"+pkg.Path
	}
	if pkg.Ecosystem == "npm" && dir != "" {
		if name, ok := npmScopedName(dir, pkg.Name, pkg.Version); ok {
			pkg.Name = name
		}
	}

	// Three independent subprocess runs, concurrently, so the wall-clock
	// cost is the slowest one, not their sum. The installing process waits
	// for this (frozen in-kernel under fanotify): it is the hottest path in
	// the daemon.
	//   - syft on the bytes: SBOM and licenses.
	//   - grype on the bytes: vulnerabilities of everything inside, including
	//     libraries bundled in a jar.
	//   - grype by identity (the package URL gated resolved): vulnerabilities
	//     of the package itself, also where the bytes yield nothing (sdists).
	var (
		mu          sync.Mutex
		wg          sync.WaitGroup
		vulns, byID []Vulnerability
	)
	fail := func(tool string, err error) {
		slog.Warn(tool+" failed", "path", pkg.Path, "err", err)
		result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", tool, err))
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		sbom, err := runSyft(ctx, o.tools.Syft, target)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			fail("syft", err)
			return
		}
		result.SBOM = sbom
		result.Licenses = extractLicenses(sbom)
	}()
	go func() {
		defer wg.Done()
		v, err := runGrype(ctx, o.tools.Grype, target, o.grypeEnv())
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			fail("grype", err)
			return
		}
		vulns = v
	}()
	go func() {
		defer wg.Done()
		v, err := runGrypePURL(ctx, o.tools.Grype, buildPURL(pkg), o.grypeEnv())
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			fail("grype (package URL)", err)
			return
		}
		byID = v
	}()
	wg.Wait()

	result.Vulnerabilities = dedup(append(vulns, byID...))
	if len(result.Licenses) == 0 && dir != "" {
		switch pkg.Ecosystem {
		case "pypi":
			result.Licenses = pythonMetadataLicenses(dir)
		case "cargo":
			result.Licenses = cargoLicenses(dir)
		case "go":
			result.Licenses = goModuleLicenses(dir, pkg.Name, pkg.Version)
		}
	}

	return result, nil
}

// InputJSON renders the scan result as JSON for OPA evaluation.
func (r *ScanResult) InputJSON() ([]byte, error) {
	return json.Marshal(r)
}

func isDir(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.IsDir()
}

// extractLicenses lists the distinct licenses syft found, as SPDX where syft
// could tell (a Maven license URL becomes "Apache-2.0"), else as written,
// cleaned up by normalizeLicense.
func extractLicenses(sbom *SyftOutput) []string {
	if sbom == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, a := range sbom.Artifacts {
		for _, l := range a.Licenses {
			id := l.SPDXExpression
			if id == "" {
				id = l.Value
			}
			id = normalizeLicense(id)
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// dedup merges vulnerabilities reported under the same ID (by the byte scan
// and the package URL lookup, say), keeping the first report and folding in what only the
// others know: aliases and exploitation data.
func dedup(vulns []Vulnerability) []Vulnerability {
	index := make(map[string]int)
	var out []Vulnerability
	for _, v := range vulns {
		i, seen := index[v.ID]
		if !seen {
			index[v.ID] = len(out)
			out = append(out, v)
			continue
		}
		kept := &out[i]
		for _, a := range v.Aliases {
			if !slices.Contains(kept.Aliases, a) {
				kept.Aliases = append(kept.Aliases, a)
			}
		}
		kept.KnownExploited = kept.KnownExploited || v.KnownExploited
		kept.Ransomware = kept.Ransomware || v.Ransomware
		kept.EPSS = max(kept.EPSS, v.EPSS)
	}
	return out
}

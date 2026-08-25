package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
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
}

func NewOrchestrator(tools config.Tools, timeoutSec int) *Orchestrator {
	return &Orchestrator{
		tools:   tools,
		timeout: time.Duration(timeoutSec) * time.Second,
	}
}

// Scan runs all tools against the artifact and returns aggregated results.
func (o *Orchestrator) Scan(pkg *resolver.Package) (*ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()

	result := &ScanResult{
		Package:   pkg,
		ScannedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// syft (SBOM/licenses), grype, and osv-scanner are independent
	// subprocess invocations against the same artifact — run them
	// concurrently so wall-clock cost is max(syft,grype,osv) instead of
	// their sum. The calling process stays frozen in-kernel for this
	// entire duration under fanotify, so this is the hottest path in the
	// daemon.
	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		vulns    []Vulnerability
		osvVulns []Vulnerability
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		sbom, err := runSyft(ctx, o.tools.Syft, pkg.Path)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			slog.Warn("syft failed", "path", pkg.Path, "err", err)
			result.Errors = append(result.Errors, fmt.Sprintf("syft: %v", err))
			return
		}
		result.SBOM = sbom
		result.Licenses = extractLicenses(sbom)
	}()

	go func() {
		defer wg.Done()
		v, err := runGrype(ctx, o.tools.Grype, pkg.Path)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			slog.Warn("grype failed", "path", pkg.Path, "err", err)
			result.Errors = append(result.Errors, fmt.Sprintf("grype: %v", err))
			return
		}
		vulns = v
	}()

	go func() {
		defer wg.Done()
		v, err := runOSV(ctx, o.tools.OsvScanner, pkg)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			slog.Warn("osv-scanner failed", "path", pkg.Path, "err", err)
			result.Errors = append(result.Errors, fmt.Sprintf("osv-scanner: %v", err))
			return
		}
		osvVulns = v
	}()

	wg.Wait()

	result.Vulnerabilities = dedup(append(vulns, osvVulns...))

	return result, nil
}

// InputJSON renders the scan result as JSON for OPA evaluation.
func (r *ScanResult) InputJSON() ([]byte, error) {
	return json.Marshal(r)
}

func extractLicenses(sbom *SyftOutput) []string {
	if sbom == nil {
		return nil
	}
	seen := make(map[string]bool)
	var out []string
	for _, a := range sbom.Artifacts {
		for _, l := range a.Licenses {
			id := l.Value
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func dedup(vulns []Vulnerability) []Vulnerability {
	seen := make(map[string]bool)
	var out []Vulnerability
	for _, v := range vulns {
		if !seen[v.ID] {
			seen[v.ID] = true
			out = append(out, v)
		}
	}
	return out
}

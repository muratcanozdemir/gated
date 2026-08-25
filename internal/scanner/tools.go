package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/muratcanozdemir/gated/internal/resolver"
)

// Vulnerability is the common representation across tools.
type Vulnerability struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	FixedIn     string  `json:"fixed_in,omitempty"`
	Description string  `json:"description,omitempty"`
	Source      string  `json:"source"` // "grype" or "osv"
}

// --- syft ---

// SyftOutput is the subset of syft JSON we need.
type SyftOutput struct {
	Artifacts []SyftArtifact `json:"artifacts"`
}

type SyftArtifact struct {
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	Type     string        `json:"type"`
	Licenses []SyftLicense `json:"licenses"`
}

type SyftLicense struct {
	Value string `json:"value"`
	Type  string `json:"spdxExpression"`
}

func runSyft(ctx context.Context, bin, path string) (*SyftOutput, error) {
	cmd := exec.CommandContext(ctx, bin, path, "-o", "json", "--quiet")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}

	var out SyftOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse syft output: %w", err)
	}
	return &out, nil
}

// --- grype ---

type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVuln `json:"vulnerability"`
}

type grypeVuln struct {
	ID          string      `json:"id"`
	Severity    string      `json:"severity"`
	Fix         grypeFix    `json:"fix"`
	Cvss        []grypeCVSS `json:"cvss"`
	Description string      `json:"description"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
}

type grypeCVSS struct {
	Metrics grypeMetrics `json:"metrics"`
}

type grypeMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

func runGrype(ctx context.Context, bin, path string) ([]Vulnerability, error) {
	cmd := exec.CommandContext(ctx, bin, path, "-o", "json", "--quiet")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// grype exits 0 unless --fail-on is set (it isn't here) or a real
	// error occurred, so any non-zero exit is a genuine failure.
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}

	var out grypeOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse grype output: %w", err)
	}

	var vulns []Vulnerability
	for _, m := range out.Matches {
		v := Vulnerability{
			ID:          m.Vulnerability.ID,
			Severity:    strings.ToLower(m.Vulnerability.Severity),
			Description: m.Vulnerability.Description,
			Source:      "grype",
		}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			v.FixedIn = m.Vulnerability.Fix.Versions[0]
		}
		if len(m.Vulnerability.Cvss) > 0 {
			v.CVSS = m.Vulnerability.Cvss[0].Metrics.BaseScore
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

// --- osv-scanner ---

type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Packages []osvPackageResult `json:"packages"`
}

type osvPackageResult struct {
	Package         osvPkg             `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func runOSV(ctx context.Context, bin string, pkg *resolver.Package) ([]Vulnerability, error) {
	// osv-scanner supports direct PURL queries.
	purl := buildPURL(pkg)
	if purl == "" {
		return nil, nil
	}

	cmd := exec.CommandContext(ctx, bin, "--format", "json", "--purl", purl)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// osv-scanner documents exit code 1 as "vulnerabilities found",
		// not a failure; anything else (including context deadlines) is
		// a genuine error.
		var exitErr *exec.ExitError
		if !(errors.As(err, &exitErr) && exitErr.ExitCode() == 1) {
			return nil, fmt.Errorf("%w: %s", err, stderr.String())
		}
	}

	if stdout.Len() == 0 {
		return nil, nil
	}

	var out osvOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return nil, fmt.Errorf("parse osv output: %w", err)
	}

	var vulns []Vulnerability
	for _, r := range out.Results {
		for _, p := range r.Packages {
			for _, v := range p.Vulnerabilities {
				vuln := Vulnerability{
					ID:          v.ID,
					Description: v.Summary,
					Source:      "osv",
				}
				if len(v.Severity) > 0 {
					vuln.Severity = normalizeSeverity(v.Severity[0].Score)
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

func buildPURL(pkg *resolver.Package) string {
	switch pkg.Ecosystem {
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", pkg.Name, pkg.Version)
	case "go":
		return fmt.Sprintf("pkg:golang/%s@%s", pkg.Name, pkg.Version)
	case "maven":
		parts := strings.SplitN(pkg.Name, ":", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:maven/%s/%s@%s", parts[0], parts[1], pkg.Version)
		}
		return ""
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", pkg.Name, pkg.Version)
	case "npm":
		if pkg.Name == "unknown" {
			return ""
		}
		return fmt.Sprintf("pkg:npm/%s@%s", pkg.Name, pkg.Version)
	default:
		return ""
	}
}

// normalizeSeverity maps CVSS score strings to severity labels.
func normalizeSeverity(score string) string {
	// OSV severity scores can be CVSS vectors or numeric.
	// For simplicity, if we can't parse it, return "unknown".
	// A proper implementation would parse the CVSS vector.
	switch {
	case strings.Contains(score, "CRITICAL"):
		return "critical"
	case strings.Contains(score, "HIGH"):
		return "high"
	case strings.Contains(score, "MEDIUM"):
		return "medium"
	case strings.Contains(score, "LOW"):
		return "low"
	default:
		return "unknown"
	}
}

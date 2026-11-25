package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
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
	Source      string  `json:"source"` // "grype"

	// Aliases are other IDs of the same vulnerability (e.g. the CVE behind
	// a GHSA), so policy lists and waivers keyed by CVE still match.
	Aliases []string `json:"aliases,omitempty"`
	// KnownExploited: listed in CISA's Known Exploited Vulnerabilities
	// catalog, per grype's vulnerability DB (grype >= 0.88), which grype
	// refreshes on its own: no list to maintain in the policy data.
	KnownExploited bool `json:"known_exploited,omitempty"`
	// Ransomware: KEV says it is known to be used in ransomware campaigns.
	Ransomware bool `json:"ransomware,omitempty"`
	// EPSS is the highest FIRST EPSS score (probability of exploitation in
	// the next 30 days, 0-1) of the vulnerability or its aliases.
	EPSS float64 `json:"epss,omitempty"`
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
	// SPDXExpression is syft's SPDX reading of Value, e.g. "Apache-2.0" for
	// a Maven license URL (syft >= 1.2x); empty when it has none.
	SPDXExpression string `json:"spdxExpression"`
}

func runSyft(ctx context.Context, bin, path string) (*SyftOutput, error) {
	// The installed-package npm cataloger is off by default for directory
	// scans, and it is the one that reads package/package.json in an
	// unpacked npm tarball: without it, an npm package has no license.
	cmd := exec.CommandContext(ctx, bin, path, "-o", "json", "--quiet",
		"--select-catalogers", "+javascript-package-cataloger")
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
	Vulnerability          grypeVuln          `json:"vulnerability"`
	RelatedVulnerabilities []grypeExploitInfo `json:"relatedVulnerabilities"`
}

type grypeVuln struct {
	grypeExploitInfo
	Severity    string      `json:"severity"`
	Fix         grypeFix    `json:"fix"`
	Cvss        []grypeCVSS `json:"cvss"`
	Description string      `json:"description"`
}

// grypeExploitInfo is what grype reports, on a vulnerability and on each of
// its related vulnerabilities, about exploitation in the wild.
type grypeExploitInfo struct {
	ID             string      `json:"id"`
	KnownExploited []grypeKEV  `json:"knownExploited"`
	EPSS           []grypeEPSS `json:"epss"`
}

type grypeKEV struct {
	CVE                        string `json:"cve"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

type grypeEPSS struct {
	CVE  string  `json:"cve"`
	EPSS float64 `json:"epss"`
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

	return parseGrype(stdout.Bytes())
}

// parseGrype maps grype's JSON report to vulnerabilities.
func parseGrype(report []byte) ([]Vulnerability, error) {
	var out grypeOutput
	if err := json.Unmarshal(report, &out); err != nil {
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
		v.addExploitInfo(m.Vulnerability.grypeExploitInfo)
		for _, r := range m.RelatedVulnerabilities {
			if r.ID != "" && r.ID != v.ID && !slices.Contains(v.Aliases, r.ID) {
				v.Aliases = append(v.Aliases, r.ID)
			}
			v.addExploitInfo(r)
		}
		vulns = append(vulns, v)
	}
	return vulns, nil
}

func (v *Vulnerability) addExploitInfo(info grypeExploitInfo) {
	for _, k := range info.KnownExploited {
		v.KnownExploited = true
		if strings.EqualFold(k.KnownRansomwareCampaignUse, "known") {
			v.Ransomware = true
		}
	}
	for _, e := range info.EPSS {
		v.EPSS = max(v.EPSS, e.EPSS)
	}
}

// --- grype by package URL ---

// runGrypePURL looks a package up in grype's DB by its package URL
// (pkg:pypi/pyyaml@5.3.1), from the identity gated resolved rather than from
// the bytes. "" (no package URL for the ecosystem) finds nothing.
func runGrypePURL(ctx context.Context, bin, purl string) ([]Vulnerability, error) {
	if purl == "" {
		return nil, nil
	}
	f, err := os.CreateTemp("", "gated-purl-*.txt")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(purl + "\n"); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return runGrype(ctx, bin, "purl:"+f.Name())
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
		// A scope's "@" is percent-encoded in a package URL.
		return fmt.Sprintf("pkg:npm/%s@%s", strings.Replace(pkg.Name, "@", "%40", 1), pkg.Version)
	default:
		return ""
	}
}

package scanner

import (
	"reflect"
	"testing"

	"github.com/muratcanozdemir/gated/internal/resolver"
)

func TestDedupVulnerabilities(t *testing.T) {
	in := []Vulnerability{
		{ID: "CVE-1", Source: "grype"},
		{ID: "CVE-2", Source: "grype"},
		{ID: "CVE-1", Source: "grype"}, // the same vulnerability from the package URL lookup
	}
	out := dedup(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 deduped vulnerabilities, got %d: %+v", len(out), out)
	}
	if out[0].ID != "CVE-1" || out[1].ID != "CVE-2" {
		t.Fatalf("expected first-seen entries to win, got %+v", out)
	}
}

func TestExtractLicenses(t *testing.T) {
	sbom := &SyftOutput{
		Artifacts: []SyftArtifact{
			{Licenses: []SyftLicense{{Value: "MIT"}, {Value: "Apache-2.0"}}},
			{Licenses: []SyftLicense{{Value: "MIT"}, {Value: ""}}}, // duplicate + empty
		},
	}
	got := extractLicenses(sbom)
	want := map[string]bool{"MIT": true, "Apache-2.0": true}
	if len(got) != len(want) {
		t.Fatalf("expected %d licenses, got %d: %v", len(want), len(got), got)
	}
	for _, l := range got {
		if !want[l] {
			t.Fatalf("unexpected license %q in %v", l, got)
		}
	}
}

func TestExtractLicensesNilSBOM(t *testing.T) {
	if got := extractLicenses(nil); got != nil {
		t.Fatalf("expected nil for nil SBOM, got %v", got)
	}
}

func TestBuildPURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  *resolver.Package
		want string
	}{
		{"pypi", &resolver.Package{Ecosystem: "pypi", Name: "requests", Version: "2.31.0"}, "pkg:pypi/requests@2.31.0"},
		{"go", &resolver.Package{Ecosystem: "go", Name: "golang.org/x/sys", Version: "v0.29.0"}, "pkg:golang/golang.org/x/sys@v0.29.0"},
		{"maven", &resolver.Package{Ecosystem: "maven", Name: "org.apache:commons-lang3", Version: "3.14.0"}, "pkg:maven/org.apache/commons-lang3@3.14.0"},
		{"maven no colon", &resolver.Package{Ecosystem: "maven", Name: "commons-lang3", Version: "3.14.0"}, ""},
		{"cargo", &resolver.Package{Ecosystem: "cargo", Name: "serde", Version: "1.0.0"}, "pkg:cargo/serde@1.0.0"},
		{"npm unknown", &resolver.Package{Ecosystem: "npm", Name: "unknown", Version: "unknown"}, ""},
		{"npm known", &resolver.Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}, "pkg:npm/lodash@4.17.21"},
		{"unsupported ecosystem", &resolver.Package{Ecosystem: "nuget", Name: "x", Version: "1.0.0"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPURL(tt.pkg); got != tt.want {
				t.Errorf("buildPURL(%+v) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}

// Shaped like grype >= 0.88 JSON (grype/presenter/models): KEV and EPSS on
// the vulnerability, and on related vulnerabilities (the CVE behind a GHSA).
const grypeReport = `{"matches": [
  {
    "vulnerability": {
      "id": "GHSA-jfh8-c2jp-5v3q", "severity": "Critical", "description": "Log4Shell",
      "fix": {"versions": ["2.15.0"], "state": "fixed"},
      "cvss": [{"metrics": {"baseScore": 10.0}}]
    },
    "relatedVulnerabilities": [
      {
        "id": "CVE-2021-44228",
        "knownExploited": [{"cve": "CVE-2021-44228", "knownRansomwareCampaignUse": "Known"}],
        "epss": [{"cve": "CVE-2021-44228", "epss": 0.94358, "percentile": 0.99}]
      }
    ]
  },
  {
    "vulnerability": {
      "id": "CVE-2023-0001", "severity": "High",
      "fix": {"versions": [], "state": "not-fixed"},
      "cvss": [],
      "knownExploited": [{"cve": "CVE-2023-0001", "knownRansomwareCampaignUse": "Unknown"}],
      "epss": [{"cve": "CVE-2023-0001", "epss": 0.12}]
    },
    "relatedVulnerabilities": [{"id": "CVE-2023-0001"}]
  },
  {
    "vulnerability": {"id": "CVE-2024-0002", "severity": "Low", "fix": {"versions": []}, "cvss": []},
    "relatedVulnerabilities": null
  }
]}`

func TestParseGrype_ExploitData(t *testing.T) {
	got, err := parseGrype([]byte(grypeReport))
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	want := []Vulnerability{
		{ID: "GHSA-jfh8-c2jp-5v3q", Severity: "critical", CVSS: 10, FixedIn: "2.15.0", Description: "Log4Shell", Source: "grype",
			Aliases: []string{"CVE-2021-44228"}, KnownExploited: true, Ransomware: true, EPSS: 0.94358},
		{ID: "CVE-2023-0001", Severity: "high", Source: "grype", KnownExploited: true, EPSS: 0.12},
		{ID: "CVE-2024-0002", Severity: "low", Source: "grype"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseGrype:\n got %+v\nwant %+v", got, want)
	}
}

// grype before 0.88 has no knownExploited/epss fields: parsing still works,
// nothing is flagged.
func TestParseGrype_OldReport(t *testing.T) {
	got, err := parseGrype([]byte(`{"matches":[{"vulnerability":{"id":"CVE-1","severity":"Medium","fix":{"versions":[]},"cvss":[]}}]}`))
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	if len(got) != 1 || got[0].KnownExploited || got[0].EPSS != 0 || got[0].Aliases != nil {
		t.Fatalf("unexpected %+v", got)
	}
}

func TestParseGrype_Invalid(t *testing.T) {
	if _, err := parseGrype([]byte("not json")); err == nil {
		t.Fatal("expected an error")
	}
}

func TestDedupMergesExploitData(t *testing.T) {
	out := dedup([]Vulnerability{
		{ID: "CVE-1", Source: "grype", Aliases: []string{"GHSA-1"}},
		{ID: "CVE-1", Source: "grype", Aliases: []string{"GHSA-1", "GHSA-2"}, KnownExploited: true, Ransomware: true, EPSS: 0.7},
		{ID: "CVE-2", Source: "grype", EPSS: 0.1},
	})
	want := []Vulnerability{
		{ID: "CVE-1", Source: "grype", Aliases: []string{"GHSA-1", "GHSA-2"}, KnownExploited: true, Ransomware: true, EPSS: 0.7},
		{ID: "CVE-2", Source: "grype", EPSS: 0.1},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("dedup:\n got %+v\nwant %+v", out, want)
	}
}

// Shaped like grype's report for golang.org/x/tools/gopls@v0.24.0 and
// github.com/segmentio/encoding@v0.5.4: matches against go.mod requirements,
// and one against a GitHub Action the module's own CI uses.
const grypeDependencyReport = `{"matches": [
  {
    "vulnerability": {"id": "GO-2026-6860", "severity": "High", "fix": {"versions": ["0.62.0"]}, "cvss": []},
    "artifact": {"name": "golang.org/x/net", "version": "v0.59.0", "type": "go-module", "purl": "pkg:golang/golang.org/x/net@v0.59.0"}
  },
  {
    "vulnerability": {"id": "GO-2026-0001", "severity": "High", "fix": {"versions": ["0.25.0"]}, "cvss": []},
    "artifact": {"name": "golang.org/x/tools/gopls", "version": "v0.24.0", "type": "go-module", "purl": "pkg:golang/golang.org/x/tools/gopls@v0.24.0"}
  },
  {
    "vulnerability": {"id": "GHSA-cxww-7g56-2vh6", "severity": "High", "fix": {"versions": ["4.1.3"]}, "cvss": []},
    "artifact": {"name": "actions/download-artifact", "version": "v4", "type": "github-action", "purl": "pkg:github/actions/download-artifact@v4"}
  }
]}`

func TestParseGrype_DependenciesAndCI(t *testing.T) {
	got, err := parseGrype([]byte(grypeDependencyReport))
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	markDependencies(&resolver.Package{Ecosystem: "go", Name: "golang.org/x/tools/gopls", Version: "v0.24.0"}, got)
	type summary struct{ ID, Dependency, DependencyVersion, FixedIn string }
	var sum []summary
	for _, v := range got {
		sum = append(sum, summary{v.ID, v.Dependency, v.DependencyVersion, v.FixedIn})
	}
	want := []summary{
		{"GO-2026-6860", "golang.org/x/net", "v0.59.0", "0.62.0"}, // in a dependency
		{"GO-2026-0001", "", "", "0.25.0"},                        // in the module itself
		// the GitHub Action is dropped: the module's CI is not installed
	}
	if !reflect.DeepEqual(sum, want) {
		t.Fatalf("got %+v\nwant %+v", sum, want)
	}
}

func TestMarkDependencies_SamePackage(t *testing.T) {
	for _, tc := range []struct {
		name string
		pkg  resolver.Package
		art  grypeArtifact
		dep  string
	}{
		{"pypi name in another form", resolver.Package{Ecosystem: "pypi", Name: "pyyaml", Version: "5.3.1"},
			grypeArtifact{Name: "PyYAML", Version: "5.3.1", PURL: "pkg:pypi/PyYAML@5.3.1"}, ""},
		{"npm scoped", resolver.Package{Ecosystem: "npm", Name: "@babel/core", Version: "7.0.0"},
			grypeArtifact{Name: "@babel/core", Version: "7.0.0", PURL: "pkg:npm/%40babel/core@7.0.0"}, ""},
		{"jar with a guessed groupId", resolver.Package{Ecosystem: "maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
			grypeArtifact{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/log4j-core/log4j-core@2.14.1"}, ""},
		{"library bundled in a jar", resolver.Package{Ecosystem: "maven", Name: "com.example:app", Version: "1.0"},
			grypeArtifact{Name: "log4j-core", Version: "2.14.1", PURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}, "log4j-core"},
		{"no package URL", resolver.Package{Ecosystem: "go", Name: "example.com/m", Version: "v1.0.0"},
			grypeArtifact{Name: "golang.org/x/net", Version: "v0.59.0"}, ""},
		{"qualifiers", resolver.Package{Ecosystem: "cargo", Name: "serde", Version: "1.0.0"},
			grypeArtifact{Name: "serde", Version: "1.0.0", PURL: "pkg:cargo/serde@1.0.0?arch=x86_64"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := []Vulnerability{{ID: "CVE-1", matched: tc.art}}
			markDependencies(&tc.pkg, v)
			if v[0].Dependency != tc.dep {
				t.Fatalf("Dependency = %q, want %q", v[0].Dependency, tc.dep)
			}
		})
	}
}

// The package URL lookup finds a vulnerability in the package itself that
// the byte scan attributed to a dependency: the package's own report wins.
func TestDedup_OwnReportWins(t *testing.T) {
	out := dedup([]Vulnerability{
		{ID: "CVE-1", Dependency: "dep", DependencyVersion: "1.0"},
		{ID: "CVE-1"},
	})
	if len(out) != 1 || out[0].Dependency != "" || out[0].DependencyVersion != "" {
		t.Fatalf("got %+v", out)
	}
}

// A package's own CI (.github/workflows) is not installed with it: grype's
// matches on the GitHub Actions it uses are dropped.
func TestParseGrype_SkipsCIActions(t *testing.T) {
	got, err := parseGrype([]byte(`{"matches": [
	  {"vulnerability": {"id": "GHSA-cxww-7g56-2vh6", "severity": "High", "fix": {"versions": ["4.1.3"]}, "cvss": []},
	   "artifact": {"name": "actions/download-artifact", "version": "v4", "type": "github-action"}},
	  {"vulnerability": {"id": "GHSA-0000-0000-0000", "severity": "High", "fix": {"versions": []}, "cvss": []},
	   "artifact": {"name": ".github/workflows/ci.yml", "type": "github-action-workflow"}},
	  {"vulnerability": {"id": "CVE-1", "severity": "High", "fix": {"versions": []}, "cvss": []},
	   "artifact": {"name": "golang.org/x/net", "version": "v0.59.0", "type": "go-module"}}
	]}`))
	if err != nil {
		t.Fatalf("parseGrype: %v", err)
	}
	if len(got) != 1 || got[0].ID != "CVE-1" {
		t.Fatalf("got %+v, want only CVE-1", got)
	}
}

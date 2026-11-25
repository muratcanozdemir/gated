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

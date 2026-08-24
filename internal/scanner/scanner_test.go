package scanner

import (
	"testing"

	"github.com/internal/gate-daemon/internal/resolver"
)

func TestDedupVulnerabilities(t *testing.T) {
	in := []Vulnerability{
		{ID: "CVE-1", Source: "grype"},
		{ID: "CVE-2", Source: "grype"},
		{ID: "CVE-1", Source: "osv"}, // duplicate ID from a different source
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

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		score string
		want  string
	}{
		{"CVSS_V3:CRITICAL", "critical"},
		{"CVSS_V3:HIGH", "high"},
		{"CVSS_V3:MEDIUM", "medium"},
		{"CVSS_V3:LOW", "low"},
		{"garbage", "unknown"},
	}
	for _, tt := range tests {
		if got := normalizeSeverity(tt.score); got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/muratcanozdemir/gated/internal/resolver"
	"github.com/muratcanozdemir/gated/internal/scanner"
)

// policyDir points at the repo's real policy/ directory, so these tests
// also guard against the policies themselves failing to compile or
// evaluate (e.g. the input.package.* reserved-keyword bug this package's
// migration to the OPA Go SDK surfaced).
const policyDir = "../../policy"

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(policyDir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.ValidatePolicies(); err != nil {
		t.Fatalf("ValidatePolicies: %v", err)
	}
	return e
}

func evalInput(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	return b
}

func TestEvaluate_Allow(t *testing.T) {
	e := newTestEngine(t)
	input := evalInput(t, map[string]any{
		"package": map[string]any{
			"ecosystem": "pypi",
			"name":      "requests",
			"version":   "2.31.0",
		},
		"licenses":        []string{"Apache-2.0"},
		"vulnerabilities": []any{},
		"errors":          []any{},
	})

	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !v.Allowed {
		t.Fatalf("expected allow, got deny: %v", v.Reasons)
	}
}

func TestEvaluate_DenyBlockedLicense(t *testing.T) {
	e := newTestEngine(t)
	input := evalInput(t, map[string]any{
		"package": map[string]any{
			"ecosystem": "pypi",
			"name":      "some-agpl-pkg",
			"version":   "1.0.0",
		},
		"licenses":        []string{"AGPL-3.0-only"},
		"vulnerabilities": []any{},
		"errors":          []any{},
	})

	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed {
		t.Fatal("expected deny for blocked license, got allow")
	}
	if len(v.Reasons) == 0 {
		t.Fatal("expected at least one deny reason")
	}
}

func TestEvaluate_DenyCriticalVulnerability(t *testing.T) {
	e := newTestEngine(t)
	input := evalInput(t, map[string]any{
		"package": map[string]any{
			"ecosystem": "pypi",
			"name":      "some-pkg",
			"version":   "1.0.0",
		},
		"licenses": []string{"MIT"},
		"vulnerabilities": []map[string]any{
			{"id": "CVE-2024-0001", "severity": "critical", "cvss": 9.8, "source": "grype"},
		},
		"errors": []any{},
	})

	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed {
		t.Fatal("expected deny for critical vulnerability, got allow")
	}
}

func TestEvaluate_DenyBlocklistedPackage(t *testing.T) {
	e := newTestEngine(t)
	input := evalInput(t, map[string]any{
		"package": map[string]any{
			"ecosystem": "pypi",
			"name":      "jeIlyfish",
			"version":   "1.0.0",
		},
		"licenses":        []string{"MIT"},
		"vulnerabilities": []any{},
		"errors":          []any{},
	})

	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed {
		t.Fatal("expected deny for blocklisted package, got allow")
	}
}

func TestValidatePolicies_KeepsOldQueryOnCompileFailure(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "gate.rego", `package gate

import rego.v1

deny contains msg if {
	input["package"].name == "bad-pkg"
	msg := "always denied for testing"
}
`)

	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.ValidatePolicies(); err != nil {
		t.Fatalf("initial ValidatePolicies: %v", err)
	}

	// Break the policy with invalid syntax and reload — should fail and
	// leave the previously-compiled query in place (mirrors the SIGHUP
	// reload path in cmd/gated/main.go).
	writeRego(t, dir, "gate.rego", `package gate

this is not valid rego
`)
	if err := e.ValidatePolicies(); err == nil {
		t.Fatal("expected ValidatePolicies to fail on invalid rego")
	}

	input := evalInput(t, map[string]any{
		"package":         map[string]any{"ecosystem": "pypi", "name": "bad-pkg", "version": "1.0.0"},
		"licenses":        []string{"MIT"},
		"vulnerabilities": []any{},
		"errors":          []any{},
	})
	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate after failed reload: %v", err)
	}
	if v.Allowed {
		t.Fatal("expected old policy to still be live after failed reload")
	}
}

func writeRego(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// The daemon hands the policies a marshalled scanner.ScanResult; a nil
// Licenses slice (syft failed or found nothing) becomes JSON null. That
// must deny, not make the no-license rule undefined.
func TestEvaluate_ScanResultWithoutLicensesDenied(t *testing.T) {
	e := newTestEngine(t)
	input, err := json.Marshal(&scanner.ScanResult{
		Package: &resolver.Package{Ecosystem: "pypi", Name: "somepkg", Version: "1.0.0"},
		Errors:  []string{"syft: exit status 1"},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(input), `"licenses":null`) {
		t.Fatalf("test premise changed: licenses not null in %s", input)
	}

	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v.Allowed {
		t.Fatal("expected deny for package without licenses, got allow")
	}
}

func TestValidatePolicies_SkipsRegoTests(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "gate.rego", "package gate\n\nimport rego.v1\n\ndeny contains \"x\" if input.bad\n")
	writeRego(t, dir, "gate_test.rego", "package gate_test\n\nthis would not compile\n")

	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.ValidatePolicies(); err != nil {
		t.Fatalf("ValidatePolicies loaded a _test.rego file: %v", err)
	}
}

func TestValidatePolicies_OnlyRegoTestsIsAnError(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "gate_test.rego", "package gate_test\n")

	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.ValidatePolicies(); err == nil {
		t.Fatal("expected an error for a policy dir with only test files")
	}
}

// copyPolicies copies the shipped .rego policies (not tests, not data.json)
// into a fresh directory.
func copyPolicies(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files, err := filepath.Glob(filepath.Join(policyDir, "*.rego"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.rego") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		writeRego(t, dir, filepath.Base(f), string(b))
	}
	return dir
}

// Every data.json knob has a default, so the policies load and decide
// without one (or with one from an older release).
func TestPolicies_WithoutDataJSON(t *testing.T) {
	e, err := NewEngine(copyPolicies(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := e.ValidatePolicies(); err != nil {
		t.Fatalf("ValidatePolicies: %v", err)
	}

	input := evalInput(t, map[string]any{
		"package":  map[string]any{"ecosystem": "pypi", "name": "somepkg", "version": "1.0.0"},
		"licenses": []string{"MIT"},
		"vulnerabilities": []map[string]any{
			{"id": "CVE-2024-0001", "severity": "unknown", "cvss": 9.8, "source": "osv"},
		},
	})
	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// No approved licenses configured, and the default CVSS bar of 9.0.
	want := map[string]bool{
		"unapproved license: MIT (package: somepkg@1.0.0) — submit for review":     true,
		"unknown-severity vulnerability CVE-2024-0001 (CVSS 9.8) in somepkg@1.0.0": true,
	}
	if len(v.Reasons) != len(want) {
		t.Fatalf("got reasons %q, want %d", v.Reasons, len(want))
	}
	for _, r := range v.Reasons {
		if !want[r] {
			t.Errorf("unexpected reason %q", r)
		}
	}
}

func TestConfigWarnings_ExpiredWaiver(t *testing.T) {
	dir := copyPolicies(t)
	writeRego(t, dir, "data.json", `{"vulnerability_waivers": {
		"CVE-1": {"reason": "old", "expires": "2020-01-01"},
		"CVE-2": {"reason": "no date"},
		"CVE-3": {"reason": "fine", "expires": "2200-01-01"}
	}}`)

	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		t.Fatal(err)
	}
	got := e.configWarnings(context.Background(), paths)
	want := []string{
		"waiver for CVE-1 expired on 2020-01-01: ignored",
		`waiver for CVE-2 has no valid "expires" date (YYYY-MM-DD): ignored`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("configWarnings:\n got %q\nwant %q", got, want)
	}
}

func TestConfigWarnings_RuleNotDefined(t *testing.T) {
	dir := t.TempDir()
	writeRego(t, dir, "gate.rego", "package gate\n\nimport rego.v1\n\ndeny contains \"x\" if input.bad\n")
	e, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if got := e.configWarnings(context.Background(), []string{filepath.Join(dir, "gate.rego")}); len(got) != 0 {
		t.Fatalf("expected no warnings, got %q", got)
	}
}

// The scanner's exploitation fields reach the policy under the names it
// reads: a KEV flag on a GHSA-keyed match denies, and a CVE waiver covers it
// through its alias.
func TestEvaluate_ScannerExploitFieldsContract(t *testing.T) {
	e := newTestEngine(t)
	result := &scanner.ScanResult{
		Package:  &resolver.Package{Ecosystem: "maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1"},
		Licenses: []string{"Apache-2.0"},
		Vulnerabilities: []scanner.Vulnerability{{
			ID: "GHSA-jfh8-c2jp-5v3q", Severity: "medium", CVSS: 5.0, Source: "grype",
			Aliases: []string{"CVE-2021-44228"}, KnownExploited: true, Ransomware: true, EPSS: 0.94,
		}},
	}
	input, err := result.InputJSON()
	if err != nil {
		t.Fatalf("InputJSON: %v", err)
	}
	v, err := e.Evaluate(input)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := "known-exploited vulnerability GHSA-jfh8-c2jp-5v3q (medium) in org.apache.logging.log4j:log4j-core@2.14.1 — in CISA KEV, used in ransomware campaigns"
	if len(v.Reasons) != 1 || v.Reasons[0] != want {
		t.Fatalf("got %q, want [%q]", v.Reasons, want)
	}

	dir := copyPolicies(t)
	writeRego(t, dir, "data.json", `{"approved_licenses": ["Apache-2.0"],
		"vulnerability_waivers": {"CVE-2021-44228": {"reason": "test", "expires": "2200-01-01"}}}`)
	waived, err := NewEngine(dir)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := waived.ValidatePolicies(); err != nil {
		t.Fatalf("ValidatePolicies: %v", err)
	}
	if v, err := waived.Evaluate(input); err != nil || !v.Allowed {
		t.Fatalf("expected the CVE waiver to cover the GHSA via its alias: %+v, %v", v, err)
	}
}

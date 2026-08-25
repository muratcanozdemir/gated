package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

func evalInput(t *testing.T, v map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}
	return b
}

func TestEvaluate_Allow(t *testing.T) {
	e := newTestEngine(t)
	input := evalInput(t, map[string]interface{}{
		"package": map[string]interface{}{
			"ecosystem": "pypi",
			"name":      "requests",
			"version":   "2.31.0",
		},
		"licenses":        []string{"Apache-2.0"},
		"vulnerabilities": []interface{}{},
		"errors":          []interface{}{},
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
	input := evalInput(t, map[string]interface{}{
		"package": map[string]interface{}{
			"ecosystem": "pypi",
			"name":      "some-agpl-pkg",
			"version":   "1.0.0",
		},
		"licenses":        []string{"AGPL-3.0-only"},
		"vulnerabilities": []interface{}{},
		"errors":          []interface{}{},
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
	input := evalInput(t, map[string]interface{}{
		"package": map[string]interface{}{
			"ecosystem": "pypi",
			"name":      "some-pkg",
			"version":   "1.0.0",
		},
		"licenses": []string{"MIT"},
		"vulnerabilities": []map[string]interface{}{
			{"id": "CVE-2024-0001", "severity": "critical", "cvss": 9.8, "source": "grype"},
		},
		"errors": []interface{}{},
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
	input := evalInput(t, map[string]interface{}{
		"package": map[string]interface{}{
			"ecosystem": "pypi",
			"name":      "jeIlyfish",
			"version":   "1.0.0",
		},
		"licenses":        []string{"MIT"},
		"vulnerabilities": []interface{}{},
		"errors":          []interface{}{},
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

	input := evalInput(t, map[string]interface{}{
		"package":         map[string]interface{}{"ecosystem": "pypi", "name": "bad-pkg", "version": "1.0.0"},
		"licenses":        []string{"MIT"},
		"vulnerabilities": []interface{}{},
		"errors":          []interface{}{},
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

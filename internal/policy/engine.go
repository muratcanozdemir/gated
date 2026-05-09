package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Verdict is the policy evaluation result.
type Verdict struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons"`
}

// Engine evaluates scan results against OPA policies.
type Engine struct {
	opaBin    string
	policyDir string
}

func NewEngine(opaBin, policyDir string) (*Engine, error) {
	if _, err := exec.LookPath(opaBin); err != nil {
		return nil, fmt.Errorf("opa binary not found: %s", opaBin)
	}
	if _, err := os.Stat(policyDir); err != nil {
		return nil, fmt.Errorf("policy dir: %w", err)
	}
	return &Engine{
		opaBin:    opaBin,
		policyDir: policyDir,
	}, nil
}

// Evaluate runs all rego policies in the policy dir against the input.
// Returns denied=true if any policy produces a deny reason.
func (e *Engine) Evaluate(inputJSON []byte) (*Verdict, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Write input to a temp file — avoid shell injection via pipe.
	tmpInput, err := os.CreateTemp("", "gate-input-*.json")
	if err != nil {
		return nil, fmt.Errorf("create temp input: %w", err)
	}
	defer os.Remove(tmpInput.Name())

	if _, err := tmpInput.Write(inputJSON); err != nil {
		tmpInput.Close()
		return nil, fmt.Errorf("write temp input: %w", err)
	}
	tmpInput.Close()

	// Build a bundle from the policy directory.
	// Query: data.gate.deny — collects all deny reasons across policies.
	cmd := exec.CommandContext(ctx, e.opaBin, "eval",
		"--input", tmpInput.Name(),
		"--data", e.policyDir,
		"--format", "json",
		"data.gate.deny",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// OPA returns non-zero on eval errors, not on policy deny.
		return nil, fmt.Errorf("opa eval: %s (stderr: %s)", err, stderr.String())
	}

	var opaResult opaEvalOutput
	if err := json.Unmarshal(stdout.Bytes(), &opaResult); err != nil {
		return nil, fmt.Errorf("parse opa output: %w", err)
	}

	verdict := &Verdict{Allowed: true}

	for _, r := range opaResult.Result {
		for _, expr := range r.Expressions {
			reasons, ok := extractReasons(expr.Value)
			if ok && len(reasons) > 0 {
				verdict.Allowed = false
				verdict.Reasons = append(verdict.Reasons, reasons...)
			}
		}
	}

	if !verdict.Allowed {
		slog.Warn("policy denied", "reasons", verdict.Reasons)
	}

	return verdict, nil
}

// ValidatePolicies runs opa check against the policy dir.
func (e *Engine) ValidatePolicies() error {
	files, err := filepath.Glob(filepath.Join(e.policyDir, "*.rego"))
	if err != nil || len(files) == 0 {
		return fmt.Errorf("no .rego files in %s", e.policyDir)
	}

	args := []string{"check"}
	args = append(args, files...)

	cmd := exec.Command(e.opaBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("opa check failed: %s", stderr.String())
	}
	return nil
}

// --- OPA output parsing ---

type opaEvalOutput struct {
	Result []opaResultSet `json:"result"`
}

type opaResultSet struct {
	Expressions []opaExpression `json:"expressions"`
}

type opaExpression struct {
	Value interface{} `json:"value"`
	Text  string      `json:"text"`
}

// extractReasons handles OPA's set output format.
// data.gate.deny returns a set of strings (reasons).
func extractReasons(v interface{}) ([]string, bool) {
	switch val := v.(type) {
	case []interface{}:
		var reasons []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				reasons = append(reasons, s)
			}
		}
		return reasons, true
	case map[string]interface{}:
		// OPA sometimes returns sets as objects.
		var reasons []string
		for k := range val {
			reasons = append(reasons, k)
		}
		return reasons, true
	default:
		return nil, false
	}
}

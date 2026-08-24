package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
)

// Verdict is the policy evaluation result.
type Verdict struct {
	Allowed bool     `json:"allowed"`
	Reasons []string `json:"reasons"`
}

// Engine evaluates scan results against OPA policies.
//
// Policies are compiled once (at construction and on each ValidatePolicies
// call) into a PreparedEvalQuery, which Evaluate reuses for every decision.
// This avoids spawning an `opa` subprocess and recompiling the rego bundle
// from disk on every package-install decision — the daemon sits synchronously
// in the install path, so that cost was paid on every cache miss.
type Engine struct {
	policyDir string

	mu    sync.RWMutex
	query rego.PreparedEvalQuery
}

func NewEngine(policyDir string) (*Engine, error) {
	if _, err := os.Stat(policyDir); err != nil {
		return nil, fmt.Errorf("policy dir: %w", err)
	}
	return &Engine{policyDir: policyDir}, nil
}

// Evaluate runs the prepared query (data.gate.deny) against the input.
// Returns denied=true if any policy produces a deny reason.
func (e *Engine) Evaluate(inputJSON []byte) (*Verdict, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var input interface{}
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("parse input: %w", err)
	}

	e.mu.RLock()
	query := e.query
	e.mu.RUnlock()

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policy eval: %w", err)
	}

	verdict := &Verdict{Allowed: true}

	for _, r := range rs {
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

// ValidatePolicies (re)compiles every .rego/.json/.yaml file in the policy
// dir into a fresh prepared query and, only on success, swaps it in — a
// syntax or compile error leaves the previously-loaded policies live. This
// is called once at startup and again on each SIGHUP reload.
func (e *Engine) ValidatePolicies() error {
	regoFiles, err := filepath.Glob(filepath.Join(e.policyDir, "*.rego"))
	if err != nil {
		return fmt.Errorf("glob policy dir: %w", err)
	}
	if len(regoFiles) == 0 {
		return fmt.Errorf("no .rego files in %s", e.policyDir)
	}

	var dataFiles []string
	for _, pattern := range []string{"*.json", "*.yaml", "*.yml"} {
		matches, err := filepath.Glob(filepath.Join(e.policyDir, pattern))
		if err != nil {
			return fmt.Errorf("glob policy dir: %w", err)
		}
		dataFiles = append(dataFiles, matches...)
	}

	loadPaths := append(append([]string{}, regoFiles...), dataFiles...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pq, err := rego.New(
		rego.Query("data.gate.deny"),
		rego.Load(loadPaths, nil),
	).PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("compile policies: %w", err)
	}

	e.mu.Lock()
	e.query = pq
	e.mu.Unlock()

	return nil
}

// --- OPA output parsing ---

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

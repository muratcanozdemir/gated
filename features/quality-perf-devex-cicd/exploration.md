# Codebase Exploration: Code Quality, Performance, DevEx & CI/CD

**Generated:** 2026-08-24 22:50
**Feature:** Audit `gated` for code-quality issues, performance opportunities, and developer-experience friction, and design a GitHub Actions CI/CD pipeline that fits the existing toolchain.

## Existing Build/Test/Lint Tooling (mandatory baseline scope)

**Makefile** (`Makefile`, 87 lines) — targets and exact behavior:

| Target | Command | Notes |
|---|---|---|
| `build` | `go build $(GOFLAGS) -o gated ./cmd/gated` | `GOFLAGS := -trimpath -ldflags="-s -w -X main.version=... -X main.commit=... -X main.buildDate=..."`, version from `git describe --tags --always --dirty` |
| `build-all` | `build-linux build-darwin build-windows` | |
| `build-linux` | `GOOS=linux GOARCH=amd64\|arm64 go build ...` | no CGO needed |
| `build-darwin` | `GOOS=darwin GOARCH=amd64\|arm64 CGO_ENABLED=1 go build ...` | **requires CGO** — `internal/watcher/watcher_darwin.go` uses `import "C"` + `#cgo LDFLAGS: -framework CoreServices`. No `cgo` build constraint on the file, so a plain `GOOS=darwin CGO_ENABLED=0 go build ./...` silently drops it and fails with `undefined: watcher.New` (confirmed). Darwin builds need a macOS runner or osxcross — cannot cross-compile from a bare Linux CI runner. |
| `build-windows` | `GOOS=windows GOARCH=amd64 go build ...` | builds fine, but watcher is a functional stub (returns error at runtime, not build time) |
| `test` | `go test ./... -v -race -count=1` | race detector always on |
| `vet` | `go vet ./...` | passes clean today |
| `lint` | `staticcheck ./...` if installed, else prints "skipping" and **exits 0** | no config file, soft-fails silently if staticcheck absent; depends on `vet` |
| `tidy` | `go mod tidy` | |
| `validate` | build then `./gated -config configs/config.example.yaml -validate` | exercises config load + `opa check` on `policy/` |
| `check` | `build validate vet` | closest thing to an existing CI gate — **does NOT include `test` or `lint`** |
| `install` / `install-config` / `install-systemd` / `install-tools` | — | deployment targets, not CI-relevant except `install-tools` → `scripts/install-tools.sh` |

**go.mod**: module `github.com/internal/gate-daemon` (placeholder path — also baked into systemd unit `Documentation=` fields), `go 1.23`. Tiny dependency surface: `golang.org/x/sys v0.29.0`, `gopkg.in/yaml.v3 v3.0.1`. No `.go-version` file — CI should use `go-version-file: go.mod` with `actions/setup-go`.

**External tool installers** (`scripts/install-tools.sh`, `scripts/install-user.sh`): both pin identical versions (`syft 1.20.0`, `grype 0.87.0`, `osv-scanner 1.9.1`, `opa 1.4.2`), installed via `curl` + GitHub release download (no `go install`, no package manager), overridable via env vars. **Only `opa` is required for `make validate`/`make check`/`make test`** — syft/grype/osv-scanner are runtime scan tools, not needed for build/vet/test/policy-validate. `install-tools.sh` defaults to `/usr/local/bin` (needs root) — a CI job should override `INSTALL_DIR` to something on `PATH` without sudo, and skip `grype db update` (network-heavy) since it's not needed for validate/test.

**Lint config**: **none exists** — no `.golangci.yml`, no staticcheck config. `make lint` is unconfigured `go vet` + optional bare staticcheck.

**gofmt**: not run anywhere in Makefile/scripts. `gofmt -l .` currently flags **7 files**: `internal/quarantine/quarantine.go`, `internal/resolver/resolver_test.go`, `internal/scanner/orchestrator.go`, `internal/scanner/tools.go`, `internal/verdict/cache.go`, `internal/watcher/watcher_iface.go`, `internal/watcher/watcher_windows.go`. A CI `gofmt -l` check would fail immediately on current `main` until these are reformatted.

**Tests**: only 2 test files exist, both stdlib-only, table-driven: `internal/quarantine/quarantine_test.go` (5 tests) and `internal/resolver/resolver_test.go` (7 tests). No tests for `config`, `scanner`, `verdict`, `watcher`, or `policy`. No coverage flags/reporting anywhere.

**Policy validation**: no standalone `make validate-policies`; validation is `opa check` invoked indirectly via `gated -validate` → `internal/policy/engine.go` `ValidatePolicies()`.

**LICENSE**: MIT (README says Apache-2.0 in one spot — worth reconciling, but not confirmed as a real discrepancy vs. stale doc).

### Gaps a CI pipeline needs to fill
1. No `.github/` directory exists at all — confirmed, building from scratch.
2. No lint config — decide: match repo convention (bare `go vet`) or introduce `golangci-lint` with a config.
3. No gofmt/goimports check, and 7 files currently fail one.
4. No coverage collection/reporting.
5. `make check` excludes `test` and `lint` — CI needs to call these explicitly.
6. staticcheck isn't installed/vendored/pinned anywhere.
7. Darwin leg of `build-all` needs a macOS runner, can't share a job with linux/windows.
8. go.mod pins `go 1.23`; no `.go-version` file, use `go-version-file: go.mod`.

## Code Quality

### internal/config (`config.go`)
Clean, consistent `%w` error wrapping. `expandPath` (`~`/env expansion) is applied to `WatchPaths`/`PolicyDir`/`VerdictDir` but **not** to `Tools.*` binary paths (config.go:60-64) — inconsistency, a configured `~/bin/syft` would silently fail to resolve. No validation of `ScanTimeout > 0` or `watcher_mode` value at load time (bad value silently coerced to `auto` deep in `watcher.New` with only a warn log). No tests.

### internal/policy (`engine.go`)
- `exec.LookPath` error discarded, message only prints the binary name, not the real cause (engine.go:28-30).
- Inconsistent `%w`/`%s`: `opa eval` error path uses `%s` (line 74, breaks `errors.Is/As`), `opa check` error drops `err` entirely and only surfaces stderr text (line 116).
- `Evaluate` has a 10s timeout; `ValidatePolicies` has **no timeout** — a hung `opa check` blocks startup/SIGHUP-reload indefinitely, inconsistent with `Evaluate`.
- No tests.

### internal/quarantine (`quarantine.go`, tested)
- Correct double-checked-locking concurrency (`RWMutex`, `-race` genuinely exercised here).
- **`PruneSeen` is never called anywhere outside tests** — `Engine.seen` grows unboundedly for the process lifetime under quarantine mode (inotify/darwin). Contrast: `verdict.Cache.PruneOlderThan` *is* wired into a periodic goroutine in `main.go`. Real unbounded-memory-growth risk for long-running daemons on high-churn caches.
- `os.Remove(holdPath)` return value discarded/unlogged on the deny path (line 132) — silent orphaned file on removal failure.
- gofmt-unclean (const alignment).

### internal/resolver (`resolver.go`, tested)
Cleanest package — pure functions, no I/O, no concurrency. `resolveNPM`'s "unknown"/"unknown" sentinel for content-addressed cache paths is checked by string comparison elsewhere (`scanner/tools.go:221`) — a stringly-typed contract that'd be more robust as an explicit `Resolved bool`.

### internal/scanner (`orchestrator.go`, `tools.go`)
- **Fragile exit-code handling**: grype and osv-scanner both use heuristics instead of checking `exec.ExitError.ExitCode()` — grype checks whether stderr contains the substring `"vulnerability"` (tools.go:96-101), osv-scanner checks whether stdout is empty (tools.go:171-176). A genuine tool failure whose stderr happens to match the heuristic is silently treated as success with an empty result.
- Inconsistent `%w`/`%s` wrapping within the same function shape across all three tool runners (tools.go:50,99,174 vs. their own JSON-parse error paths two lines below, which correctly use `%w`).
- **`Orchestrator.Scan`'s `error` return is dead** — every failure path populates `result.Errors []string` and continues; the function always returns `(result, nil)`. `main.go`'s `if err != nil` check on `Scan()` can never be true — downstream policy evaluation can silently run against an empty/partial scan with no error signal, only a warn log.
- No tests despite being the most subprocess/parsing-dependent package.

### internal/verdict (`cache.go`)
- **Doc/implementation mismatch**: struct comment says entries are "keyed by file content hash" (cache.go:30), but `hashPath` actually hashes the **file path string**, not content (cache.go:199-202). A file replaced with different bytes at the same path returns the stale verdict without rescanning — meaningful for a security-gating cache, may be intentional given package caches are usually immutable-per-version but worth confirming.
- Correct `RWMutex` + pending-channel handoff pattern for dedup'd concurrent lookups, but **no test file** — the one package with the most subtle concurrency is completely untested, so `-race` never exercises it.
- **Leak risk**: if the caller panics after `MarkPending` but before `Store`, the pending channel is never closed and all subsequent `Lookup`s for that path block forever; no `recover()` safety net in `main.go`'s decision closure.
- `os.Remove` return values discarded in `Invalidate`/`InvalidateAll`/`PruneOlderThan` (cache.go:125,136,216).

### internal/watcher (5 files, largest package, most duplication)
- Build tags used correctly per-platform.
- **~70 lines of verbatim duplicated logic** between `watcher_linux_fanotify.go` and `watcher_darwin.go`: `isMetadataFile`, `isArtifactFile` (identical, ~35 lines), `resolveEcosystem` (identical prefix-match logic), and the "stat watch path, warn+MkdirAll" block duplicated between fanotify and inotify constructors. All fixable by hoisting into a shared no-build-tag file.
- **Reinvents `golang.org/x/sys/unix`**: hand-defines fanotify constants and manually byte-parses `fanotifyEventMetadata` via `binary.LittleEndian` (watcher_linux_fanotify.go:19-45,106-137) even though the already-imported `unix` package exports `unix.FAN_OPEN_PERM`, `unix.FanotifyEventMetadata`, etc. Manual parsing carries real risk on unusual architectures.
- **Inconsistent `Close()` idempotency**: `InotifyQuarantineWatcher.Close()` guards against double-close; `FanotifyWatcher.Close()` and `DarwinWatcher.Close()` do not — a second call would panic (darwin, closed channel) or return unhandled `EBADF` (fanotify). Currently masked because `main.go` calls `w.Close()` then `os.Exit(0)` immediately, but fragile against future shutdown-sequence refactors.
- `watcher_darwin.go` has no `cgo` build constraint (see build-tooling section above).
- No tests for this package at all (syscall/cgo-dependent, understandably hard to test, but zero strategy documented).

### cmd/gated/main.go
- Consistent, deliberate **fail-open design**: every error branch (scan failure, marshal failure, policy-eval failure, cache-wait timeout) resolves to `Allowed: true`, logged via `slog`, recorded in the verdict cache's `Reasons` — an explicit security/availability tradeoff, not an accidental swallow.
- `decisionFn` closure (~95 lines) constructs an almost-identical `verdict.Entry{...}` literal **5 separate times** — candidate for a small `storeAllow`/`storeResult` helper.
- `defer w.Close()` is effectively dead code — every real exit path uses `os.Exit`, which skips deferred calls.
- Consistent, idiomatic structured `slog` logging throughout.

### Cross-cutting quality patterns
- **Good**: fail-open + structured logging applied uniformly across every subsystem — deliberate design principle.
- **Problem**: `%w` wrapping applied ~80% of the time, consistently breaks down specifically where subprocess stderr is combined into an error message (`scanner/tools.go` 3x, `policy/engine.go` 2x).
- **Problem**: gofmt not run pre-commit — 7 files currently unformatted, no CI/pre-commit gate exists.
- **Problem**: test coverage is inversely correlated with risk — the two tested packages (`resolver`, `quarantine`) have no concurrency; the three highest-risk packages (`verdict`'s pending-channel cache, `scanner`'s subprocess exit-code heuristics, `watcher`'s goroutine-per-event/cgo) have zero tests.
- **Problem**: recurring "reinvent instead of reuse" in `internal/watcher` (manual fanotify constants/parsing duplicating `x/sys/unix`, plus copy-pasted helpers between Linux/Darwin backends).
- **Two prioritizable swallowed-error clusters**: discarded `os.Remove` results (`quarantine.go:132`, `verdict/cache.go:125,136,216`), and the never-called `quarantine.Engine.PruneSeen` (genuine unbounded memory growth in quarantine mode).

## Performance

gated sits synchronously in the install critical path (fanotify mode literally freezes the calling process in-kernel), so per-decision latency matters directly.

### Verdict cache (`internal/verdict/cache.go`) — mostly well-optimized
- `RWMutex` (not plain `Mutex`) — concurrent lookups don't block each other.
- Disk persistence is async (`go c.saveToDisk(...)` after the in-memory `Store`) — off the hot path.
- Cache key construction is a single `sha256.Sum256` + one `Sprintf` — no per-call allocation churn.
- **Stands out**: `PruneOlderThan` (runs hourly via `main.go`) and `InvalidateAll` (runs on SIGHUP) both hold the **full write lock for an O(n) walk of the entire cache plus synchronous `os.Remove` per expired entry inside the loop** — the one place a maintenance operation can stall every live `Lookup`/`Store`/`MarkPending` (i.e., every in-flight install) for a long-running daemon with a large verdict cache.

### Watcher hot path (fanotify/inotify)
- Metadata-file filtering, self-PID short-circuiting, and fire-and-forget goroutine dispatch (`go w.decisionFn(...)`) are all already in place and correctly keep the event loop unblocked.
- **Stands out**: `readComm(event.Pid)` does a synchronous `os.ReadFile("/proc/%d/comm")` **unconditionally, purely to populate a log line** — runs on every intercepted `FAN_OPEN_PERM` event regardless of log level, adding a blocking procfs read to the critical path (i.e., before the frozen process is unfrozen) for no functional benefit.
- `resolveEcosystem`'s O(n) prefix-match over watch paths is negligible in practice (typical configs have ~5 entries).
- The dominant cost is not the watcher itself — it's the synchronous scanner+policy pipeline invoked inline on a cache miss (see below), during which the process stays frozen in fanotify mode.

### Scanner orchestration (`internal/scanner/orchestrator.go`, `tools.go`) — largest opportunity
- **syft, grype, and osv-scanner run strictly sequentially**, each fully awaited before the next starts. They're independent subprocess calls against the same artifact — running them concurrently (goroutines + errgroup/WaitGroup) would cut wall-clock from `sum(syft,grype,osv)` to roughly `max(syft,grype,osv)`.
- **Redundant parsing**: grype is invoked directly against the artifact path rather than being fed the SBOM syft already generated (grype supports consuming a syft SBOM as input) — the artifact is parsed twice from scratch.
- Timeout is one shared `context.WithTimeout` covering all three sequential calls — `scan_timeout_seconds` is a combined budget, not per-tool; a slow syft eats into grype/osv's time. Parallelizing would also make the timeout semantics more sensible (budget applies to the slowest single tool, not the sum).
- Each tool invocation is a fresh `exec.CommandContext` (full fork/exec per artifact) — inherent to shelling out; switching to syft/grype's importable Go libraries would eliminate this entirely if it matters at scale, but is a much larger change than parallelizing the existing subprocess calls.

### Policy evaluation (`internal/policy/engine.go`) — second-largest opportunity
- **Shells out to the `opa` CLI binary on every single evaluation**, passing `--data <policyDir>` each time — this means the entire rego bundle is **recompiled from disk on every package-install decision**. OPA's Go SDK (`github.com/open-policy-agent/opa/rego`) supports `PrepareForEval` once + `PreparedEvalQuery.Eval` reused per call, which would eliminate both the process-spawn cost and the recompilation cost from the hot path.
- Synchronous temp-file write/read used purely as IPC to hand input to `opa eval --input` (three synchronous filesystem ops per decision) — the Go SDK would let input be passed in-process instead.
- SIGHUP reload currently does real work only for `ValidatePolicies` (a separate `opa check` subprocess) + cache invalidation — there's no actual compiled-policy state for reload to refresh, since nothing is precompiled today. Switching to the Go SDK would give SIGHUP a real purpose (recompile once, reuse until next reload).

### Resolver
No concerns — pure string/path manipulation, negligible cost.

### Highest-leverage opportunities (ranked)
1. Parallelize scanner subprocess execution (`orchestrator.go`) — biggest win, gated freezes the installing process for this entire duration in fanotify mode.
2. Replace OPA CLI subprocess with OPA's Go SDK + prepared/reused query (`policy/engine.go`) — likely the highest per-call fixed cost in the whole pipeline; also gives SIGHUP reload real teeth.
3. Feed syft's SBOM into grype instead of re-parsing the artifact independently.
4. Make `PruneOlderThan`/`InvalidateAll` not hold the full lock for the whole O(n) walk + synchronous deletes (`verdict/cache.go`).
5. Drop the unconditional `readComm` procfs read from the fanotify critical path — it exists solely for a log line.

## DevEx / Onboarding Friction

### Getting started today
- README's quick-start clone URL (`github.com/internal/gate-daemon`) is a placeholder — matches `go.mod`'s module path and all three systemd units' `Documentation=` fields, but isn't a real clonable repo; every doc pointer is dead for an actual new contributor.
- `./scripts/install-user.sh` is otherwise a genuinely complete, idempotent, no-root path: builds the binary (or pulls from Artifactory if configured), installs all four scan tools with version pins, warms the grype DB, installs config+policies+systemd unit, and ends by running `gated -validate` and printing the next commands.
- The README's alternative path (`make build` then run directly) **skips scan-tool installation** — the daemon then fails at `policy.NewEngine` (missing `opa`) and at scan time (missing syft/grype/osv-scanner), since `config.user.yaml` points at `~/.local/bin/{syft,grype,osv-scanner,opa}`.
- Verified: `make check` in a fresh environment with no tools installed fails cleanly and fast with `opa binary not found: opa`, but doesn't point the developer at the install scripts as the fix.
- `make test` runs with zero privileges/network/external tools in ~2s and passes cleanly.

### Friction points
- Placeholder clone URL baked into README, go.mod, and all 3 systemd unit `Documentation=` fields.
- No CI at all — confirmed no `.github/` directory, no automated gate on PRs.
- gofmt drift is silent (not run anywhere, 7 files currently fail).
- Zero test coverage for `watcher` (needs root/CAP_SYS_ADMIN or cgo — no documented mocking/integration strategy), and for `scanner`/`verdict`/`config`/`policy`.
- **Two conflicting build paths**: `Makefile` injects version via ldflags (`-X main.version=$(VERSION)...`); `install-user.sh`'s fallback source-build uses a hardcoded `-ldflags="-s -w"` with no version injection — a contributor using only `install-user.sh` gets a binary reporting `gated dev (commit=unknown, ...)`.
- **No git tags exist** in the repo — `VERSION` falls back to an abbreviated commit hash rather than the `v0.3.0`-style semver the README's own examples and Artifactory layout assume; no documented tagging/release process anywhere.
- No CHANGELOG, no CONTRIBUTING.md, no `docs/` folder.
- `make install-systemd` only installs `gated.service` — the other two documented units (`gated-unprivileged.service`, `gated-user.service`) require manual `cp`/`install`, with no error or pointer.
- `gated-unprivileged.service` assumes a `gated` system user/group that nothing in the repo creates (`useradd`/`groupadd` absent everywhere); also has a manual `ReadWritePaths=/home` adjustment noted in-file but easy to miss.
- Config validation is shallow: only checks `watch_paths` non-empty; doesn't validate `watcher_mode` (bad value silently coerced with a warn log, not a startup error), `scan_timeout_seconds > 0`, or that `tools.*` binaries exist (deferred to first-use failure).
- `build-windows` "succeeds" but produces a non-functional binary — the real failure only surfaces at runtime (`watcher.New()` returns an error), not at build time; only an inline Makefile `@echo` warns about this.

### What's already good
- `install-user.sh` — complete, idempotent, well-sequenced no-root onboarding script.
- Actionable error messages where they do fire (`opa binary not found: %s`, `policy dir: %w`, `read config: %w`).
- Windows-stub error is a standout: explains *why* it's unsupported and points at the three documented implementation strategies in the same file's comments, rather than a bare "not implemented."
- Two example configs (`config.example.yaml`, `config.user.yaml`) are well-commented, minimal, clearly scoped ("no root required" header on the user config).
- `make test` is fast, self-contained, and what exists is high quality (table-driven, uses `t.TempDir()`).
- Fail-open design is consistently applied and logged — good for local debugging, daemon never crashes or blocks on scan/policy failures.
- SIGHUP reload is safe by construction — re-validates policies before invalidating cache, keeps old policies on parse failure.
- `gated -version` and `-validate` flags give a fast local sanity-check loop.

## Cross-Cutting Patterns

- **No CI/CD exists today** — this is a from-scratch build, not a port of an existing config. The natural CI jobs map directly onto existing Makefile targets (`build`, `test`, `vet`, `validate`) plus two new checks the repo doesn't have yet (`gofmt -l`, and a build matrix that isolates the darwin/CGO leg onto a macOS runner).
- **`gofmt` drift and missing lint config are the fastest wins** — surfaced independently by both the quality and tooling agents; fixing the 7 files and deciding on a lint policy (bare `vet` vs. `golangci-lint`) should happen before/alongside adding a CI gate, since a naive `gofmt -l` check would fail immediately on current `main`.
- **Fail-open is a deliberate, load-bearing design principle**, observed consistently across `main.go`, `scanner`, `policy`, and `quarantine` — any quality/performance change should preserve it rather than "fixing" it into fail-closed behavior, since that would change gated's availability guarantees.
- **Concurrency-heavy code is exactly the code with zero test coverage** (`verdict`, `scanner`, `watcher`) — `-race` in `make test` is currently only exercised by the two simplest packages (`quarantine`, `resolver`). A CI pipeline enabling `-race` doesn't get real value until these packages have tests.
- **Performance and quality findings overlap in `internal/policy` and `internal/scanner`**: the same "shell out to CLI tools synchronously/sequentially" pattern that fragments error handling (exit-code heuristics, `%s` vs `%w`) is also the top two performance opportunities (parallelize scanners, replace OPA CLI with Go SDK) — addressing the performance issue would likely also clean up the fragile error-handling paths in the same functions.
- **DevEx and CI are linked**: the placeholder clone URL, missing git tags, and dual build-flag paths (Makefile vs. install-user.sh) all affect what a CI-produced release artifact should look like — CI/release tooling should standardize on the Makefile's ldflags injection and could be the natural place to introduce real semver tagging.

# gated

Supply chain gate daemon. Intercepts package manager installs at the OS level,
scans artifacts with syft and grype, evaluates OPA policies, and blocks
packages that violate license, vulnerability, or provenance rules.

No wrappers. No symlinks. No devcontainer. One binary, any ecosystem.

## How it works

```
pip install requests
    │
    ▼
 [pip downloads wheel to ~/.cache/uv/...]
    │
    ▼
 [gated intercepts the file operation]
    │
    ├─ verdict cache hit → allow / deny immediately
    │
    └─ cache miss → resolve package identity from path
                  → unpack (wheels, sdists, npm tarballs, crates; jars as is)
                  → syft (SBOM + license) + grype (vulns: the bytes, and the package URL)
                  → OPA policy evaluation
                  → cache verdict
                  → allow / deny
    │
    ▼
 [pip continues or fails]
```

## Visualisation
<img src="./gated.svg">

The interception mechanism adapts to the platform and available privileges:

| Mode | Platform | Mechanism | Privileges | Guarantee |
|------|----------|-----------|------------|-----------|
| `fanotify` | Linux | Kernel permission events | `CAP_SYS_ADMIN` | Synchronous. Process frozen in kernel space. Zero race window. |
| `quarantine` | Linux, macOS | inotify/FSEvents + atomic rename | None | Near-synchronous. File quarantined before package manager reads it. |

On Linux with `watcher_mode: auto` (default), gated probes for fanotify capability
at startup and falls back to inotify+quarantine transparently. Same binary, same
policies, same scans.

### Racing the package manager (quarantine mode)

In quarantine mode gated learns of a download only after it lands, so it races
the package manager. Usually it wins: the file is moved aside before anything
reads it. Some package managers cannot lose an artifact, though, so gated judges
it **in place** instead: it scans it where it lies and never holds it.

| Package manager | Gated in place | On a deny, gated removes |
|---|---|---|
| go | the module zip in `cache/download` (go unpacks it at once) | the zip, its `.ziphash` and the unpacked module |
| uv | the unpacked wheel in `archive-v0/<id>/` (uv never writes a `.whl`) | that directory |
| bun | the unpacked package in `[@scope/]<name>@<version>@@@1/` (bun links it into `node_modules` at once) | that directory and bun's `<name>/<version>@@@1` link to it |
| yarn (2+) | the package zip, `<name>-npm-<version>-<hash>-<key>.zip` (yarn opens it at once) | the zip |
| yarn classic (1.x) | the unpacked package in `v6/npm-<name>-<version>-<sha1>-integrity/`, once yarn writes its `.yarn-metadata.json` | that directory |

Removing these means the next install fetches the package again, and gated
denies it from its verdict cache before anything unpacks it. A retried `go mod
download` of a denied module fails, and so does a retried yarn classic install:
gated removes the package while yarn is still linking it. Under yarn's
Plug'n'Play the project runs from the cache zips, so a denied package is gone
for it ("Required package missing from disk"). What the package manager already
did with the package in the first run is otherwise out of gated's reach: uv and
bun have installed it, go may have built with it. The same goes for a held file
that the package manager had already opened.

When gated loses like this, it says so **in the package manager's own output**,
where the person or CI job running it will see it:

```
$ uv pip install urllib3==1.26.4
 + urllib3==1.26.4

gated: urllib3@1.26.4 DENIED
gated:   - fixable high-severity vulnerability GHSA-v845-jxx5-vc9f in urllib3@1.26.4 — upgrade to 1.26.17
gated: uv (pid 4242) unpacked it before gated could stop it. gated removed it from the cache, but whatever this run built or installed from it stays: remove that, then rerun.
```

gated finds the package manager as the process that has files open in the cache
when the package arrives, or just before. Fast installers can be done within
milliseconds, so gated looks for one as soon as anything changes in the cache. It
opens that process's stderr (`/proc/<pid>/fd/2`, append-only), so the warning
gets through even after the process has exited. This works on Linux for processes
gated may inspect: your own (user service) or anyone's (as root). Elsewhere the
lost race appears in gated's log only, and so it does for yarn 2+, which keeps no
file open in its cache for more than a millisecond: there is no process to find. In `warn_only` mode the same message says
the package *would be* denied.

Holding a process's stderr has a cost when it is a pipe (`uv pip install … | tee`,
`$(go …)`, an IDE running go): the reader gets no end-of-file while gated holds the
pipe. So gated holds it only while the process is running, for half a second after
it was last seen, or while a verdict from that cache is pending. In practice a
piped install ends at most as late as its slowest pending scan.

## Quick start

### Developer workstation (no root)

```bash
git clone https://github.com/muratcanozdemir/gated.git
cd gated

# Install scan tools to ~/.local/bin.
./scripts/install-user.sh

# Or build and install manually:
make build
./gated -config configs/config.user.yaml
```

### System-wide (CI runners, shared build machines)

```bash
make build
sudo make install
sudo make install-config
sudo make install-systemd

# Edit watch paths and policy directory.
sudo vim /etc/gated/config.yaml

# Start.
sudo systemctl enable --now gated
sudo journalctl -u gated -f
```

## Build

```bash
make build             # native platform
make build-all         # linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64
make test              # unit tests with race detector
make lint              # golangci-lint, incl. modernize (the go fix analyzers)
make fix               # apply go fix
make check             # build + validate policies + vet + policy tests
make policy-test       # opa fmt/check/test on policy/ (same OPA version the daemon embeds)
make snapshot          # GoReleaser dry run into dist/ (this host's OS family)
make tidy              # go mod tidy
```

Version is injected at build time via `-ldflags`:

```bash
./gated -version
# gated 1.0.0 (commit=a1b2c3d, built=2026-05-09T20:00:00Z, linux/amd64)
```

## Releases

Releases are cut by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org/) on `main`: it
keeps a release PR open with the next version and `CHANGELOG.md`; merging it tags
`vX.Y.Z` and creates the GitHub release. `.github/workflows/release.yml` then
builds every platform with [GoReleaser](https://goreleaser.com) (darwin on a macOS
runner, since the FSEvents watcher needs cgo) and attaches to the release:

| Asset | Contents |
|-------|----------|
| `gated_X.Y.Z_OS_ARCH.tar.gz` (`.zip` on Windows) | binary, LICENSE, README, CHANGELOG, example config, systemd units |
| `gated_X.Y.Z_OS_ARCH.cdx.json` | CycloneDX SBOM of the binary |
| `gated-policy_X.Y.Z.tar.gz` | policy bundle: `policy/*.rego` (no tests) + `data.json` |
| `*.provenance.sigstore.json`, `*.sbom.sigstore.json` | SLSA provenance / SBOM attestations |
| `SHA256SUMS` | checksums of the archives, SBOMs and policy bundle |

Verify a download:

```bash
gh attestation verify gated_1.0.0_linux_amd64.tar.gz --repo muratcanozdemir/gated
```

## Configuration

Two example configs are provided:

| File | Use case |
|------|----------|
| `configs/config.example.yaml` | System-wide, fanotify or auto mode |
| `configs/config.user.yaml` | Developer workstation, quarantine mode, everything under `$HOME` |

Key settings:

```yaml
watcher_mode: auto          # auto | fanotify | quarantine
warn_only: true             # log denials but allow everything (rollout mode)
scan_timeout_seconds: 30    # kill scans that hang
```

### Watch paths

Each entry maps a filesystem path to a package ecosystem:

```yaml
watch_paths:
  - path: ~/.cache/uv
    ecosystem: pypi
  - path: ~/go/pkg/mod/cache
    ecosystem: go
  - path: ~/.m2/repository
    ecosystem: maven
  - path: ~/.cargo/registry
    ecosystem: cargo
  - path: ~/.bun/install/cache     # bun
    ecosystem: npm
  - path: ~/.yarn/berry/cache      # yarn 2+ (global cache, the default)
    ecosystem: npm
  - path: ~/.cache/yarn            # yarn classic
    ecosystem: npm
```

bun and both yarns install from the npm registry, so their caches use the `npm`
ecosystem; gated tells them apart by the cache's layout. A project that sets
`enableGlobalCache: false` keeps its yarn cache in `.yarn/cache`: watch that
instead.

### Ecosystem support

| Ecosystem | Cache artifacts resolved | PURL format |
|-----------|------------------------|-------------|
| PyPI | `.whl`, `.tar.gz`; uv's `archive-v0/<id>/`, gated in place | `pkg:pypi/name@version` |
| Go | `@v/*.zip`, gated in place | `pkg:golang/module@version` |
| Maven | `*.jar` | `pkg:maven/group/artifact@version` |
| Cargo | `*.crate` | `pkg:cargo/name@version` |
| npm | `*.tgz` (best-effort; scoped names read from the tarball's `package.json`); bun's, yarn's and yarn classic's caches, gated in place | `pkg:npm/name@version` |

npm's content-addressed cache (`_cacache`) makes path-based resolution unreliable.
For full npm coverage, watch `node_modules/` instead.

yarn zips of anything but a registry package (`patch:`, as yarn applies to
typescript, and `git:`, `file:` or tarball dependencies) are neither judged nor
held; neither are bun's entries for git or tarball dependencies, whose
`package.json` does not match the cache entry's name. pnpm is not supported yet:
its store keeps no file per package, only content-addressed single files and a
SQLite index.

## Policies

Policies are OPA Rego files in the `policy/` directory. They share a common
interface: any rule producing a string in `data.gate.deny` causes the package
to be blocked. `common.rego` holds the shared helpers; it reads the scan result
defensively, so a missing or `null` field (e.g. no licenses because syft failed)
can never make a deny rule silently not fire.

### license.rego

Allowlist-based SPDX enforcement, case-insensitive. Packages with blocked
licenses (AGPL, SSPL, BUSL, Elastic-2.0) are denied. Packages with no detected
license are denied (unknown obligation = unacceptable risk). SPDX expressions
are understood: `MIT OR GPL-3.0-only` passes (you may choose MIT),
`MIT AND GPL-3.0-only` does not; with parentheses every identifier must be
approved (conservative).

### vulnerability.rego

Severity-gated with nuance:

- Critical severity: always denied.
- CVSS ≥ 9.0 (`critical_cvss`): denied whatever the scanner's severity label.
- High severity + fix available: denied (upgrade available, no excuse).
- Known exploited (CISA KEV): denied at any severity.
- EPSS ≥ `epss_threshold` (off unless set, e.g. `0.5`): denied as likely to be
  exploited soon.
- More distinct vulnerability IDs than `max_total_vulnerabilities`: denied (a
  CVE reported by both the byte scan and the package URL lookup counts once).

A vulnerability is often in a dependency inside the package rather than the
package itself: a module its `go.mod` requires, a library bundled in its jar.
The message then names the dependency, and the fix version is the
dependency's:

```
fixable high-severity vulnerability GO-2026-6860 in golang.org/x/net@v0.59.0
  (a dependency of golang.org/x/tools/gopls@v0.24.0) — upgrade golang.org/x/net to 0.62.0
```

The package may have no release with the fixed dependency yet (here gopls
v0.24.0 is the latest); a waiver is then the way to install it. Files a package
carries but nobody who installs it runs are not matched: its own CI workflows
and the GitHub Actions they use (`.github/workflows`).

Exploitation data is live: grype's vulnerability DB carries CISA KEV and FIRST
EPSS (grype ≥ 0.88; `install-tools.sh` pins 0.122.1), grype refreshes it on its
own, and gated passes it to the policy for each vulnerability, including the CVE
behind a GHSA. There is no CVE list to maintain. `known_exploited_cves` in
`data.json` is only for extra IDs of your own; it is empty by default. Keep the
grype DB fresh: grype refuses to scan with a DB older than 5 days, and a failed
scan fails open (or is denied with `require_clean_scan`).

#### Waivers

Accept a vulnerability for a while with a waiver in `vulnerability_waivers`,
keyed by vulnerability ID. Ready-to-merge files for the examples below, with
the steps to add one, are in [`docs/examples`](https://github.com/muratcanozdemir/gated/tree/main/docs/examples).

```json
"vulnerability_waivers": {
  "CVE-2024-0001": {
    "reason": "not reachable: we never parse untrusted YAML (SEC-123)",
    "expires": "2027-01-31",
    "packages": ["pypi/pyyaml"]
  }
}
```

| Field | Required | Meaning |
|-------|----------|---------|
| `reason` | no, but write one | Why the risk is accepted; for the next reader, not checked. |
| `expires` | yes | `YYYY-MM-DD`, UTC, exclusive: `2027-01-31` waives up to the end of 2027-01-30. |
| `packages` | no | `<ecosystem>/<name>` of the packages it applies to; without it, every package. |

- Every waiver must expire. Expired, undated or misdated waivers are ignored
  (the vulnerability is denied again) and logged as warnings at startup, on
  reload and by `gated -validate`.
- The key matches the vulnerability's ID or any of its aliases, both ways: a
  waiver keyed by a CVE covers the same vulnerability reported under a GHSA
  ID, and one keyed by a GHSA covers it reported as the CVE.
- `packages` entries use ecosystems `pypi`, `npm`, `go`, `cargo`, `maven`.
  Maven names are `groupId:artifactId`; npm scoped names keep their scope
  (`npm/@babel/traverse`). Names are compared in canonical form, so
  `pypi/PyYAML` and `pypi/pyyaml` are the same.
- For a vulnerability in a dependency, the entry is still the package being
  installed, the one that carries it, not the dependency.
- A waived vulnerability no longer counts towards `max_total_vulnerabilities`.
  Waivers touch only the vulnerability rules: a denied license or a blocked
  package stays denied.
- One key per ID: a vulnerability cannot have two waivers with different
  dates. List every package under one waiver and give it the later date.

##### Example: one package, one vulnerability

`npm install @babel/traverse@7.22.0` is denied for CVE-2023-45133, which grype
may report under its GHSA ID. Waive the CVE for that package only:

```json
"vulnerability_waivers": {
  "CVE-2023-45133": {
    "reason": "build-time only, never compiles untrusted code; upgrade in PLAT-88",
    "expires": "2027-01-31",
    "packages": ["npm/@babel/traverse"]
  }
}
```

`@babel/core` and every other package are still denied for it.

##### Example: several waivers, several ecosystems

Each ID is its own entry; a Maven package is named `groupId:artifactId`:

```json
"vulnerability_waivers": {
  "CVE-2024-0001": {
    "reason": "not reachable: we never parse untrusted YAML (SEC-123)",
    "expires": "2027-01-31",
    "packages": ["pypi/pyyaml"]
  },
  "GHSA-7rjr-3q55-vv33": {
    "reason": "only in the offline report tool, which logs no untrusted input; jar replaced in OPS-412",
    "expires": "2027-03-15",
    "packages": ["maven/org.apache.logging.log4j:log4j-core"]
  },
  "CVE-2025-9999": {
    "reason": "disputed by upstream, NVD reanalysis pending",
    "expires": "2027-02-28"
  }
}
```

The last one has no `packages`, so it applies to every package that reports
it. Keep those rare and short: they hide the vulnerability everywhere.

##### Example: waiving a dependency's vulnerability

`go install golang.org/x/tools/gopls@latest` is denied:

```
gated: golang.org/x/tools/gopls@v0.24.0 DENIED
gated:   - fixable high-severity vulnerability GO-2026-6860 in golang.org/x/net@v0.59.0
           (a dependency of golang.org/x/tools/gopls@v0.24.0) — upgrade golang.org/x/net to 0.62.0
```

No gopls release requires a fixed x/net yet. Waive the ID for gopls only, until
a date by which a release should be out. The modules gopls itself requires are
gated one by one as `go` downloads them, so a waiver may need the same ID for
those too (here `golang.org/x/tools`). Add every ID from the denial at once:

```json
"vulnerability_waivers": {
  "GO-2026-6860": {
    "reason": "gopls v0.24.0 (latest) requires golang.org/x/net v0.59.0; drop once a gopls release requires >= 0.62.0",
    "expires": "2027-01-31",
    "packages": ["go/golang.org/x/tools/gopls", "go/golang.org/x/tools"]
  }
}
```

##### Applying and checking waivers

The file is `data.json` in the daemon's `policy_dir`: `/etc/gated/policy` for
the system service, `~/.config/gated/policy` for the user service. gated reads
it only at startup and on reload, so **a waiver does nothing until you reload
the daemon**. Check it, reload, and retry:

```bash
# Check config and policies (and list malformed or expired waivers)
gated -validate -config ~/.config/gated/config.yaml

# Reload the user service (system service: sudo systemctl reload gated)
systemctl --user reload gated
journalctl --user -u gated -n 5 -o cat   # "policy reload complete"

go install golang.org/x/tools/gopls@latest
```

A waiver that does nothing is a warning, not an error, so `-validate` still
prints `config and policies OK`. Look for the warnings above it:

```
{"level":"WARN","msg":"policy configuration","warning":"waiver for CVE-2024-0001 expired on 2026-10-31: ignored"}
{"level":"WARN","msg":"policy configuration","warning":"waiver for CVE-2024-0002 has no valid \"expires\" date (YYYY-MM-DD): ignored"}
config and policies OK
```

Delete the entry once the fix ships, or renew `expires` with a new reason if
it has not.

If the policies do not compile, the reload logs `policy reload validation
failed, keeping old policies` and the daemon keeps running on the old ones.
A reload also empties the verdict cache, so earlier denials are scanned again.

### provenance.rego

Supply chain origin checks:

- Explicit blocklist of known-malicious packages (`blocked_packages`), either
  every version (`"npm/evil": "reason"`) or only compromised releases
  (`"npm/ua-parser-js": {"reason": "...", "versions": ["0.7.29"]}`).
- Typosquats: a name one edit (insertion, deletion, substitution, adjacent
  swap) away from an entry in `popular_packages` is denied, unless listed in
  `typosquat_allowlist`. Names shorter than `typosquat_min_length` are not
  compared.
- Maven `groupId` namespace allowlist and Go module host prefix allowlist,
  matched on a `.` / `/` boundary (`org.apache` approves `org.apache.commons`,
  not `org.apachex`).
- Optional: deny packages where scan tools errored (`require_clean_scan`).

Names are compared in canonical form: PyPI per PEP 503, npm case-insensitive.

### Testing policies

Each policy has Rego unit tests next to it (`*_test.rego`; the daemon skips
them when loading). `make policy-test` runs `opa fmt`, `opa check --strict` and
`opa test` with a coverage gate, using the OPA version from `go.mod`, so the
tests run on the same engine the daemon embeds.

### Tuning

Edit `policy/data.json` to adjust approved licenses, blocked packages, popular
package lists, namespace rules, extra known-exploited CVEs, vulnerability thresholds (CVSS, EPSS) and
waivers. Every knob has a default in `policy/common.rego`, so a `data.json` from
an older release keeps working. After editing, reload:

```bash
# System service
sudo systemctl reload gated

# User service
systemctl --user reload gated

# Manual
kill -HUP $(pidof gated)
```

SIGHUP re-validates policies and invalidates the verdict cache.

## Deployment

### systemd

Three unit files in `init/systemd/`:

| Unit | Runs as | Mode | Use case | Install |
|------|---------|------|----------|---------|
| `gated.service` | root | fanotify | CI runners, shared machines | `sudo make install-systemd` |
| `gated-unprivileged.service` | `gated` (service user) | quarantine | Server, no root desired | `sudo make install-systemd-unprivileged` (also creates the `gated` system user) |
| `gated-user.service` | your UID | quarantine | Developer workstation | handled by `./scripts/install-user.sh` |

### Distribution via Artifactory

Binary to a generic repo, policies as a separate versioned tarball:

```
internal-tools-generic/
├── gated/
│   ├── v1.0.0/
│   │   ├── gated-linux-amd64
│   │   ├── gated-linux-arm64
│   │   ├── gated-darwin-amd64
│   │   ├── gated-darwin-arm64
│   │   └── config.example.yaml
│   └── latest -> v1.0.0
└── gated-policy/
    └── v1.0.0/
        └── policy.tar.gz
```

Policies change independently of the binary — different cadence, different owners.

## Architecture

```
cmd/gated/main.go          Entry point, wiring, signal handling
internal/
├── config/                 YAML config loader with ~ and $ENV expansion
├── watcher/
│   ├── watcher_iface.go          Watcher interface + Config struct
│   ├── watcher_linux_new.go      Auto-detection: fanotify vs inotify
│   ├── watcher_linux_fanotify.go Kernel-enforced synchronous gate
│   ├── watcher_linux_inotify.go  Unprivileged inotify + quarantine
│   ├── watcher_darwin.go         FSEvents + quarantine (CGo)
│   └── watcher_windows.go        Stub (three strategies documented)
├── quarantine/             Atomic rename gating, in-place gating (cross-platform)
├── installer/              Finds the package manager behind an artifact, to warn it
├── resolver/               Path → (ecosystem, name, version) mapping
├── scanner/                Unpacks artifacts, orchestrates syft and grype
├── policy/                 OPA evaluation engine
└── verdict/                Filesystem-backed verdict cache
```

### Design decisions

**fanotify over eBPF.** fanotify permission events provide synchronous allow/deny
without modifying the target process. eBPF `cgroup/connect4` can intercept
connections but can't block-and-resume a file open.

**Quarantine as universal fallback.** Atomic rename works on every OS and needs no
privileges. The race window (file exists briefly before quarantine) rarely matters
for package managers that close a download before opening it for extraction. Those
that unpack at once (go, uv, bun, yarn) are gated in place, and told when gated was too late
(see [Racing the package manager](#racing-the-package-manager-quarantine-mode)).

**Fail open on errors.** If a scan tool crashes or OPA eval fails, the artifact is
allowed. Logged and recorded in the verdict cache for audit. The daemon never
becomes a single point of failure.

**Filesystem verdict cache.** Zero dependencies. In-memory map for sub-microsecond
hot-path lookups, JSON files on disk for persistence across restarts. 24h
auto-pruning.

**SIGHUP policy reload.** Change policies in production without restart. Verdict
cache is invalidated on reload.

## Scan tools

gated shells out to two tools, both Apache-2.0 licensed. Policy evaluation
(OPA/Rego) runs in-process via the OPA Go SDK — no external `opa` binary
required.

| Tool | Purpose | Project |
|------|---------|---------|
| [syft](https://github.com/anchore/syft) | SBOM generation, license detection | Anchore |
| [grype](https://github.com/anchore/grype) | Vulnerability scanning | Anchore |

How an artifact is scanned:

- Archives syft cannot read as a file (wheels, sdists, npm tarballs, crates)
  are unpacked into a temporary directory first, with limits (no entries
  outside it, no links, 50k entries, 1 GiB). Jars are read as files.
- grype scans the bytes (catching libraries bundled inside a jar) and also
  looks the package up by its package URL, e.g. `pkg:pypi/pyyaml@5.3.1`
  (catching what the bytes miss, such as sdists). The results are merged.
- Licenses come from syft, as SPDX IDs where syft can tell (syft 1.2x or
  newer maps Maven license URLs), with its npm cataloger for unpacked npm
  tarballs switched on. gated then cleans them up: quotes are dropped, the
  common license URLs that syft leaves as-is (opensource.org, apache.org,
  eclipse.org, gnu.org) and free-text names that state a version ("Apache
  License, Version 2.0", "The MIT License (MIT)") become SPDX IDs, and
  `sha256:...` values (license text syft could not identify) are dropped.
  Where syft finds none, gated reads the package's own metadata: for Python,
  `License-Expression` or a `License` field that is an identifier; for crates,
  `license` in `Cargo.toml` (the legacy `MIT/Apache-2.0` reads as
  `MIT OR Apache-2.0`); for Go modules, the module's `LICENSE` file, identified
  with [licensecheck](https://github.com/google/licensecheck) (as pkg.go.dev
  does) and accepted only when it is one known license.
- syft never runs the go toolchain against the network or a real module
  cache: for a module with dependencies, go would download all of them, into
  a watched cache where gated would gate each download.
- gated refreshes grype's vulnerability database in the background (at start
  and every 6 hours), so that a scan never stops to download it. Scans that
  start before the first refresh succeeds still fetch it themselves.
- At most half the CPUs' worth of scans run at once (2 to 8). A project install
  can land dozens of packages within a second; the rest wait their turn.

`tools.osv_scanner` is no longer used: grype's database covers the same
advisories. Older configs that set it still load, with a warning.

Install both with `./scripts/install-tools.sh` (system-wide) or
`./scripts/install-user.sh` (per-user to `~/.local/bin`).

## Limitations

- macOS build requires CGo (`CGO_ENABLED=1`) for CoreServices FSEvents binding.
  Cross-compiling from Linux needs `osxcross` or build natively on a Mac.
- fanotify watches are per-mount, not per-directory (kernel limitation); the daemon
  filters by path prefix in userspace.
- Scan latency adds to install time. Mitigated by pre-scan on file close (fanotify
  `FAN_CLOSE_WRITE`), quarantine during download-to-open gap, and verdict caching.
  First-time installs of large dependency trees will be noticeably slower.
- npm's content-addressed cache is poorly suited to path-based package resolution.
- pnpm is not supported: its store holds no file per package to gate.
- yarn 2+ is not warned in its own output when gated loses the race (see
  [Racing the package manager](#racing-the-package-manager-quarantine-mode)).
- Windows watcher is a stub. Three implementation strategies are documented in
  `watcher_windows.go` (ReadDirectoryChangesW, minifilter driver, ProjFS).

## License

Apache-2.0. See [LICENSE](LICENSE).

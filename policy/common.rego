package gate

# Shared helpers for the gate policies.
#
# Every rule in package gate that adds a string to `deny` blocks the package.
# The input is the daemon's scan result (internal/scanner.ScanResult):
#
#   {
#     "package":         {"ecosystem": "pypi", "name": "requests", "version": "2.31.0"},
#     "licenses":        ["Apache-2.0"],
#     "vulnerabilities": [{"id": "CVE-…", "severity": "high", "cvss": 7.5, "fixed_in": "2.32.0", "source": "grype"},
#                         {"id": "GO-…", "severity": "high", "fixed_in": "0.62.0", "source": "grype",
#                          "dependency": "golang.org/x/net", "dependency_version": "v0.59.0"}],
#     "errors":          ["syft: …"]
#   }
#
# "dependency" is set when the vulnerability is in something inside the
# package (a go.mod requirement, a bundled jar), and "fixed_in" is then that
# dependency's version.
#
# The daemon encodes an empty Go slice as null and omits empty "errors",
# "fixed_in" and "dependency", so every rule reads the input through the helpers below rather
# than directly: a missing or null field must never make a deny rule
# undefined (that would fail open).
#
# Tuning knobs live in data.json at the root of data. Each has a default here,
# so a data.json that predates a knob keeps working.

import rego.v1

pkg := input["package"]

pkg_ref := sprintf("%s@%s", [pkg.name, pkg.version])

# Detected license expressions, as a set (null/missing → empty).
licenses := {l | some l in input.licenses; is_string(l); trim_space(l) != ""}

# Vulnerabilities after waivers (see vulnerability.rego), null/missing → empty.
vulnerabilities := [v |
	some v in input.vulnerabilities
	not waived(v)
]

scan_errors := [e | some e in input.errors]

# Package name in the ecosystem's canonical form, for comparisons.
# PyPI: PEP 503 (case-insensitive, runs of -_. are equivalent).
# npm: names are lowercase on the registry; compare case-insensitively.
normalize_name("pypi", name) := lower(regex.replace(name, `[-_.]+`, "-"))

normalize_name("npm", name) := lower(name)

normalize_name(eco, name) := name if not eco in {"pypi", "npm"}

pkg_name := normalize_name(pkg.ecosystem, pkg.name)

# --- data.json knobs with defaults ---

default cfg_approved_licenses := []

cfg_approved_licenses := data.approved_licenses

default cfg_blocked_licenses := []

cfg_blocked_licenses := data.blocked_licenses

default cfg_blocked_packages := {}

cfg_blocked_packages := data.blocked_packages

default cfg_popular_packages := {}

cfg_popular_packages := data.popular_packages

default cfg_typosquat_allowlist := {}

cfg_typosquat_allowlist := data.typosquat_allowlist

default cfg_typosquat_min_length := 5

cfg_typosquat_min_length := data.typosquat_min_length

default cfg_approved_maven_groups := []

cfg_approved_maven_groups := data.approved_maven_groups

default cfg_approved_go_prefixes := []

cfg_approved_go_prefixes := data.approved_go_prefixes

default cfg_known_exploited_cves := []

cfg_known_exploited_cves := data.known_exploited_cves

default cfg_vulnerability_waivers := {}

cfg_vulnerability_waivers := data.vulnerability_waivers

default cfg_require_clean_scan := false

cfg_require_clean_scan := data.require_clean_scan

default cfg_critical_cvss := 9.0

cfg_critical_cvss := data.critical_cvss

# max_total_vulnerabilities has no default: unset means no limit.

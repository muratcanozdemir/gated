package gate_test

import data.gate
import rego.v1

prov_input(ecosystem, name, version) := {
	"package": {"ecosystem": ecosystem, "name": name, "version": version},
	"licenses": ["MIT"],
	"vulnerabilities": [],
}

# --- blocklist ---

test_blocklisted_package_denied if {
	gate.deny["blocklisted package: pypi/colourama@0.1.0 — typosquat of colorama — known malware"] with input as prov_input("pypi", "colourama", "0.1.0")
}

test_blocklist_uses_pep503_names if {
	some msg in gate.deny with input as prov_input("pypi", "Python3_Dateutil", "2.8.0")
	startswith(msg, "blocklisted package:")
}

test_version_scoped_blocklist if {
	count(gate.deny) == 1 with input as prov_input("npm", "ua-parser-js", "0.7.29")
	count(gate.deny) == 0 with input as prov_input("npm", "ua-parser-js", "0.7.30")
}

test_blocklist_object_without_versions_blocks_all if {
	count(gate.deny) == 1 with input as prov_input("npm", "evil", "9.9.9")
		with data.blocked_packages as {"npm/evil": {"reason": "malware"}}
}

test_blocklist_is_per_ecosystem if {
	count(gate.deny) == 0 with input as prov_input("npm", "colourama", "0.1.0")
}

test_scoped_npm_blocklist_key if {
	count(gate.deny) == 1 with input as prov_input("npm", "@evil/pkg", "1.0.0")
		with data.blocked_packages as {"npm/@evil/pkg": "malware"}
}

# --- typosquats ---

test_typosquat_substitution if {
	gate.deny == {"potential typosquat: pypi/reqeusts is one edit away from popular package 'requests'"} with input as prov_input("pypi", "reqeusts", "1.0.0")
	count(gate.deny) == 1 with input as prov_input("npm", "reacr", "1.0.0")
}

test_typosquat_transposition if {
	count(gate.deny) == 1 with input as prov_input("npm", "axois", "1.0.0")
	count(gate.deny) == 1 with input as prov_input("npm", "lodahs", "1.0.0")
}

test_typosquat_insertion if {
	count(gate.deny) == 1 with input as prov_input("npm", "expresss", "1.0.0")
}

test_typosquat_deletion if {
	count(gate.deny) == 1 with input as prov_input("pypi", "reqests", "1.0.0")
}

test_typosquat_homoglyph_after_pep503 if {
	some msg in gate.deny with input as prov_input("pypi", "jeIlyfish", "1.0.0")
	startswith(msg, "potential typosquat:")
}

test_popular_packages_not_flagged if {
	count(gate.deny) == 0 with input as prov_input("pypi", "python-dateutil", "2.9.0")
	count(gate.deny) == 0 with input as prov_input("pypi", "Python_Dateutil", "2.9.0")
	count(gate.deny) == 0 with input as prov_input("npm", "preact", "10.0.0")
}

# The old substring patterns ("python-", "-python") denied these.
test_legit_prefixed_names_not_flagged if {
	count(gate.deny) == 0 with input as prov_input("pypi", "python-dotenv", "1.0.0")
	count(gate.deny) == 0 with input as prov_input("pypi", "opencv-python", "4.0.0")
}

test_two_edits_not_flagged if {
	count(gate.deny) == 0 with input as prov_input("pypi", "rqeuests2", "1.0.0")
}

test_typosquat_allowlist if {
	count(gate.deny) == 0 with input as prov_input("pypi", "scapy", "2.5.0")
	count(gate.deny) == 1 with input as prov_input("pypi", "scapy", "2.5.0") with data.typosquat_allowlist as {}
}

test_short_names_not_compared if {
	count(gate.deny) == 0 with input as prov_input("npm", "reacr", "1.0.0") with data.typosquat_min_length as 6
}

test_typosquat_is_per_ecosystem if {
	count(gate.deny) == 0 with input as prov_input("cargo", "reqeusts", "1.0.0")
}

test_one_edit_apart if {
	gate.one_edit_apart("abcde", "abXde")
	gate.one_edit_apart("abcde", "abdce")
	gate.one_edit_apart("abcde", "abcdef")
	gate.one_edit_apart("abcde", "bcde")
	not gate.one_edit_apart("abcde", "abcde")
	not gate.one_edit_apart("abcde", "edcba")
	not gate.one_edit_apart("abcde", "abXdY")
	not gate.one_edit_apart("abcde", "acbed")
	not gate.one_edit_apart("abcde", "abc")
}

# --- namespaces ---

test_approved_maven_group if {
	count(gate.deny) == 0 with input as prov_input("maven", "org.apache:commons-lang3", "3.14.0")
	count(gate.deny) == 0 with input as prov_input("maven", "org.apache.commons:commons-lang3", "3.14.0")
}

test_maven_group_prefix_needs_boundary if {
	gate.deny == {"unapproved Maven group: org.apachex.evil (package: org.apachex.evil:pwn)"} with input as prov_input("maven", "org.apachex.evil:pwn", "1.0.0")
}

test_maven_check_off_when_list_empty if {
	count(gate.deny) == 0 with input as prov_input("maven", "com.example:thing", "1.0.0") with data.approved_maven_groups as []
}

test_approved_go_prefix if {
	count(gate.deny) == 0 with input as prov_input("go", "github.com/stretchr/testify", "v1.9.0")
	count(gate.deny) == 0 with input as prov_input("go", "gopkg.in/yaml.v3", "v3.0.1")
}

test_unapproved_go_host if {
	gate.deny == {"unapproved Go module host: evil.example.com/pkg"} with input as prov_input("go", "evil.example.com/pkg", "v1.0.0")
}

test_go_prefix_needs_boundary if {
	count(gate.deny) == 1 with input as prov_input("go", "github.com.evil.io/pkg", "v1.0.0")
		with data.approved_go_prefixes as ["github.com"]
	count(gate.deny) == 0 with input as prov_input("go", "github.com/ok/pkg", "v1.0.0")
		with data.approved_go_prefixes as ["github.com"]
}

# --- clean scan ---

test_scan_errors_allowed_by_default if {
	inp := object.union(prov_input("pypi", "somepkg", "1.0.0"), {"errors": ["grype: timeout"]})
	count(gate.deny) == 0 with input as inp
}

test_require_clean_scan if {
	inp := object.union(prov_input("pypi", "somepkg", "1.0.0"), {"errors": ["grype: timeout", "osv: exit 2"]})
	gate.deny == {"scan incomplete for somepkg@1.0.0: grype: timeout; osv: exit 2"} with input as inp with data.require_clean_scan as true
}

test_require_clean_scan_without_errors if {
	count(gate.deny) == 0 with input as prov_input("pypi", "somepkg", "1.0.0") with data.require_clean_scan as true
}

package gate

# Provenance policy: supply chain origin checks.
#
#   - blocked_packages: known-malicious or compromised packages, keyed
#     "ecosystem/name". The value is either a reason (every version) or
#     {"reason": "...", "versions": ["1.2.3", ...]} (only those versions).
#   - Typosquats: a name one edit (insertion, deletion, substitution, or
#     swap of adjacent characters) away from a name in popular_packages is
#     denied, unless the name is popular itself or in typosquat_allowlist.
#     Names shorter than typosquat_min_length (default 5) are not compared:
#     short names are too close to each other to tell anything.
#   - Maven groupIds must be in approved_maven_groups (or below one of them,
#     on a "." boundary). Go modules must start with an approved_go_prefixes
#     entry (on a "/" boundary). Both are off while the list is empty.
#   - require_clean_scan: deny when a scanner failed (can't verify, can't trust).
# Names are compared in canonical form: PyPI per PEP 503, npm lowercase.

import rego.v1

deny contains msg if {
	some key, entry in cfg_blocked_packages
	blocked_key_matches(key)
	blocked_version_matches(entry)
	msg := sprintf("blocklisted package: %s/%s@%s — %s", [pkg.ecosystem, pkg.name, pkg.version, blocked_reason(entry)])
}

deny contains msg if {
	some popular in typosquat_targets
	msg := sprintf(
		"potential typosquat: %s/%s is one edit away from popular package '%s'",
		[pkg.ecosystem, pkg.name, popular],
	)
}

deny contains msg if {
	pkg.ecosystem == "maven"
	count(cfg_approved_maven_groups) > 0
	group_id := split(pkg.name, ":")[0]
	not maven_group_approved(group_id)
	msg := sprintf("unapproved Maven group: %s (package: %s)", [group_id, pkg.name])
}

deny contains msg if {
	pkg.ecosystem == "go"
	count(cfg_approved_go_prefixes) > 0
	not go_prefix_approved(pkg.name)
	msg := sprintf("unapproved Go module host: %s", [pkg.name])
}

deny contains msg if {
	cfg_require_clean_scan == true
	count(scan_errors) > 0
	msg := sprintf("scan incomplete for %s: %s", [pkg_ref, concat("; ", scan_errors)])
}

# --- blocklist ---

blocked_key_matches(key) if {
	parts := split(key, "/")
	parts[0] == pkg.ecosystem
	normalize_name(pkg.ecosystem, concat("/", array.slice(parts, 1, count(parts)))) == pkg_name
}

blocked_version_matches(entry) if is_string(entry)

blocked_version_matches(entry) if {
	is_object(entry)
	not "versions" in object.keys(entry)
}

blocked_version_matches(entry) if pkg.version in entry.versions

blocked_reason(entry) := entry if is_string(entry)

blocked_reason(entry) := object.get(entry, "reason", "blocklisted") if is_object(entry)

# --- typosquats ---

popular_names := {normalize_name(pkg.ecosystem, n) | some n in object.get(cfg_popular_packages, pkg.ecosystem, [])}

typosquat_allowed := {normalize_name(pkg.ecosystem, n) | some n in object.get(cfg_typosquat_allowlist, pkg.ecosystem, [])}

typosquat_targets contains popular if {
	not pkg_name in popular_names
	not pkg_name in typosquat_allowed
	some popular in popular_names
	count(popular) >= cfg_typosquat_min_length
	one_edit_apart(pkg_name, popular)
}

# Damerau-Levenshtein distance exactly 1.
one_edit_apart(a, b) if {
	count(a) == count(b)
	count(diff_positions(a, b)) == 1
}

one_edit_apart(a, b) if {
	count(a) == count(b)
	d := diff_positions(a, b)
	count(d) == 2
	d[1] == d[0] + 1
	substring(a, d[0], 1) == substring(b, d[1], 1)
	substring(a, d[1], 1) == substring(b, d[0], 1)
}

one_edit_apart(a, b) if {
	count(a) == count(b) + 1
	one_deletion(a, b)
}

one_edit_apart(a, b) if {
	count(b) == count(a) + 1
	one_deletion(b, a)
}

diff_positions(a, b) := [i |
	some i in numbers.range(0, count(a) - 1)
	substring(a, i, 1) != substring(b, i, 1)
]

# Removing one character from long gives short.
one_deletion(long, short) if {
	some i in numbers.range(0, count(long) - 1)
	concat("", [substring(long, 0, i), substring(long, i + 1, -1)]) == short
}

# --- namespaces ---

maven_group_approved(group_id) if {
	some approved in cfg_approved_maven_groups
	namespace_match(group_id, trim_suffix(approved, "."), ".")
}

go_prefix_approved(module) if {
	some approved in cfg_approved_go_prefixes
	namespace_match(module, trim_suffix(approved, "/"), "/")
}

# name is prefix itself, or below it on a separator boundary, so that
# "org.apache" approves "org.apache.commons" but not "org.apachex".
namespace_match(name, prefix, _) if name == prefix

namespace_match(name, prefix, sep) if startswith(name, concat("", [prefix, sep]))

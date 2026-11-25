package gate

# License policy: allowlist-based SPDX enforcement.
#
# A package passes when every detected license expression can be satisfied
# with approved licenses:
#   - "MIT"                      the identifier must be approved
#   - "MIT OR GPL-3.0-only"      one alternative must be approved (you may choose it)
#   - "MIT AND BSD-3-Clause"     every term must be approved
#   - "(MIT OR X) AND Y"         with parentheses, every identifier must be approved
#                                (conservative: no full SPDX parser here)
# SPDX identifiers are compared case-insensitively.
#
# No detected license at all is a deny: unknown obligation, unacceptable risk.

import rego.v1

# Deny a single blocked license.
deny contains msg if {
	some expr in licenses
	not compound(expr)
	blocked_license(expr)
	msg := sprintf("blocked license: %s (package: %s)", [expr, pkg_ref])
}

# Deny a single license that is neither approved nor blocked.
deny contains msg if {
	some expr in licenses
	not compound(expr)
	not approved_license(expr)
	not blocked_license(expr)
	msg := sprintf("unapproved license: %s (package: %s) — submit for review", [expr, pkg_ref])
}

# Deny a compound expression no approved choice satisfies.
deny contains msg if {
	some expr in licenses
	compound(expr)
	not satisfiable(expr)
	blocked := [id | some id in license_ids(expr); blocked_license(id)]
	unapproved := [id | some id in license_ids(expr); not approved_license(id); not blocked_license(id)]
	msg := sprintf(
		"license expression not satisfiable with approved licenses: %s (package: %s; blocked: %v; unapproved: %v)",
		[expr, pkg_ref, blocked, unapproved],
	)
}

# Deny if no license information was detected at all.
deny contains msg if {
	count(licenses) == 0
	pkg.name != "unresolved"
	msg := sprintf("no license detected for %s — manual review required", [pkg_ref])
}

# --- helpers ---

approved_ids := {lower(l) | some l in cfg_approved_licenses}

blocked_ids := {lower(l) | some l in cfg_blocked_licenses}

approved_license(id) if lower(trim_space(id)) in approved_ids

blocked_license(id) if lower(trim_space(id)) in blocked_ids

compound(expr) if regex.match(`(?i)\s(AND|OR)\s|[()]`, expr)

# Every identifier in the expression ("X WITH exception" stays one identifier).
license_ids(expr) := {trim_space(id) |
	some id in regex.split(`(?i)\s+(?:AND|OR)\s+`, regex.replace(expr, `[()]`, " "))
	trim_space(id) != ""
}

# The sets of identifiers one may choose between. AND binds tighter than OR,
# so without parentheses "A OR B AND C" is A, or both B and C.
choices(expr) := [terms |
	some alt in regex.split(`(?i)\s+OR\s+`, expr)
	terms := [trim_space(t) | some t in regex.split(`(?i)\s+AND\s+`, alt)]
] if not regex.match(`[()]`, expr)

choices(expr) := [license_ids(expr)] if regex.match(`[()]`, expr)

satisfiable(expr) if {
	some choice in choices(expr)
	every id in choice {
		approved_license(id)
	}
}

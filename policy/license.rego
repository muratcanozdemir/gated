package gate

# License policy: allowlist-based enforcement.
#
# Produces deny reasons for any package whose detected licenses
# are not in the approved set or are in the explicit blocklist.

import rego.v1

# Deny if any detected license is explicitly blocked.
deny contains msg if {
    some license in input.licenses
    license in data.blocked_licenses
    msg := sprintf("blocked license: %s (package: %s@%s)", [license, input.package.name, input.package.version])
}

# Deny if a license is detected but not in the approved set.
deny contains msg if {
    count(input.licenses) > 0
    some license in input.licenses
    not license in data.approved_licenses
    not license in data.blocked_licenses
    msg := sprintf("unapproved license: %s (package: %s@%s) — submit for review", [license, input.package.name, input.package.version])
}

# Deny if no license information was detected at all.
# Unknown license = unknown obligation = unacceptable risk.
deny contains msg if {
    count(input.licenses) == 0
    input.package.name != "unresolved"
    msg := sprintf("no license detected for %s@%s — manual review required", [input.package.name, input.package.version])
}

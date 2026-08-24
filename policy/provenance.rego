package gate

# Provenance policy: supply chain origin checks.
#
# Blocks known-malicious packages, suspicious naming patterns,
# and enforces namespace restrictions per ecosystem.

import rego.v1

# Deny explicitly blocklisted packages (known malware, abandoned, etc.)
deny contains msg if {
    key := sprintf("%s/%s", [input["package"].ecosystem, input["package"].name])
    key in data.blocked_packages
    msg := sprintf("blocklisted package: %s/%s — %s", [input["package"].ecosystem, input["package"].name, data.blocked_packages[key]])
}

# Deny packages with names that are suspiciously similar to popular packages.
# Catches common typosquatting patterns.
deny contains msg if {
    input["package"].ecosystem == "pypi"
    some pattern in data.typosquat_patterns.pypi
    contains(input["package"].name, pattern)
    msg := sprintf("potential typosquat: %s matches suspicious pattern '%s'", [input["package"].name, pattern])
}

deny contains msg if {
    input["package"].ecosystem == "npm"
    some pattern in data.typosquat_patterns.npm
    contains(input["package"].name, pattern)
    msg := sprintf("potential typosquat: %s matches suspicious pattern '%s'", [input["package"].name, pattern])
}

# Enforce namespace restrictions for Maven (require approved group IDs).
deny contains msg if {
    input["package"].ecosystem == "maven"
    count(data.approved_maven_groups) > 0
    group_id := split(input["package"].name, ":")[0]
    not namespace_approved(group_id)
    msg := sprintf("unapproved Maven group: %s (package: %s)", [group_id, input["package"].name])
}

# Enforce Go module path restrictions (e.g., only allow known hosts).
deny contains msg if {
    input["package"].ecosystem == "go"
    count(data.approved_go_prefixes) > 0
    not go_prefix_approved(input["package"].name)
    msg := sprintf("unapproved Go module host: %s", [input["package"].name])
}

# Deny packages with scan errors — if we can't verify, we can't trust.
# Configurable: set require_clean_scan to false to disable.
deny contains msg if {
    data.require_clean_scan == true
    count(input.errors) > 0
    msg := sprintf("scan incomplete for %s@%s: %s", [input["package"].name, input["package"].version, concat("; ", input.errors)])
}

# --- helpers ---

namespace_approved(group_id) if {
    some prefix in data.approved_maven_groups
    startswith(group_id, prefix)
}

go_prefix_approved(module) if {
    some prefix in data.approved_go_prefixes
    startswith(module, prefix)
}

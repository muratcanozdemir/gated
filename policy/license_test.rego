package gate_test

import data.gate
import rego.v1

lic_input(licenses) := {
	"package": {"ecosystem": "pypi", "name": "somepkg", "version": "1.0.0"},
	"licenses": licenses,
	"vulnerabilities": [],
}

test_approved_license_allowed if {
	count(gate.deny) == 0 with input as lic_input(["MIT"])
}

test_license_ids_case_insensitive if {
	count(gate.deny) == 0 with input as lic_input(["apache-2.0", "mit"])
}

test_blocked_license_denied if {
	gate.deny == {"blocked license: AGPL-3.0-only (package: somepkg@1.0.0)"} with input as lic_input(["AGPL-3.0-only"])
}

test_unapproved_license_denied if {
	gate.deny == {"unapproved license: GPL-3.0-only (package: somepkg@1.0.0) — submit for review"} with input as lic_input(["GPL-3.0-only"])
}

test_one_bad_license_among_good_denied if {
	count(gate.deny) == 1 with input as lic_input(["MIT", "SSPL-1.0"])
}

test_no_license_denied if {
	gate.deny == {"no license detected for somepkg@1.0.0 — manual review required"} with input as lic_input([])
}

# The daemon encodes a nil Go slice as null (syft failed or found nothing).
test_null_licenses_denied if {
	gate.deny == {"no license detected for somepkg@1.0.0 — manual review required"} with input as lic_input(null)
}

test_missing_licenses_denied if {
	count(gate.deny) == 1 with input as {"package": {"ecosystem": "pypi", "name": "somepkg", "version": "1.0.0"}}
}

test_blank_license_strings_ignored if {
	count(gate.deny) == 1 with input as lic_input(["", "  "])
}

test_unresolved_package_without_license_allowed if {
	count(gate.deny) == 0 with input as {
		"package": {"ecosystem": "npm", "name": "unresolved", "version": "unknown"},
		"licenses": [],
	}
}

test_or_with_approved_alternative_allowed if {
	count(gate.deny) == 0 with input as lic_input(["MIT OR GPL-3.0-only"])
}

test_or_without_approved_alternative_denied if {
	count(gate.deny) == 1 with input as lic_input(["AGPL-3.0-only OR GPL-3.0-only"])
}

test_and_all_approved_allowed if {
	count(gate.deny) == 0 with input as lic_input(["MIT AND BSD-3-Clause"])
}

test_and_with_unapproved_term_denied if {
	count(gate.deny) == 1 with input as lic_input(["MIT AND GPL-3.0-only"])
}

test_and_binds_tighter_than_or if {
	count(gate.deny) == 0 with input as lic_input(["GPL-3.0-only OR MIT AND ISC"])
	count(gate.deny) == 1 with input as lic_input(["GPL-3.0-only OR MIT AND SSPL-1.0"])
}

test_lowercase_operators if {
	count(gate.deny) == 0 with input as lic_input(["MIT or GPL-3.0-only"])
}

# With parentheses every identifier must be approved: choosing MIT would
# still leave SSPL-1.0, which a naive OR-first split would miss.
test_parenthesised_expression_is_conservative if {
	count(gate.deny) == 0 with input as lic_input(["(MIT OR Apache-2.0) AND BSD-3-Clause"])
	count(gate.deny) == 1 with input as lic_input(["(MIT OR Apache-2.0) AND SSPL-1.0"])
	count(gate.deny) == 1 with input as lic_input(["(MIT OR GPL-3.0-only) AND ISC"])
}

test_compound_message_lists_offenders if {
	gate.deny == {concat("", [
		"license expression not satisfiable with approved licenses: SSPL-1.0 OR GPL-3.0-only ",
		"(package: somepkg@1.0.0; blocked: [\"SSPL-1.0\"]; unapproved: [\"GPL-3.0-only\"])",
	])} with input as lic_input(["SSPL-1.0 OR GPL-3.0-only"])
}

test_with_exception_is_one_identifier if {
	count(gate.deny) == 1 with input as lic_input(["GPL-2.0-only WITH Classpath-exception-2.0"])
	count(gate.deny) == 0 with input as lic_input(["GPL-2.0-only WITH Classpath-exception-2.0"])
		with data.approved_licenses as ["GPL-2.0-only WITH Classpath-exception-2.0"]
}

test_missing_license_lists_in_data_deny_everything if {
	count(gate.deny) == 1 with input as lic_input(["MIT"])
		with data.approved_licenses as null
		with data.blocked_licenses as null
}

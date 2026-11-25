# Changelog

## [0.2.0](https://github.com/muratcanozdemir/gated/compare/v0.1.0...v0.2.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* **policy:** data.json's typosquat_patterns is no longer read; use popular_packages and typosquat_allowlist. known_exploited_cves ships empty: KEV now comes from grype (>= 0.88), so an older grype no longer flags known-exploited vulnerabilities.

### Features

* **policy:** harden policies, add Rego tests, use live KEV data ([4df53a3](https://github.com/muratcanozdemir/gated/commit/4df53a3c58699b34378daf5c92cf9ab64ddda4e1))
* register in Murat's software catalog, resolve license mismatch ([f4fae63](https://github.com/muratcanozdemir/gated/commit/f4fae63635bf2710b015adcd10eb221540d6023c))
* **scanner:** read CISA KEV and EPSS from grype ([4df53a3](https://github.com/muratcanozdemir/gated/commit/4df53a3c58699b34378daf5c92cf9ab64ddda4e1))

## 0.1.0 (2026-08-25)

Initial release.

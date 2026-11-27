# Changelog

## [1.0.1](https://github.com/muratcanozdemir/gated/compare/v1.0.0...v1.0.1) (2026-11-27)


### Bug Fixes

* **quarantine:** find a fast uv on the first install into a new cache, and when a cache scan is already running ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **quarantine:** hold a package manager's output only for its own pending verdicts, not for others in the same cache ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **quarantine:** remove a denied Go module even while go is still unpacking it ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **quarantine:** stop hanging pipelines that read a package manager's output (gated held the pipe open after the package manager exited) ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **resolver:** scan jars in a local Maven repository outside "repository/" (they were allowed unscanned) ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **scanner:** find Go module licenses (every Go module was denied for "no license" under the service), without letting syft's go toolchain download dependencies ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **scanner:** read free-text license names that state license and version ("Apache License, Version 2.0") as SPDX ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **scanner:** refresh grype's database in the background, so a scan never stops to download it ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **scanner:** run at most half the CPUs' worth of scans at once ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))
* **watcher:** never gate a package manager's hidden staging directory (uv's .tmpXXXX), and finish holding or releasing files before stopping ([292041b](https://github.com/muratcanozdemir/gated/commit/292041b338398b2f9b3a9c1bd94322fc13f17ad6))

## [1.0.0](https://github.com/muratcanozdemir/gated/compare/v0.2.0...v1.0.0) (2026-11-25)


### Features

* **quarantine:** race package managers that unpack downloads at once (go, uv), and warn them in their own output when gated loses ([1567011](https://github.com/muratcanozdemir/gated/commit/1567011a8119571fa29df166fc99a89647543b58))
* **scanner:** scan what is inside packages and look them up by package URL ([#22](https://github.com/muratcanozdemir/gated/issues/22)) ([41d67c3](https://github.com/muratcanozdemir/gated/commit/41d67c320654cd29b1389261538233f1ee5f07b0))


### Bug Fixes

* **policy:** approve the Unicode license (Unicode-3.0, Unicode-DFS-2016), which nearly every Rust build needs ([1567011](https://github.com/muratcanozdemir/gated/commit/1567011a8119571fa29df166fc99a89647543b58))
* quarantine mode never scanned or gated real package downloads ([#21](https://github.com/muratcanozdemir/gated/issues/21)) ([a15baf6](https://github.com/muratcanozdemir/gated/commit/a15baf6a3b2f1255412d40f064008f5fa98d7b32))
* **quarantine:** a download retried at the path of a denied one was allowed as a duplicate ([1567011](https://github.com/muratcanozdemir/gated/commit/1567011a8119571fa29df166fc99a89647543b58))
* **scanner:** stop denying clean packages over how their license is written; look up scoped npm packages by their real name ([1567011](https://github.com/muratcanozdemir/gated/commit/1567011a8119571fa29df166fc99a89647543b58))
* **watcher:** stop logging "bad file descriptor" when inotify shuts down ([1567011](https://github.com/muratcanozdemir/gated/commit/1567011a8119571fa29df166fc99a89647543b58))

## [0.2.0](https://github.com/muratcanozdemir/gated/compare/v0.1.0...v0.2.0) (2026-11-25)


### ⚠ BREAKING CHANGES

* **policy:** data.json's typosquat_patterns is no longer read; use popular_packages and typosquat_allowlist. known_exploited_cves ships empty: KEV now comes from grype (>= 0.88), so an older grype no longer flags known-exploited vulnerabilities.

### Features

* **policy:** harden policies, add Rego tests, use live KEV data ([4df53a3](https://github.com/muratcanozdemir/gated/commit/4df53a3c58699b34378daf5c92cf9ab64ddda4e1))
* register in Murat's software catalog, resolve license mismatch ([f4fae63](https://github.com/muratcanozdemir/gated/commit/f4fae63635bf2710b015adcd10eb221540d6023c))
* **scanner:** read CISA KEV and EPSS from grype ([4df53a3](https://github.com/muratcanozdemir/gated/commit/4df53a3c58699b34378daf5c92cf9ab64ddda4e1))

## 0.1.0 (2026-08-25)

Initial release.

package scanner

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// normalizeLicense turns a license value as syft reports it into what the
// policy compares against approved and blocked licenses: an SPDX identifier
// or expression. It returns "" for values that are not a license at all.
//
//   - syft reports license text it cannot identify as "sha256:<digest of the
//     text>": not a license name; the package's other licenses stand.
//   - some Maven POMs quote the name (<name>"Apache-2.0"</name>).
//   - many POMs name the license by URL only; the common ones map to SPDX.
func normalizeLicense(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSpace(strings.Trim(v, `"'`))
	if v == "" || strings.HasPrefix(v, "sha256:") {
		return ""
	}
	if id, ok := licenseURLs[licenseURLKey(v)]; ok {
		return id
	}
	return v
}

// licenseURLKey reduces a license URL to host and path, without scheme,
// "www.", file extension or trailing slash, lowercased: "http://www.
// opensource.org/licenses/mit-license.php" and "https://opensource.org/
// licenses/MIT" differ only in what this drops or in the table below.
func licenseURLKey(u string) string {
	l := strings.ToLower(u)
	if !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return ""
	}
	l = l[strings.Index(l, "//")+2:]
	l = strings.TrimPrefix(l, "www.")
	l = strings.TrimRight(l, "/")
	for _, ext := range []string{".txt", ".html", ".htm", ".php", ".md"} {
		l = strings.TrimSuffix(l, ext)
	}
	return l
}

// licenseURLs maps the license URLs most often found in POMs (and in other
// metadata that names a license by URL) to SPDX identifiers. Keys are
// licenseURLKey forms.
var licenseURLs = map[string]string{
	"apache.org/licenses/license-2.0":                     "Apache-2.0",
	"opensource.org/licenses/apache-2.0":                  "Apache-2.0",
	"opensource.org/licenses/mit":                         "MIT",
	"opensource.org/licenses/mit-license":                 "MIT",
	"opensource.org/license/mit":                          "MIT",
	"opensource.org/licenses/bsd-license":                 "BSD-2-Clause",
	"opensource.org/licenses/bsd-2-clause":                "BSD-2-Clause",
	"opensource.org/licenses/bsd-3-clause":                "BSD-3-Clause",
	"opensource.org/license/bsd-3-clause":                 "BSD-3-Clause",
	"eclipse.org/legal/epl-v10":                           "EPL-1.0",
	"eclipse.org/legal/epl-2.0":                           "EPL-2.0",
	"eclipse.org/legal/epl-v20":                           "EPL-2.0",
	"eclipse.org/org/documents/edl-v10":                   "BSD-3-Clause", // EDL 1.0 is BSD-3-Clause
	"gnu.org/licenses/lgpl":                               "LGPL-3.0-only",
	"gnu.org/licenses/lgpl-3.0":                           "LGPL-3.0-only",
	"gnu.org/licenses/old-licenses/lgpl-2.1":              "LGPL-2.1-only",
	"gnu.org/licenses/gpl-2.0":                            "GPL-2.0-only",
	"gnu.org/licenses/gpl-3.0":                            "GPL-3.0-only",
	"mozilla.org/mpl/2.0":                                 "MPL-2.0",
	"opensource.org/licenses/epl-1.0":                     "EPL-1.0",
	"opensource.org/licenses/epl-2.0":                     "EPL-2.0",
	"creativecommons.org/publicdomain/zero/1.0":           "CC0-1.0",
	"creativecommons.org/publicdomain/zero/1.0/legalcode": "CC0-1.0",
}

// cargoLicenses reads the license of an unpacked crate from its Cargo.toml
// ([package] license, an SPDX expression), for when syft reports none: syft
// catalogs the crate but not its license. A crate unpacks into
// <name>-<version>/, so the manifest is at most one directory deep.
func cargoLicenses(root string) []string {
	manifests, _ := filepath.Glob(filepath.Join(root, "*", "Cargo.toml"))
	manifests = append([]string{filepath.Join(root, "Cargo.toml")}, manifests...)
	for _, m := range manifests {
		if l := cargoTomlLicense(m); l != "" {
			return []string{l}
		}
	}
	return nil
}

// cargoTomlLicense finds `license = "..."` in the [package] table. Published
// manifests are normalized by cargo (one key per line, basic strings), so a
// line scan suffices; anything less regular yields "", not a guess.
func cargoTomlLicense(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	inPackage := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inPackage = line == "[package]"
			continue
		}
		if !inPackage {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "license" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			return ""
		}
		// "MIT/Apache-2.0" is cargo's deprecated spelling of "MIT OR Apache-2.0".
		license := strings.TrimSpace(value[1 : len(value)-1])
		if !strings.Contains(license, " ") && strings.Contains(license, "/") {
			license = strings.ReplaceAll(license, "/", " OR ")
		}
		return license
	}
	return ""
}

// npmScopedName recovers a scoped package's name from its unpacked tarball.
// npm names the tarball of @scope/name "scope-name-<version>.tgz", so the
// resolver can only see "scope-name". The package.json inside says which
// package it is; it is trusted only as far as it agrees with the file name
// (same version, and "@scope/name" flattens to the resolved name), so a
// tarball cannot pass itself off as some other package.
func npmScopedName(root, resolvedName, version string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(root, "package", "package.json"))
	if err != nil {
		return "", false
	}
	var m struct{ Name, Version string }
	if json.Unmarshal(b, &m) != nil || m.Version != version || !strings.HasPrefix(m.Name, "@") {
		return "", false
	}
	scope, name, ok := strings.Cut(m.Name[1:], "/")
	if !ok || scope == "" || name == "" || strings.Contains(name, "/") || scope+"-"+name != resolvedName {
		return "", false
	}
	return m.Name, true
}

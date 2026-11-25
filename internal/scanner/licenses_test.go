package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeLicense(t *testing.T) {
	for in, want := range map[string]string{
		`"Apache-2.0"`: "Apache-2.0", // quoted in log4j's POM
		"MIT":          "MIT",
		"http://www.opensource.org/licenses/mit-license.php":             "MIT", // slf4j
		"https://www.apache.org/licenses/LICENSE-2.0.txt":                "Apache-2.0",
		"http://www.eclipse.org/legal/epl-v10.html":                      "EPL-1.0",
		"https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html":        "LGPL-2.1-only",
		"sha256:cad1ef5bd340d73e074ba614d26f7deaca5c7940c3d8c34852e65c4": "", // unidentified license text
		"https://example.com/our-license":                                "https://example.com/our-license",
		"  ":                                                             "",
	} {
		if got := normalizeLicense(in); got != want {
			t.Errorf("normalizeLicense(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractLicensesDropsHashesKeepsTheRest(t *testing.T) {
	sbom := &SyftOutput{Artifacts: []SyftArtifact{{Licenses: []SyftLicense{
		{Value: "Apache-2.0", SPDXExpression: "Apache-2.0"},
		{Value: "BSD-2-Clause", SPDXExpression: "BSD-2-Clause"},
		{Value: "sha256:cad1ef5bd340d73e074ba614d26f7deaca5c7940c3d8c34852e65c4909686c48"},
	}}}}
	got := extractLicenses(sbom)
	if len(got) != 2 || got[0] != "Apache-2.0" || got[1] != "BSD-2-Clause" {
		t.Errorf("extractLicenses = %v (packaging 24.0 was denied for the hash)", got)
	}
}

func TestCargoLicenses(t *testing.T) {
	root := t.TempDir()
	crate := filepath.Join(root, "serde-1.0.200")
	if err := os.MkdirAll(crate, 0o755); err != nil {
		t.Fatal(err)
	}
	toml := "[dependencies.serde_derive]\nversion = \"=1.0.200\"\nlicense = \"GPL-3.0\"\n\n[package]\nedition = \"2018\"\nname = \"serde\"\nlicense = \"MIT OR Apache-2.0\"\n\n[features]\n"
	if err := os.WriteFile(filepath.Join(crate, "Cargo.toml"), []byte(toml), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := cargoLicenses(root); len(got) != 1 || got[0] != "MIT OR Apache-2.0" {
		t.Errorf("cargoLicenses = %v: only [package] license counts", got)
	}
	old := filepath.Join(t.TempDir(), "time-0.1.43")
	if err := os.MkdirAll(old, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "Cargo.toml"), []byte("[package]\nlicense = \"MIT/Apache-2.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := cargoLicenses(filepath.Dir(old)); len(got) != 1 || got[0] != "MIT OR Apache-2.0" {
		t.Errorf("legacy slash form: %v", got)
	}
	if got := cargoLicenses(t.TempDir()); got != nil {
		t.Errorf("no manifest: %v", got)
	}
}

func TestNpmScopedName(t *testing.T) {
	write := func(name, version string) string {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "package"), 0o755); err != nil {
			t.Fatal(err)
		}
		pj := `{"name":"` + name + `","version":"` + version + `"}`
		if err := os.WriteFile(filepath.Join(root, "package", "package.json"), []byte(pj), 0o644); err != nil {
			t.Fatal(err)
		}
		return root
	}
	if got, ok := npmScopedName(write("@babel/traverse", "7.22.0"), "babel-traverse", "7.22.0"); !ok || got != "@babel/traverse" {
		t.Errorf("scoped: %q %v", got, ok)
	}
	for name, root := range map[string]string{
		"other package":   write("@evil/thing", "7.22.0"),
		"other version":   write("@babel/traverse", "7.23.2"),
		"unscoped":        write("babel-traverse", "7.22.0"),
		"nested slash":    write("@babel/traverse/x", "7.22.0"),
		"no package.json": t.TempDir(),
	} {
		if got, ok := npmScopedName(root, "babel-traverse", "7.22.0"); ok {
			t.Errorf("%s: accepted %q", name, got)
		}
	}
}

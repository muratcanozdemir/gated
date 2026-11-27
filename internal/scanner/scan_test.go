package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/muratcanozdemir/gated/internal/config"
	"github.com/muratcanozdemir/gated/internal/resolver"
)

// --- archive fixtures ---

type entry struct {
	name, body string
	link       string // symlink target, for a symlink entry
}

func writeZip(t *testing.T, path string, entries ...entry) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		body := e.body
		if e.link != "" {
			h.SetMode(os.ModeSymlink | 0o777)
			body = e.link
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTarGz(t *testing.T, path string, entries ...entry) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.link != "" {
			h.Typeflag, h.Linkname, h.Size = tar.TypeSymlink, e.link, 0
		}
		if strings.HasSuffix(e.name, "/") {
			h.Typeflag, h.Size = tar.TypeDir, 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.link == "" && h.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- unpack ---

func TestUnpack_Wheel(t *testing.T) {
	src := filepath.Join(t.TempDir(), "requests-2.32.3-py3-none-any.whl")
	writeZip(t, src,
		entry{name: "requests/__init__.py", body: "x = 1\n"},
		entry{name: "requests-2.32.3.dist-info/METADATA", body: "Name: requests\nLicense: Apache-2.0\n"},
	)
	dir, cleanup, err := unpack(src)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	if dir == "" {
		t.Fatal("a wheel must be unpacked")
	}
	if got := readFile(t, filepath.Join(dir, "requests-2.32.3.dist-info", "METADATA")); !strings.Contains(got, "requests") {
		t.Fatalf("METADATA = %q", got)
	}
	cleanup()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("cleanup left %s behind", dir)
	}
}

func TestUnpack_Sdist(t *testing.T) {
	src := filepath.Join(t.TempDir(), "PyYAML-5.3.1.tar.gz")
	writeTarGz(t, src,
		entry{name: "PyYAML-5.3.1/"},
		entry{name: "PyYAML-5.3.1/PKG-INFO", body: "Name: PyYAML\nLicense: MIT\n"},
	)
	dir, cleanup, err := unpack(src)
	defer cleanup()
	if err != nil || dir == "" {
		t.Fatalf("unpack: %q, %v", dir, err)
	}
	if got := readFile(t, filepath.Join(dir, "PyYAML-5.3.1", "PKG-INFO")); !strings.Contains(got, "MIT") {
		t.Fatalf("PKG-INFO = %q", got)
	}
}

func TestUnpack_JarScannedAsIs(t *testing.T) {
	src := filepath.Join(t.TempDir(), "x-1.0.jar")
	writeZip(t, src, entry{name: "META-INF/MANIFEST.MF", body: "x"})
	dir, cleanup, err := unpack(src)
	defer cleanup()
	if err != nil || dir != "" {
		t.Fatalf("a jar is read natively by syft: got dir %q, err %v", dir, err)
	}
}

func TestUnpack_RefusesEscapes(t *testing.T) {
	outside := t.TempDir()
	for _, name := range []string{"../escape.txt", "a/../../escape.txt", "/abs/escape.txt"} {
		src := filepath.Join(t.TempDir(), "evil.whl")
		writeZip(t, src, entry{name: name, body: "pwned"})
		if _, _, err := unpack(src); err == nil {
			t.Errorf("zip entry %q: expected an error", name)
		}
		srcTar := filepath.Join(t.TempDir(), "evil.tar.gz")
		writeTarGz(t, srcTar, entry{name: name, body: "pwned"})
		if _, _, err := unpack(srcTar); err == nil {
			t.Errorf("tar entry %q: expected an error", name)
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("something was written outside: %v", entries)
	}
}

func TestUnpack_SkipsLinks(t *testing.T) {
	for _, src := range []string{filepath.Join(t.TempDir(), "x.whl"), filepath.Join(t.TempDir(), "x.tar.gz")} {
		ents := []entry{{name: "pkg/link", link: "/etc/passwd"}, {name: "pkg/real.txt", body: "ok"}}
		if strings.HasSuffix(src, ".whl") {
			writeZip(t, src, ents...)
		} else {
			writeTarGz(t, src, ents...)
		}
		dir, cleanup, err := unpack(src)
		if err != nil {
			t.Fatalf("%s: unpack: %v", src, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "pkg", "link")); !os.IsNotExist(err) {
			t.Errorf("%s: a symlink entry was created", src)
		}
		if readFile(t, filepath.Join(dir, "pkg", "real.txt")) != "ok" {
			t.Errorf("%s: regular file missing", src)
		}
		cleanup()
	}
}

func TestUnpack_Limits(t *testing.T) {
	entries, size := maxUnpackEntries, maxUnpackBytes
	t.Cleanup(func() { maxUnpackEntries, maxUnpackBytes = entries, size })

	maxUnpackEntries, maxUnpackBytes = 2, 1<<20
	src := filepath.Join(t.TempDir(), "many.whl")
	writeZip(t, src, entry{name: "a", body: "1"}, entry{name: "b", body: "2"}, entry{name: "c", body: "3"})
	if _, _, err := unpack(src); !errors.Is(err, errUnpackLimit) {
		t.Errorf("too many entries: err = %v", err)
	}

	maxUnpackEntries, maxUnpackBytes = 100, 10
	src = filepath.Join(t.TempDir(), "bomb.tar.gz")
	writeTarGz(t, src, entry{name: "big", body: strings.Repeat("A", 11)})
	if _, _, err := unpack(src); !errors.Is(err, errUnpackLimit) {
		t.Errorf("too many bytes: err = %v", err)
	}

	src = filepath.Join(t.TempDir(), "exact.tar.gz")
	writeTarGz(t, src, entry{name: "fits", body: strings.Repeat("A", 10)})
	dir, cleanup, err := unpack(src)
	defer cleanup()
	if err != nil || readFile(t, filepath.Join(dir, "fits")) != strings.Repeat("A", 10) {
		t.Errorf("exactly at the limit must unpack: %v", err)
	}
}

// --- Python metadata licenses ---

func TestPythonMetadataLicenses(t *testing.T) {
	cases := map[string]struct {
		file, body string
		want       []string
	}{
		"license field":        {"PKG-INFO", "Metadata-Version: 1.1\nName: PyYAML\nLicense: MIT\n\nlong description\nLicense: GPL\n", []string{"MIT"}},
		"expression wins":      {"PKG-INFO", "Name: x\nLicense: BSD\nLicense-Expression: Apache-2.0 OR MIT\n", []string{"Apache-2.0 OR MIT"}},
		"wheel METADATA":       {"x-1.0.dist-info/METADATA", "Name: x\nLicense: ISC\n", []string{"ISC"}},
		"full text is ignored": {"PKG-INFO", "Name: x\nLicense: Copyright (c) 2020\n        Permission is hereby granted\nAuthor: me\n", nil},
		"UNKNOWN is ignored":   {"PKG-INFO", "Name: x\nLicense: UNKNOWN\n", nil},
		"no license":           {"PKG-INFO", "Name: x\n", nil},
	}
	for name, c := range cases {
		root := t.TempDir()
		path := filepath.Join(root, "x-1.0", c.file)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(c.body), 0o644); err != nil {
			t.Fatal(err)
		}
		if got := pythonMetadataLicenses(root); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %q, want %q", name, got, c.want)
		}
	}
}

func TestPythonMetadataLicenses_DepthLimited(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	// e.g. a vendored package's metadata deep inside the sdist
	if err := os.WriteFile(filepath.Join(deep, "PKG-INFO"), []byte("License: MIT\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := pythonMetadataLicenses(root); got != nil {
		t.Fatalf("read metadata %d levels deep: %q", 3, got)
	}
}

func TestExtractLicenses_PrefersSPDX(t *testing.T) {
	got := extractLicenses(&SyftOutput{Artifacts: []SyftArtifact{{Licenses: []SyftLicense{
		{Value: "https://www.apache.org/licenses/LICENSE-2.0.txt", SPDXExpression: "Apache-2.0"},
		{Value: "Some Custom License"},
	}}}})
	if !slices.Equal(got, []string{"Apache-2.0", "Some Custom License"}) {
		t.Fatalf("got %q", got)
	}
}

// --- Scan, end to end, with stand-in syft and grype ---

// fakeTools writes syft and grype stand-ins that log their arguments (and,
// for a package URL file, its content) and print canned reports.
func fakeTools(t *testing.T, syftReport, grypeReport, purlReport string) (config.Tools, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell stand-ins")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "calls.log")
	for name, body := range map[string]string{
		"syft": `printf '%s\n' "syft $*" >> "$CALLS"
printf 'syft env: GOPROXY=%s GOMODCACHE=%s\n' "$GOPROXY" "$GOMODCACHE" >> "$CALLS"
printf '%s' "$SYFT_REPORT"`,
		"grype": `printf '%s\n' "grype $*" >> "$CALLS"
printf 'grype env: GRYPE_DB_AUTO_UPDATE=%s\n' "$GRYPE_DB_AUTO_UPDATE" >> "$CALLS"
case "$1" in
  db) exit 0 ;;
  purl:*) printf 'purls: %s\n' "$(cat "${1#purl:}")" >> "$CALLS"; printf '%s' "$PURL_REPORT" ;;
  *) printf '%s' "$GRYPE_REPORT" ;;
esac`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("CALLS", log)
	t.Setenv("SYFT_REPORT", syftReport)
	t.Setenv("GRYPE_REPORT", grypeReport)
	t.Setenv("PURL_REPORT", purlReport)
	return config.Tools{Syft: filepath.Join(dir, "syft"), Grype: filepath.Join(dir, "grype")}, log
}

const noMatches = `{"matches": []}`

func TestScan_WheelUnpackedAndLookedUp(t *testing.T) {
	tools, log := fakeTools(t,
		`{"artifacts": [{"name": "requests", "version": "2.32.3", "type": "python", "licenses": [{"value": "Apache-2.0", "spdxExpression": "Apache-2.0"}]}]}`,
		`{"matches": [{"vulnerability": {"id": "GHSA-9hjg-9r4m-mvj7", "severity": "Medium", "fix": {"versions": ["2.32.4"]}, "cvss": []}}]}`,
		`{"matches": [
		   {"vulnerability": {"id": "GHSA-9hjg-9r4m-mvj7", "severity": "Medium", "fix": {"versions": ["2.32.4"]}, "cvss": []}},
		   {"vulnerability": {"id": "GHSA-only-by-purl", "severity": "High", "fix": {"versions": []}, "cvss": []}}]}`,
	)
	src := filepath.Join(t.TempDir(), "requests-2.32.3-py3-none-any.whl")
	writeZip(t, src, entry{name: "requests-2.32.3.dist-info/METADATA", body: "Name: requests\n"})

	res, err := NewOrchestrator(tools, 30).Scan(&resolver.Package{Ecosystem: "pypi", Name: "requests", Version: "2.32.3", Path: src})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	calls := readFile(t, log)
	if !strings.Contains(calls, "syft dir:") || !strings.Contains(calls, "grype dir:") {
		t.Errorf("syft and grype must read the unpacked wheel (dir:), calls:\n%s", calls)
	}
	if !strings.Contains(calls, "purls: pkg:pypi/requests@2.32.3") {
		t.Errorf("grype must look the package up by package URL, calls:\n%s", calls)
	}
	ids := []string{}
	for _, v := range res.Vulnerabilities {
		ids = append(ids, v.ID)
	}
	if !slices.Equal(ids, []string{"GHSA-9hjg-9r4m-mvj7", "GHSA-only-by-purl"}) {
		t.Errorf("vulnerabilities = %v, want both sources merged without duplicates", ids)
	}
	if !slices.Equal(res.Licenses, []string{"Apache-2.0"}) || len(res.Errors) != 0 {
		t.Errorf("licenses %q, errors %q", res.Licenses, res.Errors)
	}
}

func TestScan_SdistLicenseFromMetadata(t *testing.T) {
	tools, _ := fakeTools(t, `{"artifacts": []}`, noMatches,
		`{"matches": [{"vulnerability": {"id": "GHSA-8q59-q68h-6hv4", "severity": "Critical", "fix": {"versions": ["5.4"]}, "cvss": []}}]}`)
	src := filepath.Join(t.TempDir(), "PyYAML-5.3.1.tar.gz")
	writeTarGz(t, src, entry{name: "PyYAML-5.3.1/PKG-INFO", body: "Name: PyYAML\nVersion: 5.3.1\nLicense: MIT\n"})

	res, err := NewOrchestrator(tools, 30).Scan(&resolver.Package{Ecosystem: "pypi", Name: "pyyaml", Version: "5.3.1", Path: src})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if !slices.Equal(res.Licenses, []string{"MIT"}) {
		t.Errorf("licenses = %q, want MIT from PKG-INFO", res.Licenses)
	}
	if len(res.Vulnerabilities) != 1 || res.Vulnerabilities[0].ID != "GHSA-8q59-q68h-6hv4" {
		t.Errorf("vulnerabilities = %+v, want the one found by package URL", res.Vulnerabilities)
	}
}

func TestScan_JarScannedAsFile(t *testing.T) {
	tools, log := fakeTools(t, `{"artifacts": []}`, noMatches, noMatches)
	src := filepath.Join(t.TempDir(), "commons-lang3-3.14.0.jar")
	writeZip(t, src, entry{name: "META-INF/MANIFEST.MF", body: "x"})

	if _, err := NewOrchestrator(tools, 30).Scan(&resolver.Package{Ecosystem: "maven", Name: "org.apache.commons:commons-lang3", Version: "3.14.0", Path: src}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	calls := readFile(t, log)
	if !strings.Contains(calls, "syft "+src+" ") || strings.Contains(calls, "dir:") {
		t.Errorf("a jar is scanned as a file, calls:\n%s", calls)
	}
	if !strings.Contains(calls, "purls: pkg:maven/org.apache.commons/commons-lang3@3.14.0") {
		t.Errorf("missing package URL lookup, calls:\n%s", calls)
	}
}

func TestScan_UnpackFailureIsReportedAndFileStillScanned(t *testing.T) {
	tools, log := fakeTools(t, `{"artifacts": []}`, noMatches, noMatches)
	src := filepath.Join(t.TempDir(), "broken-1.0.tar.gz")
	if err := os.WriteFile(src, []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := NewOrchestrator(tools, 30).Scan(&resolver.Package{Ecosystem: "pypi", Name: "broken", Version: "1.0", Path: src})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Errors) != 1 || !strings.Contains(res.Errors[0], "unpack") {
		t.Errorf("errors = %q, want the unpack failure", res.Errors)
	}
	if !strings.Contains(readFile(t, log), "syft "+src+" ") {
		t.Error("the file must still be scanned as is")
	}
}

// syft must never run go against a real module cache or the network: for a
// module with dependencies, go downloads all of them (into a watched cache,
// where gated would gate each download).
func TestScan_SyftKeptOffGoNetworkAndCaches(t *testing.T) {
	tools, log := fakeTools(t, `{"artifacts": []}`, noMatches, noMatches)
	dir := t.TempDir()
	jar := filepath.Join(dir, "x-1.0.jar")
	if err := os.WriteFile(jar, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOMODCACHE", filepath.Join(dir, "real-cache"))
	t.Setenv("GOPROXY", "https://proxy.golang.org")
	if _, err := NewOrchestrator(tools, 30).Scan(&resolver.Package{Ecosystem: "maven", Name: "g:x", Version: "1.0", Path: jar}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(log)
	var env string
	for line := range strings.SplitSeq(string(b), "\n") {
		if strings.HasPrefix(line, "syft env:") {
			env = line
		}
	}
	if !strings.Contains(env, "GOPROXY=off") || strings.Contains(env, "real-cache") || !strings.Contains(env, "gated-syft-gomodcache-") {
		t.Errorf("syft ran with %q: want GOPROXY=off and a throwaway GOMODCACHE", env)
	}
}

// Scans stop checking for a database update once gated keeps it fresh: a
// refresh inside a scan took 80 s, and a package manager's piped output
// waited for that verdict all along.
func TestScan_NoDBUpdateOnceKeptFresh(t *testing.T) {
	tools, log := fakeTools(t, `{"artifacts": []}`, noMatches, noMatches)
	jar := filepath.Join(t.TempDir(), "x-1.0.jar")
	if err := os.WriteFile(jar, []byte("PK"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := NewOrchestrator(tools, 30)
	pkg := &resolver.Package{Ecosystem: "maven", Name: "g:x", Version: "1.0", Path: jar}
	updates := func() (on, off int) {
		b, _ := os.ReadFile(log)
		for line := range strings.SplitSeq(string(b), "\n") {
			switch line {
			case "grype env: GRYPE_DB_AUTO_UPDATE=":
				on++
			case "grype env: GRYPE_DB_AUTO_UPDATE=false":
				off++
			}
		}
		return on, off
	}
	if _, err := o.Scan(pkg); err != nil {
		t.Fatal(err)
	}
	if on, off := updates(); on != 2 || off != 0 {
		t.Fatalf("before a refresh: %d scans may update, %d may not; want both to (a missing DB must still be fetched)", on, off)
	}
	o.updateDB(t.Context())
	_ = os.Truncate(log, 0)
	if _, err := o.Scan(pkg); err != nil {
		t.Fatal(err)
	}
	if on, off := updates(); on != 0 || off != 2 {
		t.Fatalf("after a refresh: %d grype runs may update, %d may not", on, off)
	}
}

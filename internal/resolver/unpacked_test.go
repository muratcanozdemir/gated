package resolver

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestResolveInPlaceGoZip(t *testing.T) {
	root := "/home/u/go/pkg/mod"
	zip := root + "/cache/download/github.com/!azure/azure-sdk-for-go/@v/v1.2.0.zip"
	ip := ResolveInPlace(zip, "go")
	if ip == nil {
		t.Fatal("not resolved")
	}
	if ip.Pkg.Name != "github.com/Azure/azure-sdk-for-go" || ip.Pkg.Version != "v1.2.0" {
		t.Errorf("identity %s@%s: the module path must be unescaped", ip.Pkg.Name, ip.Pkg.Version)
	}
	want := []string{
		zip,
		root + "/cache/download/github.com/!azure/azure-sdk-for-go/@v/v1.2.0.ziphash",
		root + "/github.com/!azure/azure-sdk-for-go@v1.2.0", // on disk: escaped
	}
	if ip.Root != root || !reflect.DeepEqual(ip.Remove, want) {
		t.Errorf("root %s, remove %v; want %s, %v", ip.Root, ip.Remove, root, want)
	}
	for _, notZip := range []string{
		root + "/cache/download/github.com/x/y/@v/v1.0.0.mod",
		root + "/cache/download/github.com/x/y/@v/list",
		root + "/github.com/x/y@v1.0.0/testdata/a.zip",
	} {
		if ip := ResolveInPlace(notZip, "go"); ip != nil {
			t.Errorf("%s resolved in place: %+v", notZip, ip)
		}
	}
}

func TestResolveInPlaceUVArchive(t *testing.T) {
	cache := t.TempDir()
	dir := filepath.Join(cache, "archive-v0", "Xy12")
	info := filepath.Join(dir, "Django-3.2.dist-info")
	if err := os.MkdirAll(info, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(info, "METADATA"), []byte("Metadata-Version: 2.1\nName: Django\nVersion: 3.2\n\nName: not-a-header\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ip := ResolveInPlace(dir, "pypi")
	if ip == nil || ip.Pkg.Name != "django" || ip.Pkg.Version != "3.2" || ip.Root != cache || !reflect.DeepEqual(ip.Remove, []string{dir}) {
		t.Fatalf("ResolveInPlace = %+v", ip)
	}
	if ip := ResolveInPlace(filepath.Join(cache, "archive-v0", "empty"), "pypi"); ip != nil {
		t.Errorf("a directory without metadata resolved: %+v", ip)
	}
	if ip := ResolveInPlace(filepath.Join(cache, "wheels-v5", "Xy12"), "pypi"); ip != nil {
		t.Errorf("a directory outside archive-v0 resolved: %+v", ip)
	}
}

func TestIsUnpackedContent(t *testing.T) {
	for _, c := range []struct {
		path, eco string
		want      bool
	}{
		{"/m/golang.org/x/text@v0.3.5/unicode/testdata/a.gz", "go", true},
		{"/m/golang.org/x/text@v0.3.5.tmp-123/a.zip", "go", true},
		{"/m/golang.org/x/text@v0.3.5", "go", true}, // judged through its zip
		{"/m/cache/download/golang.org/x/text/@v/v0.3.5.zip", "go", false},
		{"/m/golang.org/x", "go", false},
		{"/c/uv/archive-v0/Xy12/django/a.gz", "pypi", true},
		{"/c/uv/archive-v0/Xy12", "pypi", false}, // the package itself
		{"/c/uv/archive-v0", "pypi", false},
		{"/c/pip/Django-3.2.tar.gz", "pypi", false},
		{"/r/org/x/1.0/x@1.0.jar", "maven", false},
	} {
		if got := IsUnpackedContent(c.path, c.eco); got != c.want {
			t.Errorf("IsUnpackedContent(%s, %s) = %v, want %v", c.path, c.eco, got, c.want)
		}
	}
}

func TestUnescapeGoPath(t *testing.T) {
	for in, want := range map[string]string{
		"github.com/!burnt!sushi/toml": "github.com/BurntSushi/toml",
		"golang.org/x/text":            "golang.org/x/text",
		"v1.0.0-!r!c1":                 "v1.0.0-RC1",
	} {
		if got := unescapeGoPath(in); got != want {
			t.Errorf("unescapeGoPath(%q) = %q, want %q", in, got, want)
		}
	}
}

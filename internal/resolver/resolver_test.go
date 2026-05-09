package resolver

import (
	"testing"
)

func TestResolvePyPI(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantPkg *Package
	}{
		{
			name: "wheel",
			path: "/home/user/.cache/uv/wheels-v1/abc123/requests-2.31.0-py3-none-any.whl",
			wantPkg: &Package{
				Ecosystem: "pypi",
				Name:      "requests",
				Version:   "2.31.0",
			},
		},
		{
			name: "wheel with underscores",
			path: "/home/user/.cache/pip/wheels/a/b/c/urllib3-2.1.0-py3-none-any.whl",
			wantPkg: &Package{
				Ecosystem: "pypi",
				Name:      "urllib3",
				Version:   "2.1.0",
			},
		},
		{
			name: "sdist tarball",
			path: "/home/user/.cache/uv/archive-v0/hash/flask-3.0.0.tar.gz",
			wantPkg: &Package{
				Ecosystem: "pypi",
				Name:      "flask",
				Version:   "3.0.0",
			},
		},
		{
			name: "non-artifact",
			path: "/home/user/.cache/uv/some-metadata.json",
			wantPkg: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.path, "pypi")
			if tt.wantPkg == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected package, got nil")
			}
			if got.Name != tt.wantPkg.Name {
				t.Errorf("name: got %q, want %q", got.Name, tt.wantPkg.Name)
			}
			if got.Version != tt.wantPkg.Version {
				t.Errorf("version: got %q, want %q", got.Version, tt.wantPkg.Version)
			}
			if got.Ecosystem != tt.wantPkg.Ecosystem {
				t.Errorf("ecosystem: got %q, want %q", got.Ecosystem, tt.wantPkg.Ecosystem)
			}
		})
	}
}

func TestResolveGo(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantPkg *Package
	}{
		{
			name: "module zip",
			path: "/home/user/go/pkg/mod/cache/download/github.com/stretchr/testify/@v/v1.9.0.zip",
			wantPkg: &Package{
				Ecosystem: "go",
				Name:      "github.com/stretchr/testify",
				Version:   "v1.9.0",
			},
		},
		{
			name: "module mod file",
			path: "/home/user/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.29.0.mod",
			wantPkg: &Package{
				Ecosystem: "go",
				Name:      "golang.org/x/sys",
				Version:   "v0.29.0",
			},
		},
		{
			name: "info file skipped",
			path: "/home/user/go/pkg/mod/cache/download/golang.org/x/sys/@v/v0.29.0.info",
			wantPkg: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.path, "go")
			if tt.wantPkg == nil {
				if got != nil {
					t.Errorf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected package, got nil")
			}
			if got.Name != tt.wantPkg.Name {
				t.Errorf("name: got %q, want %q", got.Name, tt.wantPkg.Name)
			}
			if got.Version != tt.wantPkg.Version {
				t.Errorf("version: got %q, want %q", got.Version, tt.wantPkg.Version)
			}
		})
	}
}

func TestResolveMaven(t *testing.T) {
	got := Resolve("/home/user/.m2/repository/org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar", "maven")
	if got == nil {
		t.Fatal("expected package, got nil")
	}
	if got.Name != "org.apache.commons:commons-lang3" {
		t.Errorf("name: got %q, want %q", got.Name, "org.apache.commons:commons-lang3")
	}
	if got.Version != "3.14.0" {
		t.Errorf("version: got %q, want %q", got.Version, "3.14.0")
	}
}

func TestResolveCargo(t *testing.T) {
	got := Resolve("/home/user/.cargo/registry/cache/crates.io-abc123/serde-1.0.197.crate", "cargo")
	if got == nil {
		t.Fatal("expected package, got nil")
	}
	if got.Name != "serde" {
		t.Errorf("name: got %q, want %q", got.Name, "serde")
	}
	if got.Version != "1.0.197" {
		t.Errorf("version: got %q, want %q", got.Version, "1.0.197")
	}
}

func TestResolveUnknownEcosystem(t *testing.T) {
	got := Resolve("/some/path/artifact.bin", "unknown")
	if got != nil {
		t.Errorf("expected nil for unknown ecosystem, got %+v", got)
	}
}

func TestNormalizePyPIName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Flask", "flask"},
		{"my_package", "my-package"},
		{"My.Package", "my-package"},
		{"already-normal", "already-normal"},
	}
	for _, tt := range tests {
		got := normalizePyPIName(tt.input)
		if got != tt.want {
			t.Errorf("normalizePyPIName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

package watcher

import (
	"testing"

	"github.com/muratcanozdemir/gated/internal/config"
)

func TestResolveEcosystem(t *testing.T) {
	paths := []config.WatchPath{
		{Path: "/home/user/.cache/uv", Ecosystem: "pypi"},
		{Path: "/home/user/go/pkg/mod/cache", Ecosystem: "go"},
	}

	tests := []struct {
		name string
		path string
		want string
	}{
		{"matches first prefix", "/home/user/.cache/uv/requests-2.31.0.whl", "pypi"},
		{"matches second prefix", "/home/user/go/pkg/mod/cache/download/x.zip", "go"},
		{"no match", "/home/user/.cargo/registry/pkg.crate", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveEcosystem(paths, tt.path); got != tt.want {
				t.Errorf("resolveEcosystem(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsMetadataFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/proj/go.sum", true},
		{"/proj/go.mod", true},
		{"/proj/package-lock.json", true},
		{"/proj/yarn.lock", true},
		{"/proj/Cargo.lock", true},
		{"/proj/Cargo.toml", true},
		{"/proj/requirements.txt", true},
		{"/proj/pyproject.toml", true},
		{"/proj/pkg-1.0.pom", true},
		{"/proj/metadata.xml", true},
		{"/proj/.hidden", true},
		{"/proj/requests-2.31.0.whl", false},
		{"/proj/pkg.tar.gz", false},
	}
	for _, tt := range tests {
		if got := isMetadataFile(tt.path); got != tt.want {
			t.Errorf("isMetadataFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestIsArtifactFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/proj/requests-2.31.0-py3-none-any.whl", true},
		{"/proj/pkg.jar", true},
		{"/proj/pkg.crate", true},
		{"/proj/pkg.tgz", true},
		{"/proj/pkg.egg", true},
		{"/proj/pkg.zip", true},
		{"/proj/pkg.tar.gz", true},
		{"/proj/go.sum", false},
		{"/proj/README.md", false},
		{"/proj/noext", false},
	}
	for _, tt := range tests {
		if got := isArtifactFile(tt.path); got != tt.want {
			t.Errorf("isArtifactFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

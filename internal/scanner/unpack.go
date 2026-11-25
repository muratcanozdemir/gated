package scanner

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Limits for unpacking an untrusted artifact before scanning it. A package
// that exceeds them is not unpacked; it is scanned as a file and the reason
// is recorded as a scan error. Variables so tests can lower them.
var (
	maxUnpackEntries int64 = 50_000
	maxUnpackBytes   int64 = 1 << 30 // 1 GiB uncompressed
)

var errUnpackLimit = errors.New("archive exceeds unpack limits")

// unpack extracts an artifact that the scanners cannot read as a file into a
// new temporary directory, and returns that directory. syft (and grype, which
// builds on it) catalog nothing in a wheel, sdist, npm tarball or crate given
// as a file; unpacked, they find the package metadata inside. Jars are read
// natively, so they and unknown types return "" (scan the file as is).
//
// The artifact is untrusted: entries that would land outside the directory
// (absolute paths, "..") are refused, links and special files are skipped,
// and the entry count and total size are capped.
func unpack(path string) (dir string, cleanup func(), err error) {
	var extract func(src, dst string) error
	switch name := strings.ToLower(filepath.Base(path)); {
	case strings.HasSuffix(name, ".whl"), strings.HasSuffix(name, ".egg"), strings.HasSuffix(name, ".zip"):
		extract = unzip
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"), strings.HasSuffix(name, ".crate"):
		extract = untarGz
	default:
		return "", func() {}, nil
	}

	dir, err = os.MkdirTemp("", "gated-scan-*")
	if err != nil {
		return "", func() {}, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	if err := extract(path, dir); err != nil {
		cleanup()
		return "", func() {}, fmt.Errorf("unpack %s: %w", filepath.Base(path), err)
	}
	return dir, cleanup, nil
}

// budget tracks what an extraction may still write.
type budget struct{ entries, bytes int64 }

func newBudget() *budget { return &budget{entries: maxUnpackEntries, bytes: maxUnpackBytes} }

// target maps an archive entry name to a path under dst, refusing names
// that would escape it.
func target(dst, name string) (string, error) {
	clean := filepath.FromSlash(strings.TrimPrefix(name, "./"))
	if clean == "" || clean == "." {
		return "", nil
	}
	if !filepath.IsLocal(clean) {
		return "", fmt.Errorf("entry %q escapes the archive", name)
	}
	return filepath.Join(dst, clean), nil
}

// write copies one regular file into place within the budget.
func (b *budget) write(path string, r io.Reader) error {
	b.entries--
	if b.entries < 0 {
		return errUnpackLimit
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	// Copy one byte past the budget to tell "exactly full" from "too big".
	n, err := io.CopyN(f, r, b.bytes+1)
	if cerr := f.Close(); err == nil || errors.Is(err, io.EOF) {
		err = cerr
	}
	b.bytes -= n
	if b.bytes < 0 {
		return errUnpackLimit
	}
	return err
}

func (b *budget) mkdir(path string) error {
	b.entries--
	if b.entries < 0 {
		return errUnpackLimit
	}
	return os.MkdirAll(path, 0o700)
}

func unzip(src, dst string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()

	b := newBudget()
	for _, f := range zr.File {
		path, err := target(dst, f.Name)
		if err != nil || path == "" {
			if err != nil {
				return err
			}
			continue
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			err = b.mkdir(path)
		case mode.IsRegular():
			var rc io.ReadCloser
			if rc, err = f.Open(); err == nil {
				err = b.write(path, rc)
				_ = rc.Close()
			}
		default:
			continue // symlinks and special files: not needed to find package metadata
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func untarGz(src, dst string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	b := newBudget()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		path, err := target(dst, h.Name)
		if err != nil {
			return err
		}
		if path == "" {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			err = b.mkdir(path)
		case tar.TypeReg:
			err = b.write(path, tr)
		default:
			continue // links, devices, PAX/global headers: skipped
		}
		if err != nil {
			return err
		}
	}
}

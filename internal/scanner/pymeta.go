package scanner

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// pythonMetadataLicenses reads the license of an unpacked Python package
// from its core metadata (PKG-INFO in an sdist, METADATA in a wheel's
// .dist-info), for when syft reports none: syft catalogs nothing in an sdist,
// even unpacked. It looks at most two directories deep, where sdists and
// wheels keep that file.
//
// PEP 639 License-Expression (an SPDX expression) wins; otherwise a License
// field that reads as an identifier ("MIT", "Apache-2.0"). Many packages put
// the whole license text in License: that is not an identifier, and is
// ignored rather than guessed at, so the policy sees no license.
func pythonMetadataLicenses(root string) []string {
	var found []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() {
			if depth >= 2 {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "PKG-INFO" && d.Name() != "METADATA" {
			return nil
		}
		if l := licenseFromMetadata(path); l != "" {
			found = append(found, l)
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// licenseFromMetadata parses the header block of a core metadata file.
func licenseFromMetadata(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	var expression, license string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	continuation := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			break // end of headers; the description follows
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if continuation {
				license = "" // a multi-line License field is license text
			}
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		continuation = false
		switch strings.ToLower(key) {
		case "license-expression":
			expression = value
		case "license":
			license = value
			continuation = true
		}
	}
	if expression != "" {
		return expression
	}
	if looksLikeIdentifier(license) {
		return license
	}
	return ""
}

func looksLikeIdentifier(s string) bool {
	return s != "" && len(s) <= 64 && !strings.EqualFold(s, "UNKNOWN") && !strings.ContainsAny(s, "\n\r")
}

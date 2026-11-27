package resolver

import (
	"archive/zip"
	"bufio"
	"io"
	"path/filepath"
	"strings"
)

// ResolveMavenJar identifies a jar whose path does not say its group: a local
// repository that is not under a "repository/" directory (Maven's
// -Dmaven.repo.local=/build/m2, a CI cache), where resolveMaven gives up and
// the jar went through unscanned. Maven-built jars carry their coordinates in
// META-INF/maven/<group>/<artifact>/pom.properties; those are trusted only as
// far as the path agrees (.../<artifact>/<version>/<artifact>-<version>*.jar),
// so a jar cannot pass itself off as some other package.
//
// idPath is where the jar is going (its layout gives artifact and version);
// jarPath is where its bytes are now (the quarantine hold file).
func ResolveMavenJar(idPath, jarPath string) *Package {
	if !strings.HasSuffix(idPath, ".jar") {
		return nil
	}
	versionDir := filepath.Dir(idPath)
	version := filepath.Base(versionDir)
	artifact := filepath.Base(filepath.Dir(versionDir))
	if !strings.HasPrefix(filepath.Base(idPath), artifact+"-"+version) {
		return nil
	}

	zr, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil
	}
	defer zr.Close()
	for _, f := range zr.File {
		dir, name := f.Name[:strings.LastIndex(f.Name, "/")+1], f.Name[strings.LastIndex(f.Name, "/")+1:]
		if name != "pom.properties" || !strings.HasPrefix(dir, "META-INF/maven/") || !strings.HasSuffix(dir, "/"+artifact+"/") {
			continue
		}
		props := readProperties(f)
		if props["artifactId"] != artifact || props["version"] != version || props["groupId"] == "" {
			continue
		}
		return &Package{Ecosystem: "maven", Name: props["groupId"] + ":" + artifact, Version: version, Path: idPath}
	}
	return nil
}

// readProperties reads key=value lines from a small properties file.
func readProperties(f *zip.File) map[string]string {
	props := map[string]string{}
	rc, err := f.Open()
	if err != nil {
		return props
	}
	defer rc.Close()
	sc := bufio.NewScanner(io.LimitReader(rc, 64<<10))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			props[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return props
}

package releasepkg

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type releaseFile struct {
	Source string
	Target string
	Mode   fs.FileMode
}

// This allowlist is the complete source-backed, non-binary 3.x release
// surface. The packager also generates a minimal 2.x upgrade bridge; no
// legacy installer implementation is copied from the source tree.
var releaseFiles = [...]releaseFile{
	{Source: ".env.example", Target: ".env.example", Mode: 0o644},
	{Source: "CHANGELOG.md", Target: "CHANGELOG.md", Mode: 0o644},
	{Source: "LICENSE", Target: "LICENSE", Mode: 0o644},
	{Source: "README.md", Target: "README.md", Mode: 0o644},
	{Source: "README.en.md", Target: "README.en.md", Mode: 0o644},
	{Source: "VERSION", Target: "VERSION", Mode: 0o644},
	{Source: "sun.sh", Target: "sun.sh", Mode: 0o755},
	{Source: "files/needrestart-report-only.conf", Target: "files/needrestart-report-only.conf", Mode: 0o644},
	{Source: "files/release-signing.pub.asc", Target: "files/release-signing.pub.asc", Mode: 0o644},
	{Source: "files/security-update-notify.logrotate", Target: "files/security-update-notify.logrotate", Mode: 0o644},
	{Source: "files/security-update-notify.service", Target: "files/security-update-notify.service", Mode: 0o644},
}

const compatibilityInstallShim = `#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  i386|i486|i586|i686) arch=386 ;;
  ppc64le) arch=ppc64le ;;
  s390x) arch=s390x ;;
  *)
    printf '%s\n' "security-update-notify 3.x does not support this architecture" >&2
    exit 2
    ;;
esac

runtime="./files/security-update-notify-linux-$arch"
if [ ! -f "$runtime" ] || [ ! -x "$runtime" ]; then
  printf '%s\n' "verified Go installer is missing for linux/$arch" >&2
  exit 1
fi
exec "$runtime" install "$@"
`

func validateRegularSource(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("must be a regular file, got mode %s", info.Mode())
	}
	return nil
}

func preparePackageTree(root, pkgDir, version string) error {
	if err := os.MkdirAll(filepath.Join(pkgDir, "files"), 0o755); err != nil {
		return fmt.Errorf("create package tree: %w", err)
	}
	if err := os.Chmod(pkgDir, 0o755); err != nil {
		return fmt.Errorf("normalize package directory mode: %w", err)
	}
	if err := os.Chmod(filepath.Join(pkgDir, "files"), 0o755); err != nil {
		return fmt.Errorf("normalize files directory mode: %w", err)
	}
	for _, spec := range releaseFiles {
		if err := copyRegularFile(
			filepath.Join(root, filepath.FromSlash(spec.Source)),
			filepath.Join(pkgDir, filepath.FromSlash(spec.Target)),
			spec.Mode,
		); err != nil {
			return fmt.Errorf("copy release source %s: %w", spec.Source, err)
		}
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "install.sh"), []byte(compatibilityInstallShim), 0o755); err != nil {
		return fmt.Errorf("write 2.x compatibility installer: %w", err)
	}
	if err := os.Chmod(filepath.Join(pkgDir, "install.sh"), 0o755); err != nil {
		return fmt.Errorf("normalize 2.x compatibility installer mode: %w", err)
	}
	marker := []byte("VERSION=\"" + version + "\"\n")
	if err := os.WriteFile(filepath.Join(pkgDir, "files", productName), marker, 0o644); err != nil {
		return fmt.Errorf("write 2.x compatibility version marker: %w", err)
	}
	if err := os.Chmod(filepath.Join(pkgDir, "files", productName), 0o644); err != nil {
		return fmt.Errorf("normalize 2.x compatibility marker mode: %w", err)
	}
	return nil
}

func copyRegularFile(source, target string, mode fs.FileMode) error {
	if err := validateRegularSource(source); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = out.Close()
		if !ok {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(out, io.LimitReader(in, maxUncompressedSize+1)); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Chmod(target, mode); err != nil {
		return err
	}
	ok = true
	return nil
}

func expectedPackagePaths() map[string]fs.FileMode {
	want := map[string]fs.FileMode{
		".":                    fs.ModeDir | 0o755,
		"files":                fs.ModeDir | 0o755,
		"install.sh":           0o755,
		"files/" + productName: 0o644,
	}
	for _, spec := range releaseFiles {
		want[filepath.FromSlash(spec.Target)] = spec.Mode
	}
	for _, arch := range officialArches {
		want[filepath.Join("files", productName+"-linux-"+arch)] = 0o755
	}
	return want
}

func validatePackageTree(pkgDir, version string) error {
	want := expectedPackagePaths()
	seen := make(map[string]bool, len(want))
	var total int64
	err := filepath.WalkDir(pkgDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(pkgDir, path)
		if err != nil {
			return err
		}
		expectedMode, ok := want[rel]
		if !ok {
			return fmt.Errorf("unexpected package path %q", filepath.ToSlash(rel))
		}
		if forbiddenReleasePath(filepath.ToSlash(rel)) {
			return fmt.Errorf("private, credential, or state path is forbidden in release: %q", filepath.ToSlash(rel))
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is forbidden in release: %q", filepath.ToSlash(rel))
		}
		if d.IsDir() {
			if expectedMode&fs.ModeDir == 0 {
				return fmt.Errorf("expected regular file at %q", filepath.ToSlash(rel))
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("special file is forbidden in release: %q", filepath.ToSlash(rel))
		}
		if info.Mode().Perm() != expectedMode.Perm() {
			return fmt.Errorf("unexpected mode for %q: %04o", filepath.ToSlash(rel), info.Mode().Perm())
		}
		if info.Mode().IsRegular() {
			if info.Size() < 0 || total > maxUncompressedSize-info.Size() {
				return fmt.Errorf("release payload exceeds %d bytes", maxUncompressedSize)
			}
			total += info.Size()
		}
		seen[rel] = true
		return nil
	})
	if err != nil {
		return fmt.Errorf("validate package tree: %w", err)
	}
	for path := range want {
		if !seen[path] {
			return fmt.Errorf("validate package tree: missing %q", filepath.ToSlash(path))
		}
	}
	b, err := os.ReadFile(filepath.Join(pkgDir, "VERSION"))
	if err != nil {
		return fmt.Errorf("read package VERSION: %w", err)
	}
	if string(b) != "VERSION=\""+version+"\"\n" {
		return fmt.Errorf("package VERSION does not match %s", version)
	}
	shim, err := os.ReadFile(filepath.Join(pkgDir, "install.sh"))
	if err != nil {
		return fmt.Errorf("read 2.x compatibility installer: %w", err)
	}
	if string(shim) != compatibilityInstallShim {
		return errors.New("2.x compatibility installer content mismatch")
	}
	marker, err := os.ReadFile(filepath.Join(pkgDir, "files", productName))
	if err != nil {
		return fmt.Errorf("read 2.x compatibility version marker: %w", err)
	}
	if string(marker) != "VERSION=\""+version+"\"\n" {
		return errors.New("2.x compatibility version marker mismatch")
	}
	return nil
}

func forbiddenReleasePath(path string) bool {
	if path == "." || path == "files" || path == "VERSION" {
		return false
	}
	base := strings.ToLower(filepath.Base(path))
	parts := strings.Split(strings.ToLower(filepath.ToSlash(path)), "/")
	for _, part := range parts {
		if part == ".git" || part == "credentials" || strings.HasPrefix(part, "credstore") {
			return true
		}
	}
	if base == ".env.example" {
		return false
	}
	return base == ".env" || strings.HasPrefix(base, ".env.") || base == "telegram.env" ||
		strings.HasSuffix(base, ".local.md") || strings.HasSuffix(base, ".log") ||
		strings.HasPrefix(base, "last-alert") || strings.Contains(base, "feishu-app-secret")
}

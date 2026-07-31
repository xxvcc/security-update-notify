package releasepkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/xxvcc/security-update-notify/internal/assets"
)

func TestValidateVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"3.0.0", "3.0.0-rc1", "3.0.0.1"} {
		if err := ValidateVersion(version); err != nil {
			t.Errorf("ValidateVersion(%q): %v", version, err)
		}
	}
	for _, version := range []string{"", "v3.0.0", "3.0", "3.0.0_rc1", "3.0.0-01", "3.0.0-rc.1", "3.0.0/evil", strings.Repeat("1", 65)} {
		if err := ValidateVersion(version); err == nil {
			t.Errorf("ValidateVersion(%q) unexpectedly succeeded", version)
		}
	}
}

func TestReadVersionStrict(t *testing.T) {
	t.Parallel()
	valid := map[string]string{
		"stable":     "VERSION=\"3.0.0\"\n",
		"prerelease": "VERSION=\"3.0.0-rc1\"\n",
	}
	for name, content := range valid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			got, err := ReadVersion(root)
			if err != nil || got != strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(content, "\n"), `VERSION="`), `"`) {
				t.Fatalf("ReadVersion()=(%q,%v)", got, err)
			}
		})
	}
	invalid := map[string]string{
		"empty":           "",
		"missing newline": "VERSION=\"3.0.0\"",
		"extra line":      "VERSION=\"3.0.0\"\nextra\n",
		"leading space":   " VERSION=\"3.0.0\"\n",
		"unquoted":        "VERSION=3.0.0\n",
		"v prefix":        "VERSION=\"v3.0.0\"\n",
		"unsafe":          "VERSION=\"3.0.0/../../x\"\n",
	}
	for name, content := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadVersion(root); err == nil {
				t.Fatalf("ReadVersion accepted %q", content)
			}
		})
	}
}

func TestReadVersionRejectsMissingAndSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if _, err := ReadVersion(root); err == nil || !strings.Contains(err.Error(), "canonical VERSION") {
		t.Fatalf("missing VERSION error=%v", err)
	}
	target := filepath.Join(root, "actual")
	if err := os.WriteFile(target, []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("actual", filepath.Join(root, "VERSION")); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVersion(root); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked VERSION error=%v", err)
	}
}

func TestBuildRejectsVersionAssertionMismatchBeforePackaging(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), Options{Root: root, Version: "3.0.1", Sign: SignOff})
	if err == nil || !strings.Contains(err.Error(), `does not match canonical VERSION "3.0.0"`) {
		t.Fatalf("version mismatch error=%v", err)
	}
}

func TestBuildRejectsSignOffForOfficialRelease(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	for _, test := range []struct {
		name    string
		release bool
		tag     bool
	}{
		{name: "explicit release flag", release: true},
		{name: "annotated version tag", tag: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := sourceFixture(t, "3.0.0")
			gitRun(t, root, "init", "-q")
			gitRun(t, root, "config", "user.name", "SUN test")
			gitRun(t, root, "config", "user.email", "sun@example.invalid")
			gitRun(t, root, "add", ".")
			gitRun(t, root, "commit", "-qm", "release fixture")
			if test.tag {
				gitRun(t, root, "tag", "-am", "v3.0.0", "v3.0.0")
			}

			_, err := Build(context.Background(), Options{
				Root: root, DistDir: filepath.Join(root, "dist"), Release: test.release, Sign: SignOff,
			})
			if err == nil || !strings.Contains(err.Error(), "official releases cannot disable signing") {
				t.Fatalf("Build() error=%v, want official SignOff rejection", err)
			}
			if _, statErr := os.Stat(filepath.Join(root, "dist")); !os.IsNotExist(statErr) {
				t.Fatalf("official SignOff created dist before rejection: %v", statErr)
			}
		})
	}
}

func TestParseSignMode(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]SignMode{
		"": SignAuto, "auto": SignAuto, "required": SignRequired,
		"yes": SignRequired, "1": SignRequired, "off": SignOff, "no": SignOff, "0": SignOff,
	} {
		got, err := ParseSignMode(input)
		if err != nil || got != want {
			t.Errorf("ParseSignMode(%q)=(%q,%v), want %q", input, got, err, want)
		}
	}
	if _, err := ParseSignMode("sometimes"); err == nil {
		t.Fatal("invalid signing mode unexpectedly succeeded")
	}
}

func TestValidateSourcesRequiresExactChangelogAndRegularFiles(t *testing.T) {
	t.Parallel()
	root := sourceFixture(t, "3.0.0")
	if err := validateSources(root, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "CHANGELOG.md"), []byte("## 3.0.0\n## 3.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil {
		t.Fatal("duplicate changelog heading unexpectedly succeeded")
	}
	if err := os.Remove(filepath.Join(root, "sun.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("README.md", filepath.Join(root, "sun.sh")); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("symlinked release source error=%v", err)
	}
}

func TestValidateSourcesRejectsEmbeddedAssetAndFingerprintDrift(t *testing.T) {
	t.Parallel()
	root := sourceFixture(t, "3.0.0")
	asset := filepath.Join(root, "files", "security-update-notify.service")
	if err := os.WriteFile(asset, []byte("drift\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "embedded copy") {
		t.Fatalf("asset drift error=%v", err)
	}
	root = sourceFixture(t, "3.0.0")
	sun := filepath.Join(root, "sun.sh")
	if err := os.WriteFile(sun, []byte("#!/bin/sh\nRELEASE_SIGNING_FINGERPRINT=\""+strings.Repeat("0", 40)+"\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "pinned release fingerprint") {
		t.Fatalf("bootstrap fingerprint drift error=%v", err)
	}
	root = sourceFixture(t, "3.0.0")
	sun = filepath.Join(root, "sun.sh")
	b, err := os.ReadFile(sun)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, assets.ReleaseSigningPublicKey(), []byte("different-key\n"), 1)
	if err := os.WriteFile(sun, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "public key differs") {
		t.Fatalf("bootstrap public-key drift error=%v", err)
	}
	root = sourceFixture(t, "3.0.0")
	sun = filepath.Join(root, "sun.sh")
	b, err = os.ReadFile(sun)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`BOOTSTRAP_SIGNATURE_ASSET="sun.sh.asc"`), []byte(`BOOTSTRAP_SIGNATURE_ASSET="other.asc"`), 1)
	if err := os.WriteFile(sun, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "bootstrap signature asset") {
		t.Fatalf("bootstrap signature-asset drift error=%v", err)
	}
	root = sourceFixture(t, "3.0.0")
	sun = filepath.Join(root, "sun.sh")
	b, err = os.ReadFile(sun)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`BOOTSTRAP_VERSION_NOTATION="release-version@xxv.cc"`), []byte(`BOOTSTRAP_VERSION_NOTATION="other@xxv.cc"`), 1)
	if err := os.WriteFile(sun, b, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSources(root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "bootstrap version notation") {
		t.Fatalf("bootstrap version-notation drift error=%v", err)
	}
}

func TestPackageTreeIsExactGoRuntimeAllowlistWithMigrationBridge(t *testing.T) {
	t.Parallel()
	root := sourceFixture(t, "3.0.0")
	pkg := filepath.Join(t.TempDir(), "security-update-notify-3.0.0")
	if err := preparePackageTree(root, pkg, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	writeDummyBinaries(t, pkg)
	if err := validatePackageTree(pkg, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"menu.sh", "test.sh", "uninstall.sh", "files/lib.sh"} {
		if _, err := os.Lstat(filepath.Join(pkg, filepath.FromSlash(forbidden))); !os.IsNotExist(err) {
			t.Errorf("legacy shell path entered package: %s", forbidden)
		}
	}
	if got, err := os.ReadFile(filepath.Join(pkg, "install.sh")); err != nil || string(got) != compatibilityInstallShim {
		t.Fatalf("generated compatibility installer=(%q,%v)", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(pkg, "files", productName)); err != nil || string(got) != "VERSION=\"3.0.0\"\n" {
		t.Fatalf("generated compatibility marker=(%q,%v)", got, err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validatePackageTree(pkg, "3.0.0"); err == nil || !strings.Contains(err.Error(), "unexpected package path") {
		t.Fatalf("unexpected file error=%v", err)
	}
}

func TestCopyRegularFileRejectsHardLinkedSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	alias := filepath.Join(dir, "alias")
	if err := os.WriteFile(source, []byte("source bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(source, alias); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := copyRegularFile(source, target, 0o644); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("hard-linked source error=%v", err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("hard-link rejection created target: %v", err)
	}
}

func TestDeterministicArchiveMetadataAndContents(t *testing.T) {
	t.Parallel()
	root := sourceFixture(t, "3.0.0")
	pkg := filepath.Join(t.TempDir(), "security-update-notify-3.0.0")
	if err := preparePackageTree(root, pkg, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	writeDummyBinaries(t, pkg)
	if err := validatePackageTree(pkg, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	one := filepath.Join(outDir, "one.tar.gz")
	two := filepath.Join(outDir, "two.tar.gz")
	const epoch = int64(1_700_000_000)
	if err := writeDeterministicArchive(one, pkg, filepath.Base(pkg), epoch); err != nil {
		t.Fatal(err)
	}
	// Source mtimes and process umask must not affect the archive bytes.
	if err := os.Chtimes(filepath.Join(pkg, "README.md"), time.Now(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := writeDeterministicArchive(two, pkg, filepath.Base(pkg), epoch); err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(one)
	b2, _ := os.ReadFile(two)
	if !reflect.DeepEqual(b1, b2) {
		t.Fatal("archives built from the same payload and epoch differ")
	}

	f, err := os.Open(one)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("non-normalized ownership for %s", h.Name)
		}
		if h.ModTime.Unix() != epoch {
			t.Errorf("mtime for %s=%d", h.Name, h.ModTime.Unix())
		}
		if strings.HasSuffix(h.Name, ".sh") &&
			!strings.HasSuffix(h.Name, "/sun.sh") && !strings.HasSuffix(h.Name, "/install.sh") {
			t.Errorf("unexpected shell program in archive: %s", h.Name)
		}
		if strings.Contains(h.Name, ".local.md") || strings.Contains(h.Name, "telegram.env") {
			t.Errorf("private path in archive: %s", h.Name)
		}
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("archive entries are not sorted: %v", names)
	}
	wantCount := len(expectedPackagePaths())
	if len(names) != wantCount {
		t.Errorf("archive has %d entries, want %d", len(names), wantCount)
	}
}

func TestReadArchiveRegularFileReturnsFinalArchivedBytes(t *testing.T) {
	t.Parallel()
	root := sourceFixture(t, "3.0.0")
	pkgName := "security-update-notify-3.0.0"
	pkg := filepath.Join(t.TempDir(), pkgName)
	if err := preparePackageTree(root, pkg, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	writeDummyBinaries(t, pkg)
	archive := filepath.Join(t.TempDir(), pkgName+".tar.gz")
	if err := writeDeterministicArchive(archive, pkg, pkgName, 1_700_000_000); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(pkg, "sun.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "sun.sh"), []byte("changed after archiving\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := readArchiveRegularFile(archive, pkgName+"/sun.sh", maxBootstrapSize)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("archive member reader returned mutable package-tree bytes")
	}
	if _, err := readArchiveRegularFile(archive, pkgName+"/missing", maxBootstrapSize); err == nil {
		t.Fatal("missing archive member was accepted")
	}
	if _, err := readArchiveRegularFile(archive, pkgName+"/sun.sh", 1); err == nil {
		t.Fatal("oversized archive member was accepted")
	}
	corrupt, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	corrupt[len(corrupt)-1] ^= 0xff
	corruptArchive := filepath.Join(t.TempDir(), "corrupt.tar.gz")
	if err := os.WriteFile(corruptArchive, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchiveRegularFile(corruptArchive, pkgName+"/sun.sh", maxBootstrapSize); err == nil {
		t.Fatal("corrupted gzip footer was accepted while reading archived bootstrap")
	}
	concatenatedArchive := filepath.Join(t.TempDir(), "concatenated.tar.gz")
	validArchive, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(concatenatedArchive, validArchive, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(concatenatedArchive, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	if _, err := gz.Write([]byte("unchecked second gzip member")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readArchiveRegularFile(concatenatedArchive, pkgName+"/sun.sh", maxBootstrapSize); err == nil {
		t.Fatal("concatenated gzip members were accepted while reading archived bootstrap")
	}
}

func TestWriteArchiveRejectsSymlinkedPackageAncestor(t *testing.T) {
	root := sourceFixture(t, "3.0.0")
	pkg := filepath.Join(t.TempDir(), productName+"-3.0.0")
	if err := preparePackageTree(root, pkg, "3.0.0"); err != nil {
		t.Fatal(err)
	}
	writeDummyBinaries(t, pkg)
	docs := filepath.Join(pkg, "docs")
	if err := os.RemoveAll(docs); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), docs); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "release.tar.gz")
	if err := writeDeterministicArchive(target, pkg, filepath.Base(pkg), 1_700_000_000); err == nil {
		t.Fatal("symlinked package ancestor was archived")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("failed archive output was retained: %v", err)
	}
}

func TestForbiddenReleasePaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		".env", ".env.production", "telegram.env", "notes.local.md", "x.log",
		"last-alert", "feishu-app-secret.txt", ".git/config", "credentials/token", "credstore-x/value", "credentials/.env.example",
	} {
		if !forbiddenReleasePath(path) {
			t.Errorf("forbiddenReleasePath(%q)=false", path)
		}
	}
	for _, path := range []string{".env.example", "README.md", "sun.sh", "files/security-update-notify.service"} {
		if forbiddenReleasePath(path) {
			t.Errorf("forbiddenReleasePath(%q)=true", path)
		}
	}
}

func TestInspectRepositoryFindsTrackedAndUntrackedReleaseChanges(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.name", "SUN test")
	gitRun(t, root, "config", "user.email", "sun@example.invalid")
	for _, dir := range []string{"docs", "internal"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "initial")
	clean, err := inspectRepository(context.Background(), root, "3.0.0")
	if err != nil || clean.Dirty {
		t.Fatalf("clean repository state=%+v err=%v", clean, err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "internal", "new.go"), []byte("package internal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "new.md"), []byte("new documentation\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dirty, err := inspectRepository(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !dirty.Dirty || !reflect.DeepEqual(dirty.DirtyFiles, []string{"README.md", "docs/new.md", "internal/new.go"}) {
		t.Fatalf("dirty files=%v", dirty.DirtyFiles)
	}
}

func TestVerifyReleaseSourceStateDetectsFurtherChangesToAnAlreadyDirtyFile(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.name", "SUN test")
	gitRun(t, root, "config", "user.email", "sun@example.invalid")
	readme := filepath.Join(root, "README.md")
	if err := os.WriteFile(readme, []byte("committed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "initial")
	if err := os.WriteFile(readme, []byte("dirty before build\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := captureReleaseSourceState(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !before.repository.Dirty || !reflect.DeepEqual(before.repository.DirtyFiles, []string{"README.md"}) {
		t.Fatalf("initial dirty state = %+v", before.repository)
	}
	if err := os.WriteFile(readme, []byte("dirty during build\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := captureReleaseSourceState(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !sameRepositoryIdentity(before.repository, after.repository) {
		t.Fatalf("dirty filename set changed unexpectedly: before=%+v after=%+v", before.repository, after.repository)
	}
	if err := verifyReleaseSourceState(context.Background(), root, "3.0.0", before); err == nil || !strings.Contains(err.Error(), "source files changed") {
		t.Fatalf("continued mutation of an already-dirty file was accepted: %v", err)
	}
}

func TestVerifyReleaseSourceStateDetectsGitIdentityChangeWithTheSameTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.name", "SUN test")
	gitRun(t, root, "config", "user.email", "sun@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("unchanged\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "initial")
	before, err := captureReleaseSourceState(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "commit", "--allow-empty", "-qm", "identity drift")
	after, err := captureReleaseSourceState(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if before.fingerprint != after.fingerprint {
		t.Fatal("an empty commit unexpectedly changed the source fingerprint")
	}
	if err := verifyReleaseSourceState(context.Background(), root, "3.0.0", before); err == nil || !strings.Contains(err.Error(), "repository identity changed") {
		t.Fatalf("HEAD identity drift with an unchanged tree was accepted: %v", err)
	}
}

func TestFingerprintReleaseSourcesRejectsSymlinksAndCoversModes(t *testing.T) {
	root := t.TempDir()
	readme := filepath.Join(root, "README.md")
	if err := os.WriteFile(readme, []byte("same bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := fingerprintReleaseSources(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(readme, 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := fingerprintReleaseSources(root)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("source permission change did not change the fingerprint")
	}
	if err := os.Remove(readme); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", readme); err != nil {
		t.Fatal(err)
	}
	if _, err := fingerprintReleaseSources(root); err == nil || !strings.Contains(err.Error(), "regular file or directory") {
		t.Fatalf("symlinked release source was accepted: %v", err)
	}
}

// A repository git refuses to inspect (dubious ownership, a broken gitfile, unreadable objects) must
// not be reported as "no repository here": the zero state clears Dirty and TagExists, which silently
// skips both the uncommitted-sources gate and the official-release signing escalation in Build.
func TestInspectRepositoryFailsClosedWhenGitCannotReadTheRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /nonexistent-sun-audit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := inspectRepository(context.Background(), root, "3.0.0")
	if err == nil {
		t.Fatalf("unreadable repository was reported as a clean non-repository: %+v", state)
	}
}

func TestInspectRepositoryFailsClosedForBrokenGitMetadataLink(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	if err := os.Symlink("missing-git-metadata", filepath.Join(root, ".git")); err != nil {
		t.Fatal(err)
	}
	state, err := inspectRepository(context.Background(), root, "3.0.0")
	if err == nil {
		t.Fatalf("broken .git link was reported as a tree without git metadata: %+v", state)
	}
}

// Packaging an extracted source tree has no .git at all and must still be allowed.
func TestInspectRepositoryAllowsATreeWithoutGitMetadata(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	state, err := inspectRepository(context.Background(), t.TempDir(), "3.0.0")
	if err != nil {
		t.Fatalf("non-repository tree rejected: %v", err)
	}
	if state.InWorkTree || state.Dirty || state.TagExists {
		t.Fatalf("non-repository tree produced state %+v", state)
	}
}

func TestInspectRepositoryIgnoresAnUnrelatedParentWorkTree(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	parent := t.TempDir()
	gitRun(t, parent, "init", "-q")
	root := filepath.Join(parent, "extracted-source")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	state, err := inspectRepository(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatalf("source tree nested below an unrelated repository was rejected: %v", err)
	}
	if state.InWorkTree || state.Dirty || state.TagExists {
		t.Fatalf("parent repository leaked into extracted source state: %+v", state)
	}
}

func TestInspectRepositoryIgnoresAmbientGitRepositoryOverrides(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.email", "test@example.com")
	gitRun(t, root, "config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "initial")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	other := t.TempDir()
	gitRun(t, other, "init", "--bare", "-q")
	t.Setenv("GIT_DIR", other)
	t.Setenv("GIT_WORK_TREE", t.TempDir())
	state, err := inspectRepository(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !state.InWorkTree || !state.Dirty || !reflect.DeepEqual(state.DirtyFiles, []string{"README.md"}) {
		t.Fatalf("ambient GIT_* variables changed repository inspection: %+v", state)
	}
}

func TestInspectRepositoryRejectsBareGitMetadataAtTheReleaseRoot(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "--bare", "-q")
	state, err := inspectRepository(context.Background(), root, "3.0.0")
	if err == nil {
		t.Fatalf("bare repository metadata was reported as a source tree without git: %+v", state)
	}
}

func TestInspectRepositoryRequiresAnnotatedVersionTagAtHead(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.name", "SUN test")
	gitRun(t, root, "config", "user.email", "sun@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "initial")
	gitRun(t, root, "tag", "v3.0.0")
	if _, err := inspectRepository(context.Background(), root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "annotated") {
		t.Fatalf("lightweight tag error=%v, want annotated-tag rejection", err)
	}
	gitRun(t, root, "tag", "-d", "v3.0.0")
	gitRun(t, root, "tag", "-am", "v3.0.0", "v3.0.0")
	state, err := inspectRepository(context.Background(), root, "3.0.0")
	if err != nil || !state.TagExists {
		t.Fatalf("annotated tag at HEAD state=%+v err=%v", state, err)
	}
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "next")
	if _, err := inspectRepository(context.Background(), root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "does not point to HEAD") {
		t.Fatalf("stale version tag error=%v, want HEAD mismatch rejection", err)
	}
}

func TestInspectRepositoryRejectsAnnotatedVersionTagThatDoesNotPointToCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git unavailable")
	}
	root := t.TempDir()
	gitRun(t, root, "init", "-q")
	gitRun(t, root, "config", "user.name", "SUN test")
	gitRun(t, root, "config", "user.email", "sun@example.invalid")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun(t, root, "add", "README.md")
	gitRun(t, root, "commit", "-qm", "initial")
	blob := strings.TrimSpace(gitOutput(t, root, "hash-object", "README.md"))
	gitRun(t, root, "tag", "-am", "invalid release target", "v3.0.0", blob)
	if _, err := inspectRepository(context.Background(), root, "3.0.0"); err == nil || !strings.Contains(err.Error(), "must point to a commit") {
		t.Fatalf("non-commit annotated tag error=%v", err)
	}
}

func TestResolveEpochRequiresExplicitValueWithoutGit(t *testing.T) {
	t.Parallel()
	if _, err := resolveEpoch(context.Background(), t.TempDir(), "3.0.0", nil, repositoryState{}); err == nil {
		t.Fatal("missing epoch unexpectedly succeeded")
	}
	epoch := int64(123)
	got, err := resolveEpoch(context.Background(), t.TempDir(), "3.0.0", &epoch, repositoryState{})
	if err != nil || got != epoch {
		t.Fatalf("resolveEpoch=%d,%v", got, err)
	}
}

func TestValidSignatureFingerprintAcceptsPrimaryOrSigningSubkey(t *testing.T) {
	t.Parallel()
	const primary = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	const subkey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
	primaryStatus := []byte("[GNUPG:] GOODSIG key signer\n[GNUPG:] VALIDSIG " + primary + " 2026 0 0 0 0 0 0 0 " + primary + "\n")
	subkeyStatus := []byte("[GNUPG:] GOODSIG key signer\n[GNUPG:] VALIDSIG " + subkey + " 2026 0 0 0 0 0 0 0 " + primary + "\n")
	if !validSignatureFingerprint(primaryStatus, primary) || !validSignatureFingerprint(subkeyStatus, primary) {
		t.Fatal("valid signature fingerprint was rejected")
	}
	if validSignatureFingerprint(subkeyStatus, strings.Repeat("C", 40)) {
		t.Fatal("unrelated signature fingerprint was accepted")
	}
	if validSignatureFingerprint(append(append([]byte(nil), primaryStatus...), primaryStatus...), primary) {
		t.Fatal("multiple valid signatures were accepted as one pinned signature")
	}
	for _, outcome := range []string{"EXPSIG", "EXPKEYSIG", "REVKEYSIG", "BADSIG", "ERRSIG"} {
		status := []byte("[GNUPG:] " + outcome + " key signer\n[GNUPG:] VALIDSIG " + primary + " 2026 0 0 0 0 0 0 0 " + primary + "\n")
		if validSignatureFingerprint(status, primary) {
			t.Fatalf("%s outcome was accepted as a releasable signature", outcome)
		}
	}
	const goodStatus = "[GNUPG:] GOODSIG key signer\n"
	if validSignatureFingerprint(primaryStatus[len(goodStatus):], primary) {
		t.Fatal("VALIDSIG without a GOODSIG outcome was accepted")
	}
}

func TestValidSignatureNotationRequiresOneExactPair(t *testing.T) {
	t.Parallel()
	valid := []byte("[GNUPG:] NOTATION_NAME release-version@xxv.cc\n[GNUPG:] NOTATION_FLAGS 1 1\n[GNUPG:] NOTATION_DATA 3.0.2\n")
	if !validSignatureNotation(valid, bootstrapVersionNotation, "3.0.2") {
		t.Fatal("exact release-version notation was rejected")
	}
	for _, status := range [][]byte{
		[]byte("[GNUPG:] NOTATION_NAME release-version@xxv.cc\n[GNUPG:] NOTATION_FLAGS 1 1\n[GNUPG:] NOTATION_DATA 3.0.1\n"),
		[]byte("[GNUPG:] NOTATION_NAME release-version@xxv.cc\n[GNUPG:] NOTATION_FLAGS 0 1\n[GNUPG:] NOTATION_DATA 3.0.2\n"),
		[]byte("[GNUPG:] NOTATION_NAME release-version@xxv.cc\n[GNUPG:] NOTATION_DATA 3.0.2\n"),
		append(append([]byte(nil), valid...), valid...),
		[]byte("[GNUPG:] NOTATION_NAME other@xxv.cc\n[GNUPG:] NOTATION_FLAGS 1 1\n[GNUPG:] NOTATION_DATA 3.0.2\n"),
	} {
		if validSignatureNotation(status, bootstrapVersionNotation, "3.0.2") {
			t.Fatalf("invalid release-version notation accepted: %q", status)
		}
	}
}

func TestMaybeSignRejectsIncompleteOrUnsafeNotationBeforeGPG(t *testing.T) {
	t.Parallel()
	for _, opts := range []signOptions{
		{Mode: SignRequired, NotationName: bootstrapVersionNotation},
		{Mode: SignRequired, NotationValue: "3.0.2"},
		{Mode: SignRequired, NotationName: "bad=name", NotationValue: "3.0.2"},
		{Mode: SignRequired, NotationName: bootstrapVersionNotation, NotationValue: "3.0.2\nother"},
	} {
		if _, err := maybeSign(context.Background(), opts, "missing", "missing.asc"); err == nil || !strings.Contains(err.Error(), "notation") {
			t.Fatalf("maybeSign(%+v) error=%v, want notation rejection", opts, err)
		}
	}
}

func TestMaybeSignAuthenticatesArbitraryReleaseArtifact(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg unavailable")
	}
	home := filepath.Join(t.TempDir(), "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	identity := "SUN bootstrap test <sun-bootstrap@example.invalid>"
	if err := runGPG(ctx, gpg, home,
		"--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", identity, "ed25519", "sign", "0",
	); err != nil {
		t.Fatalf("generate test signing key: %v", err)
	}
	fingerprint, err := secretKeyFingerprint(ctx, gpg, home, identity)
	if err != nil {
		t.Fatal(err)
	}
	verificationKey := exportPublicKeyForTest(t, ctx, gpg, home, fingerprint)
	artifact := filepath.Join(t.TempDir(), "sun.sh")
	signature := artifact + ".asc"
	if err := os.WriteFile(artifact, []byte("#!/bin/sh\necho verified\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "must-not-be-overwritten")
	if err := os.WriteFile(victim, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, signature); err != nil {
		t.Fatal(err)
	}
	if signed, err := maybeSign(ctx, signOptions{
		Mode: SignRequired, GPGKeyID: fingerprint, GPGHome: home,
		PinnedFingerprint: fingerprint,
		TrustedPublicKey:  verificationKey,
		NotationName:      bootstrapVersionNotation,
		NotationValue:     "3.0.2",
	}, artifact, signature); err == nil || signed {
		t.Fatalf("symlinked signature output was accepted: signed=%v err=%v", signed, err)
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "preserved" {
		t.Fatalf("signature output changed symlink target: %q err=%v", got, err)
	}
	if err := os.Remove(signature); err != nil {
		t.Fatal(err)
	}
	signed, err := maybeSign(ctx, signOptions{
		Mode: SignRequired, GPGKeyID: fingerprint, GPGHome: home,
		PinnedFingerprint: fingerprint,
		TrustedPublicKey:  verificationKey,
		NotationName:      bootstrapVersionNotation,
		NotationValue:     "3.0.2",
	}, artifact, signature)
	if err != nil || !signed {
		t.Fatalf("maybeSign()=(%v,%v)", signed, err)
	}
	armored, err := os.ReadFile(signature)
	if err != nil || !bytes.Contains(armored, []byte("BEGIN PGP SIGNATURE")) {
		t.Fatalf("detached signature is not ASCII armored: %v", err)
	}
	if _, err := runGPGOutput(ctx, gpg, home,
		"--status-fd=1", "--show-notation", "--verify", signature, artifact,
	); err == nil {
		t.Fatal("critical release-version notation was accepted without explicit verifier recognition")
	}
	status, err := runGPGOutput(ctx, gpg, home,
		"--status-fd=1", "--known-notation", bootstrapVersionNotation, "--show-notation",
		"--verify", signature, artifact,
	)
	if err != nil || !validSignatureFingerprint(status, fingerprint) ||
		!validSignatureNotation(status, bootstrapVersionNotation, "3.0.2") {
		t.Fatalf("verify generated artifact signature: %v", err)
	}
	if _, err := runGPGOutput(ctx, gpg, home,
		"--status-fd=1", "--verify", signature, artifact,
	); err == nil {
		t.Fatal("critical version notation was accepted without explicit verifier recognition")
	}
	if err := os.WriteFile(artifact, []byte("#!/bin/sh\necho tampered\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := runGPGOutput(ctx, gpg, home,
		"--status-fd=1", "--known-notation", bootstrapVersionNotation,
		"--verify", signature, artifact,
	); err == nil {
		t.Fatal("detached signature accepted a modified bootstrap")
	}
}

func TestMaybeSignRejectsSigningSubkeyAbsentFromPublishedKey(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg unavailable")
	}
	home := filepath.Join(t.TempDir(), "gnupg")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	identity := "SUN unpublished subkey test <sun-unpublished-subkey@example.invalid>"
	if err := runGPG(ctx, gpg, home,
		"--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-generate-key", identity, "ed25519", "cert", "0",
	); err != nil {
		t.Fatalf("generate test primary key: %v", err)
	}
	fingerprint, err := secretKeyFingerprint(ctx, gpg, home, identity)
	if err != nil {
		t.Fatal(err)
	}
	// Capture the public trust anchor before the local signer gains a signing
	// subkey. This matches a stale published key file on release machines.
	publishedKey := exportPublicKeyForTest(t, ctx, gpg, home, fingerprint)
	if err := runGPG(ctx, gpg, home,
		"--pinentry-mode", "loopback", "--passphrase", "",
		"--quick-add-key", fingerprint, "ed25519", "sign", "0",
	); err != nil {
		t.Fatalf("add unpublished signing subkey: %v", err)
	}

	artifact := filepath.Join(t.TempDir(), "release.tar.gz")
	signature := artifact + ".asc"
	if err := os.WriteFile(artifact, []byte("release bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	signed, err := maybeSign(ctx, signOptions{
		Mode: SignRequired, GPGKeyID: fingerprint, GPGHome: home,
		PinnedFingerprint: fingerprint,
		TrustedPublicKey:  publishedKey,
	}, artifact, signature)
	if err == nil || signed {
		t.Fatalf("signature by an unpublished subkey was accepted: signed=%v err=%v", signed, err)
	}
	if _, statErr := os.Lstat(signature); !os.IsNotExist(statErr) {
		t.Fatalf("rejected signature was not removed: %v", statErr)
	}

	// Once the same subkey is present in the published anchor, the identical
	// signing path is usable. This proves the rejection is an anchor mismatch,
	// not an invalid test key or artifact.
	completeKey := exportPublicKeyForTest(t, ctx, gpg, home, fingerprint)
	signed, err = maybeSign(ctx, signOptions{
		Mode: SignRequired, GPGKeyID: fingerprint, GPGHome: home,
		PinnedFingerprint: fingerprint,
		TrustedPublicKey:  completeKey,
	}, artifact, signature)
	if err != nil || !signed {
		t.Fatalf("published signing subkey was rejected: signed=%v err=%v", signed, err)
	}
}

func exportPublicKeyForTest(t *testing.T, ctx context.Context, gpg, home, fingerprint string) []byte {
	t.Helper()
	cmd := exec.CommandContext(ctx, gpg, "--batch", "--no-tty", "--homedir", home, "--armor", "--export", "--", fingerprint)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("export test public key: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("exported test public key is empty")
	}
	return out
}

func TestCommitArtifactsCleansPartialCommit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	stageSig := stageTar + ".asc"
	for _, path := range []string{stageTar, stageSHA, stageSig} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	finalSig := finalTar + ".asc"
	finalBootstrapSig := filepath.Join(dir, bootstrapSignatureName)
	err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, stageSig, filepath.Join(dir, "missing-bootstrap.asc"),
		finalTar, finalSHA, finalSig, finalBootstrapSig,
		true,
		nil,
	)
	if err == nil {
		t.Fatal("missing staged signature unexpectedly committed")
	}
	for _, path := range []string{finalTar, finalSHA, finalSig, finalBootstrapSig} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("partial artifact remains at %s: %v", path, statErr)
		}
	}
}

func TestCommitArtifactsPreservesPreviousSetOnPreflightFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	stageSig := stageTar + ".asc"
	for _, path := range []string{stageTar, stageSHA, stageSig} {
		if err := os.WriteFile(path, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	finalSig := finalTar + ".asc"
	finalBootstrapSig := filepath.Join(dir, bootstrapSignatureName)
	for _, path := range []string{finalTar, finalSHA, finalSig, finalBootstrapSig} {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, stageSig, filepath.Join(dir, "missing-bootstrap.asc"),
		finalTar, finalSHA, finalSig, finalBootstrapSig,
		true,
		nil,
	)
	if err == nil {
		t.Fatal("missing staged bootstrap signature unexpectedly committed")
	}
	for _, path := range []string{finalTar, finalSHA, finalSig, finalBootstrapSig} {
		if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "old" {
			t.Errorf("previous artifact %s=(%q,%v), want preserved", path, got, readErr)
		}
	}
}

func TestCommitArtifactsFailsClosedOnUnfinishedRecoveryDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stageDir := filepath.Join(dir, "stage")
	if err := os.Mkdir(stageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stageTar := filepath.Join(stageDir, "final.tar.gz")
	stageSHA := stageTar + ".sha256"
	for _, path := range []string{stageTar, stageSHA} {
		if err := os.WriteFile(path, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	for _, path := range []string{finalTar, finalSHA} {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	recoveryDir := filepath.Join(dir, ".sun-commit-backup-interrupted")
	if err := os.Mkdir(recoveryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	recoveryEvidence := filepath.Join(recoveryDir, "0-final.tar.gz")
	if err := os.WriteFile(recoveryEvidence, []byte("previous"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, "", "",
		finalTar, finalSHA, finalTar+".asc", filepath.Join(dir, bootstrapSignatureName),
		false,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "manual recovery") {
		t.Fatalf("unfinished recovery error=%v", err)
	}
	for _, path := range []string{finalTar, finalSHA} {
		if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "old" {
			t.Fatalf("existing artifact %s=(%q,%v), want unchanged", path, got, readErr)
		}
	}
	if got, readErr := os.ReadFile(recoveryEvidence); readErr != nil || string(got) != "previous" {
		t.Fatalf("recovery evidence=(%q,%v), want retained", got, readErr)
	}
}

func TestCommitArtifactsUnsignedReplacesPayloadAndRemovesStaleSignatures(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	for _, path := range []string{stageTar, stageSHA} {
		if err := os.WriteFile(path, []byte("new"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	finalSig := finalTar + ".asc"
	finalBootstrapSig := filepath.Join(dir, bootstrapSignatureName)
	for _, path := range []string{finalTar, finalSHA, finalSig, finalBootstrapSig} {
		if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, "", "",
		finalTar, finalSHA, finalSig, finalBootstrapSig,
		false,
		nil,
	); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{finalTar, finalSHA} {
		if got, err := os.ReadFile(path); err != nil || string(got) != "new" {
			t.Errorf("committed payload %s=(%q,%v)", path, got, err)
		}
	}
	for _, path := range []string{finalSig, finalBootstrapSig} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("stale signature remains at %s: %v", path, err)
		}
	}
}

func TestCommitArtifactsSerializesConcurrentCompleteSets(t *testing.T) {
	dir := t.TempDir()
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	finalSig := finalTar + ".asc"
	finalBootstrapSig := filepath.Join(dir, bootstrapSignatureName)

	type stagedSet struct {
		tar, sha, sig, bootstrap string
	}
	makeSet := func(name, content string) stagedSet {
		t.Helper()
		stage := filepath.Join(dir, name)
		if err := os.Mkdir(stage, 0o755); err != nil {
			t.Fatal(err)
		}
		set := stagedSet{
			tar:       filepath.Join(stage, "final.tar.gz"),
			sha:       filepath.Join(stage, "final.tar.gz.sha256"),
			sig:       filepath.Join(stage, "final.tar.gz.asc"),
			bootstrap: filepath.Join(stage, bootstrapSignatureName),
		}
		for _, path := range []string{set.tar, set.sha, set.sig, set.bootstrap} {
			if err := os.WriteFile(path, []byte(content+"/"+filepath.Base(path)), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return set
	}
	first := makeSet("stage-first", "first")
	second := makeSet("stage-second", "second")

	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withReleaseCommitLock(context.Background(), dir, func(directory *os.File) error {
			close(firstEntered)
			<-releaseFirst
			return commitArtifactsUnlockedAt(
				directory,
				first.tar, first.sha, first.sig, first.bootstrap,
				finalTar, finalSHA, finalSig, finalBootstrapSig,
				true,
			)
		})
	}()
	<-firstEntered

	probe, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		if err == nil {
			_ = syscall.Flock(int(probe.Fd()), syscall.LOCK_UN)
		}
		t.Fatalf("concurrent release directory lock probe: %v", err)
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- commitArtifacts(
			context.Background(),
			second.tar, second.sha, second.sig, second.bootstrap,
			finalTar, finalSHA, finalSig, finalBootstrapSig,
			true,
			nil,
		)
	}()
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatalf("first commit: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second commit: %v", err)
	}
	for _, path := range []string{finalTar, finalSHA, finalSig, finalBootstrapSig} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		want := "second/" + filepath.Base(path)
		if string(got) != want {
			t.Errorf("final artifact %s = %q, want %q", filepath.Base(path), got, want)
		}
	}
}

func TestCommitArtifactsWaitHonorsContextCancellation(t *testing.T) {
	dir := t.TempDir()
	held, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := syscall.Flock(int(held.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(held.Fd()), syscall.LOCK_UN)

	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	for _, path := range []string{stageTar, stageSHA} {
		if err := os.WriteFile(path, []byte("staged"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	preCommitCalled := false
	err = commitArtifacts(
		ctx,
		stageTar, stageSHA, "", "",
		filepath.Join(dir, "final.tar.gz"), filepath.Join(dir, "final.tar.gz.sha256"),
		filepath.Join(dir, "final.tar.gz.asc"), filepath.Join(dir, bootstrapSignatureName),
		false,
		func() error {
			preCommitCalled = true
			return nil
		},
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended commit error = %v, want context deadline", err)
	}
	if preCommitCalled {
		t.Fatal("pre-commit source revalidation ran before the commit lock was acquired")
	}
}

func TestCommitArtifactsRejectsAliasedPathsBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	if err := os.WriteFile(stageTar, []byte("new archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stageSHA, []byte("new checksum"), 0o644); err != nil {
		t.Fatal(err)
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	if err := os.WriteFile(finalTar, []byte("old archive"), 0o644); err != nil {
		t.Fatal(err)
	}

	err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, "", "",
		finalTar, finalTar, finalTar+".asc", filepath.Join(dir, bootstrapSignatureName),
		false,
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "must be distinct") {
		t.Fatalf("aliased final paths error=%v", err)
	}
	for path, want := range map[string]string{
		stageTar: "new archive", stageSHA: "new checksum", finalTar: "old archive",
	} {
		if got, readErr := os.ReadFile(path); readErr != nil || string(got) != want {
			t.Fatalf("artifact %s=(%q,%v), want unchanged %q", path, got, readErr, want)
		}
	}
	recovery, globErr := filepath.Glob(filepath.Join(dir, ".sun-commit-backup-*"))
	if globErr != nil || len(recovery) != 0 {
		t.Fatalf("path preflight left recovery data: %v, %v", recovery, globErr)
	}
}

func TestCommitArtifactsRejectsHardLinkedStagedArtifacts(t *testing.T) {
	dir := t.TempDir()
	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	if err := os.WriteFile(stageTar, []byte("aliased staged bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(stageTar, stageSHA); err != nil {
		t.Fatal(err)
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	for _, path := range []string{finalTar, finalSHA} {
		if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, "", "",
		finalTar, finalSHA, finalTar+".asc", filepath.Join(dir, bootstrapSignatureName),
		false, nil,
	)
	if err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("hard-linked staged artifacts error=%v", err)
	}
	for _, path := range []string{finalTar, finalSHA} {
		if got, readErr := os.ReadFile(path); readErr != nil || string(got) != "previous" {
			t.Fatalf("existing output changed after hard-link rejection: %s=(%q,%v)", path, got, readErr)
		}
	}
}

func TestCommitArtifactsRemainsBoundToLockedOutputDirectory(t *testing.T) {
	root := t.TempDir()
	distDir := filepath.Join(root, "dist")
	movedDir := filepath.Join(root, "opened-dist")
	external := filepath.Join(root, "external")
	stageDir := filepath.Join(root, "stage")
	for _, path := range []string{distDir, external, stageDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stageTar := filepath.Join(stageDir, "release.tar.gz")
	stageSHA := stageTar + ".sha256"
	for _, path := range []string{stageTar, stageSHA} {
		if err := os.WriteFile(path, []byte("new/"+filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	finalTar := filepath.Join(distDir, "release.tar.gz")
	finalSHA := finalTar + ".sha256"
	err := commitArtifacts(
		context.Background(),
		stageTar, stageSHA, "", "",
		finalTar, finalSHA, finalTar+".asc", filepath.Join(distDir, bootstrapSignatureName),
		false,
		func() error {
			if err := os.Rename(distDir, movedDir); err != nil {
				return err
			}
			return os.Symlink(external, distDir)
		},
	)
	if err == nil || !strings.Contains(err.Error(), "output directory changed") {
		t.Fatalf("replaced output directory error=%v", err)
	}
	for _, name := range []string{"release.tar.gz", "release.tar.gz.sha256"} {
		got, readErr := os.ReadFile(filepath.Join(movedDir, name))
		if readErr != nil || string(got) != "new/"+name {
			t.Fatalf("opened output %s=(%q,%v)", name, got, readErr)
		}
		if _, statErr := os.Lstat(filepath.Join(external, name)); !os.IsNotExist(statErr) {
			t.Fatalf("replacement output received %s: %v", name, statErr)
		}
	}
}

func TestValidatePinnedGoToolchainRequiresAnExactMatch(t *testing.T) {
	metadata := []byte(`{"Toolchain":"go1.26.5"}`)
	if err := validatePinnedGoToolchain(metadata, []byte("go1.26.5\n")); err != nil {
		t.Fatalf("matching pinned toolchain rejected: %v", err)
	}
	for name, candidate := range map[string][]byte{
		"newer local toolchain": []byte("go1.27.0\n"),
		"missing directive":     []byte(`{"Go":"1.23"}`),
		"malformed metadata":    []byte(`{"Toolchain":`),
	} {
		t.Run(name, func(t *testing.T) {
			input := metadata
			actual := candidate
			if name != "newer local toolchain" {
				input = candidate
				actual = []byte("go1.26.5\n")
			}
			if err := validatePinnedGoToolchain(input, actual); err == nil {
				t.Fatal("release toolchain drift was accepted")
			}
		})
	}
}

func TestCappedCombinedOutputDiscardsBytesBeyondLimit(t *testing.T) {
	var output cappedCombinedOutput
	payload := bytes.Repeat([]byte{'x'}, maxCombinedCommandOutput+1)
	n, err := output.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write() = %d, %v; want %d, nil", n, err, len(payload))
	}
	if !output.truncated || output.buf.Len() != maxCombinedCommandOutput {
		t.Fatalf("capped output = len %d, truncated %v", output.buf.Len(), output.truncated)
	}
}

func TestCommandErrorSummaryIsBoundedAndTerminalSafe(t *testing.T) {
	message := strings.Repeat("界", maxCommandErrorBytes/3) + "\nforged\r\x1b[31mred\u202eevil\u2028tail"
	got := commandErrorSummary([]byte(message))
	if !utf8.ValidString(got) || len(got) > maxCommandErrorBytes {
		t.Fatalf("unsafe command error length=%d valid=%v", len(got), utf8.ValidString(got))
	}
	for _, forbidden := range []string{"\n", "\r", "\x1b", "\u202e", "\u2028"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("command error retained display control %q: %q", forbidden, got)
		}
	}
}

func TestRunGPGIgnoresHomeOptions(t *testing.T) {
	gpg, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not available")
	}
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "gpg.conf"), []byte("not-a-real-gpg-option\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runGPGOutput(context.Background(), gpg, home, "--with-colons", "--list-keys"); err != nil {
		t.Fatalf("explicit GPG invocation read gpg.conf: %v", err)
	}
}

func TestCurrentGoToolchainMatchesRepositoryPin(t *testing.T) {
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go unavailable")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if err := requirePinnedGoToolchain(context.Background(), root, goTool); err != nil {
		t.Fatal(err)
	}
}

func TestGoBuildEnvironmentOverridesAmbientValues(t *testing.T) {
	t.Setenv("GOARCH", "evil")
	t.Setenv("GOFLAGS", "-mod=vendor")
	env := goBuildEnvironment("linux", "arm64")
	values := make(map[string]string)
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		values[key] = value
	}
	if values["GOARCH"] != "arm64" || values["GOOS"] != "linux" || values["GOFLAGS"] != "" || values["GOTOOLCHAIN"] != "local" {
		t.Fatalf("unexpected build environment: GOARCH=%q GOOS=%q GOFLAGS=%q GOTOOLCHAIN=%q", values["GOARCH"], values["GOOS"], values["GOFLAGS"], values["GOTOOLCHAIN"])
	}
}

func sourceFixture(t *testing.T, version string) string {
	t.Helper()
	root := t.TempDir()
	for _, spec := range releaseFiles {
		path := filepath.Join(root, filepath.FromSlash(spec.Source))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		content := []byte(spec.Source + "\n")
		if spec.Source == "CHANGELOG.md" {
			content = []byte("# Changes\n\n## " + version + "\n")
		} else if spec.Source == "VERSION" {
			content = []byte("VERSION=\"" + version + "\"\n")
		} else if spec.Source == "sun.sh" {
			content = []byte("#!/usr/bin/env bash\nset -eu\nRELEASE_SIGNING_FINGERPRINT=\"" + assets.ReleaseSigningFingerprint + "\"\n" +
				"BOOTSTRAP_SIGNATURE_ASSET=\"" + bootstrapSignatureName + "\"\n" +
				"BOOTSTRAP_VERSION_NOTATION=\"" + bootstrapVersionNotation + "\"\n" +
				"release_signing_public_key() {\n  cat <<'EOF'\n" + string(assets.ReleaseSigningPublicKey()) + "EOF\n}\n")
		} else {
			switch spec.Source {
			case "files/release-signing.pub.asc":
				content = assets.ReleaseSigningPublicKey()
			case "files/security-update-notify.service":
				content = assets.SystemdServiceUnit()
			case "files/needrestart-report-only.conf":
				content = assets.NeedrestartConf()
			case "files/security-update-notify.logrotate":
				content = assets.LogrotateConf()
			}
		}
		if err := os.WriteFile(path, content, spec.Mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, spec.Mode); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func writeDummyBinaries(t *testing.T, pkg string) {
	t.Helper()
	for _, arch := range officialArches {
		path := filepath.Join(pkg, "files", productName+"-linux-"+arch)
		if err := os.WriteFile(path, []byte("binary-"+arch+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	_ = gitOutput(t, dir, args...)
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

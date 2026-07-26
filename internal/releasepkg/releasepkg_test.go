package releasepkg

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/assets"
)

func TestValidateVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"3.0.0", "3.0.0-rc1", "3.0.0_rc1", "3.0.0.1"} {
		if err := ValidateVersion(version); err != nil {
			t.Errorf("ValidateVersion(%q): %v", version, err)
		}
	}
	for _, version := range []string{"", "v3.0.0", "3.0", "3.0.0-rc.1", "3.0.0/evil", strings.Repeat("1", 65)} {
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
	if err := os.MkdirAll(filepath.Join(root, "internal"), 0o755); err != nil {
		t.Fatal(err)
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
	dirty, err := inspectRepository(context.Background(), root, "3.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !dirty.Dirty || !reflect.DeepEqual(dirty.DirtyFiles, []string{"README.md", "internal/new.go"}) {
		t.Fatalf("dirty files=%v", dirty.DirtyFiles)
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
	primaryStatus := []byte("[GNUPG:] VALIDSIG " + primary + " 2026 0 0 0 0 0 0 0 " + primary + "\n")
	subkeyStatus := []byte("[GNUPG:] VALIDSIG " + subkey + " 2026 0 0 0 0 0 0 0 " + primary + "\n")
	if !validSignatureFingerprint(primaryStatus, primary) || !validSignatureFingerprint(subkeyStatus, primary) {
		t.Fatal("valid signature fingerprint was rejected")
	}
	if validSignatureFingerprint(subkeyStatus, strings.Repeat("C", 40)) {
		t.Fatal("unrelated signature fingerprint was accepted")
	}
}

func TestCommitArtifactsCleansPartialCommit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stageTar := filepath.Join(dir, "stage.tar.gz")
	stageSHA := stageTar + ".sha256"
	for _, path := range []string{stageTar, stageSHA} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	finalTar := filepath.Join(dir, "final.tar.gz")
	finalSHA := finalTar + ".sha256"
	finalSig := finalTar + ".asc"
	err := commitArtifacts(stageTar, stageSHA, filepath.Join(dir, "missing.asc"), finalTar, finalSHA, finalSig, true)
	if err == nil {
		t.Fatal("missing staged signature unexpectedly committed")
	}
	for _, path := range []string{finalTar, finalSHA, finalSig} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("partial artifact remains at %s: %v", path, statErr)
		}
	}
}

func TestClearTargetArtifactsLeavesNoSameVersionReleaseSet(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "security-update-notify-3.0.0.tar.gz"),
		filepath.Join(dir, "security-update-notify-3.0.0.tar.gz.sha256"),
		filepath.Join(dir, "security-update-notify-3.0.0.tar.gz.asc"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := clearTargetArtifacts(paths...); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("stale artifact remains at %s: %v", path, err)
		}
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

package run

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

func TestReadPackageVersionIsStrict(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "VERSION")
	if _, err := readPackageVersion(path); err == nil {
		t.Fatal("missing VERSION was accepted")
	}
	if err := os.WriteFile(path, []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := readPackageVersion(path); err != nil || got != "3.0.0" {
		t.Fatalf("readPackageVersion()=(%q, %v), want 3.0.0", got, err)
	}

	malformed := []string{
		"VERSION='3.0.0'\n",
		"VERSION=\"3.0.0\"",
		"VERSION=\"3.0.0\" trailing\n",
		"VERSION=\"3.0.0\"\r\n",
		"VERSION=\"\"\n",
		"VERSION=\"3.0.0\"\nVERSION=\"9.9.9\"\n",
		"VERSION=\"" + strings.Repeat("x", 129) + "\"\n",
	}
	for _, contents := range malformed {
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := readPackageVersion(path); err == nil {
			t.Errorf("malformed VERSION accepted as %q: %q", got, contents)
		}
	}
}

func TestReadPackageVersionRejectsSymlinkAndOversizedFile(t *testing.T) {
	dir := t.TempDir()
	realPath := filepath.Join(dir, "real-version")
	if err := os.WriteFile(realPath, []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "VERSION")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readPackageVersion(linkPath); err == nil {
		t.Fatal("symlink VERSION was accepted")
	}
	if err := os.Remove(linkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(linkPath, []byte(strings.Repeat("x", 257)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPackageVersion(linkPath); err == nil {
		t.Fatal("oversized VERSION was accepted")
	}
}

func TestSelectUpgradeBinaryBindsVersionAndCurrentArchitecture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("official release payloads target Linux")
	}
	if _, ok := releaseELFIdentities[runtime.GOARCH]; !ok {
		t.Skip("test host architecture is not in the official release set")
	}

	extractDir := t.TempDir()
	filesDir := filepath.Join(extractDir, "files")
	if err := os.Mkdir(filesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extractDir, "VERSION"), []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(filesDir, "security-update-notify-linux-"+runtime.GOARCH)
	copyTestExecutable(t, want)

	got, err := selectUpgradeBinary(extractDir, "3.0.0", runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("selectUpgradeBinary(): %v", err)
	}
	if got != want {
		t.Fatalf("selected %q, want %q", got, want)
	}
}

func TestSelectUpgradeBinaryRejectsVersionMismatch(t *testing.T) {
	extractDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(extractDir, "VERSION"), []byte("VERSION=\"3.0.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := selectUpgradeBinary(extractDir, "3.0.0", "linux", "amd64"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("version mismatch error=%v", err)
	}
}

func TestSelectUpgradeBinaryRejectsMissingArchitecture(t *testing.T) {
	extractDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(extractDir, "VERSION"), []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := selectUpgradeBinary(extractDir, "3.0.0", "linux", "s390x"); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing architecture error=%v", err)
	}
	if _, err := selectUpgradeBinary(extractDir, "3.0.0", "linux", "riscv64"); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unsupported architecture error=%v", err)
	}
	if _, err := selectUpgradeBinary(extractDir, "3.0.0", "darwin", "amd64"); err == nil || !strings.Contains(err.Error(), "does not support") {
		t.Fatalf("unsupported operating system error=%v", err)
	}
}

func TestUpgradeArchitectureSetIsFixed(t *testing.T) {
	want := map[string]bool{"amd64": true, "arm64": true, "386": true, "ppc64le": true, "s390x": true}
	if len(releaseELFIdentities) != len(want) {
		t.Fatalf("release architecture count=%d, want %d", len(releaseELFIdentities), len(want))
	}
	for arch := range releaseELFIdentities {
		if !want[arch] {
			t.Errorf("unexpected release architecture %q", arch)
		}
	}
}

func TestSelectUpgradeBinaryRejectsSymlinkAndWrongELFArchitecture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("official release payloads target Linux")
	}
	if _, ok := releaseELFIdentities[runtime.GOARCH]; !ok {
		t.Skip("test host architecture is not in the official release set")
	}

	extractDir := t.TempDir()
	filesDir := filepath.Join(extractDir, "files")
	if err := os.Mkdir(filesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(extractDir, "VERSION"), []byte("VERSION=\"3.0.0\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	realBinary := filepath.Join(filesDir, "real-binary")
	copyTestExecutable(t, realBinary)
	selected := filepath.Join(filesDir, "security-update-notify-linux-"+runtime.GOARCH)
	if err := os.Symlink(realBinary, selected); err != nil {
		t.Fatal(err)
	}
	if _, err := selectUpgradeBinary(extractDir, "3.0.0", "linux", runtime.GOARCH); err == nil {
		t.Fatal("symlink candidate was accepted")
	}
	if err := os.Remove(selected); err != nil {
		t.Fatal(err)
	}

	otherArch := "amd64"
	if runtime.GOARCH == otherArch {
		otherArch = "arm64"
	}
	wrongPath := filepath.Join(filesDir, "security-update-notify-linux-"+otherArch)
	copyTestExecutable(t, wrongPath)
	if _, err := selectUpgradeBinary(extractDir, "3.0.0", "linux", otherArch); err == nil || !strings.Contains(err.Error(), "ELF identity") {
		t.Fatalf("wrong ELF architecture error=%v", err)
	}
}

func TestValidateUpgradeArchiveRejectsMaliciousEntries(t *testing.T) {
	const top = "security-update-notify-3.0.0"
	tests := []struct {
		name    string
		entries []upgradeTarEntry
	}{
		{
			name: "symlink",
			entries: []upgradeTarEntry{
				{name: top + "/", typeflag: tar.TypeDir, mode: 0o755},
				{name: top + "/files/", typeflag: tar.TypeDir, mode: 0o755},
				{name: top + "/files/security-update-notify-linux-amd64", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/bin/sh"},
			},
		},
		{
			name: "path traversal",
			entries: []upgradeTarEntry{
				{name: top + "/../outside", typeflag: tar.TypeReg, mode: 0o755, body: []byte("bad")},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tarPath := writeUpgradeArchive(t, tc.entries)
			if err := validateUpgradeArchive(tarPath, top); err == nil {
				t.Fatal("malicious release archive was accepted")
			}
		})
	}
}

func TestUpgradeInstallCommandUsesGoInstallerEntrypoint(t *testing.T) {
	t.Setenv("SECURITY_UPDATE_NOTIFY_UPGRADE", "stale")
	t.Setenv("PATH", "/hostile/bin")
	t.Setenv("LD_PRELOAD", "/tmp/hostile.so")
	t.Setenv("HTTPS_PROXY", "http://proxy.example:8080")
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS", "120")
	binary := filepath.Join(t.TempDir(), "security-update-notify-linux-amd64")
	extractDir := t.TempDir()
	cmd := upgradeInstallCommand(binary, extractDir, i18n.EN)
	wantArgs := []string{binary, "install", "--non-interactive", "-y", "--lang", "en"}
	if strings.Join(cmd.Args, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("args=%q, want %q", cmd.Args, wantArgs)
	}
	if cmd.Dir != extractDir {
		t.Fatalf("command dir=%q, want %q", cmd.Dir, extractDir)
	}
	count := 0
	wantEnvironment := map[string]bool{
		"PATH=" + privilegedUpgradePath:                false,
		"LC_ALL=C":                                     false,
		"HTTPS_PROXY=http://proxy.example:8080":        false,
		"SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS=120": false,
		"SECURITY_UPDATE_NOTIFY_UPGRADE=1":             false,
	}
	for _, item := range cmd.Env {
		if item == "SECURITY_UPDATE_NOTIFY_UPGRADE=1" {
			count++
		}
		if strings.HasPrefix(item, "SECURITY_UPDATE_NOTIFY_UPGRADE=") && item != "SECURITY_UPDATE_NOTIFY_UPGRADE=1" {
			t.Fatalf("stale upgrade environment survived: %q", item)
		}
		if item == "PATH=/hostile/bin" || strings.HasPrefix(item, "LD_PRELOAD=") {
			t.Fatalf("unsafe inherited environment survived: %q", item)
		}
		if _, ok := wantEnvironment[item]; ok {
			wantEnvironment[item] = true
		}
	}
	if count != 1 {
		t.Fatalf("upgrade environment count=%d, want 1", count)
	}
	for item, found := range wantEnvironment {
		if !found {
			t.Errorf("expected environment entry missing: %q", item)
		}
	}
}

func TestValidateUpgradeBinaryVersionIsExactAndBounded(t *testing.T) {
	dir := t.TempDir()
	writeProbe := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := writeProbe("good", "printf 'security-update-notify 3.0.0\\n'\n")
	if err := validateUpgradeBinaryVersion(good, dir, "3.0.0"); err != nil {
		t.Fatalf("valid binary version rejected: %v", err)
	}
	for name, body := range map[string]string{
		"wrong":     "printf 'security-update-notify 2.9.9\\n'\n",
		"trailing":  "printf 'security-update-notify 3.0.0\\nextra\\n'\n",
		"stderr":    "printf 'security-update-notify 3.0.0\\n'; printf warning >&2\n",
		"failure":   "exit 2\n",
		"oversized": "i=0; while [ \"$i\" -lt 5000 ]; do printf x; i=$((i + 1)); done\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateUpgradeBinaryVersion(writeProbe(name, body), dir, "3.0.0"); err == nil {
				t.Fatal("invalid binary version output was accepted")
			}
		})
	}
}

func TestUpgradeInstallerExitCodePreserved(t *testing.T) {
	if os.Getenv("SECURITY_UPDATE_NOTIFY_EXIT_HELPER") == "1" &&
		len(os.Args) > 1 && os.Args[len(os.Args)-1] == "selfupgrade-exit-75" {
		os.Exit(75)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestUpgradeInstallerExitCodePreserved$", "--", "selfupgrade-exit-75")
	cmd.Env = envWithOverride(os.Environ(), "SECURITY_UPDATE_NOTIFY_EXIT_HELPER", "1")
	err := cmd.Run()
	if code, ok := upgradeInstallerExitCode(err); !ok || code != 75 {
		t.Fatalf("exit mapping=(%d, %v), want (75, true); err=%v", code, ok, err)
	}
	if code, ok := upgradeInstallerExitCode(errors.New("start failed")); ok || code != 0 {
		t.Fatalf("non-exit mapping=(%d, %v), want (0, false)", code, ok)
	}
	signaled := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	if err := signaled.Run(); err == nil {
		t.Fatal("signal helper unexpectedly succeeded")
	} else if code, ok := upgradeInstallerExitCode(err); ok || code != 0 {
		t.Fatalf("signal mapping=(%d, %v), want (0, false)", code, ok)
	} else if status, statusOK := err.(*exec.ExitError).Sys().(syscall.WaitStatus); !statusOK || !status.Signaled() {
		t.Fatalf("helper did not terminate by signal: %v", err)
	}
}

func TestEnvWithOverrideRemovesDuplicates(t *testing.T) {
	got := envWithOverride([]string{"A=1", "SECURITY_UPDATE_NOTIFY_UPGRADE=0", "B=2", "SECURITY_UPDATE_NOTIFY_UPGRADE=stale"}, "SECURITY_UPDATE_NOTIFY_UPGRADE", "1")
	want := []string{"A=1", "B=2", "SECURITY_UPDATE_NOTIFY_UPGRADE=1"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("env=%q want %q", got, want)
	}
}

func copyTestExecutable(t *testing.T, destination string) {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	in, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

type upgradeTarEntry struct {
	name     string
	typeflag byte
	mode     int64
	body     []byte
	linkname string
}

func writeUpgradeArchive(t *testing.T, entries []upgradeTarEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "release.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, entry := range entries {
		header := &tar.Header{
			Name: entry.name, Typeflag: entry.typeflag, Mode: entry.mode,
			Size: int64(len(entry.body)), Linkname: entry.linkname,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if len(entry.body) > 0 {
			if _, err := tw.Write(entry.body); err != nil {
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
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

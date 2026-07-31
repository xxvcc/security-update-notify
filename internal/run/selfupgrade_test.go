package run

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

// http.Client.Timeout bounds the entire exchange including reading the response body, so the release
// archive must not share the metadata client's ceiling: a ~16 MB archive under a 60 s limit would
// demand ~2.2 Mbit/s sustained, making --upgrade impossible on a slow link rather than merely slow.
func TestReleaseDownloadDeadlineFitsTheArchive(t *testing.T) {
	if releaseDownloadTimeout <= releaseMetadataTimeout {
		t.Fatalf("archive deadline %v must exceed the metadata deadline %v", releaseDownloadTimeout, releaseMetadataTimeout)
	}
	// A 16 MB archive over a modest 256 kbit/s link needs about 8.5 minutes.
	const archiveBytes = 16 << 20
	const floorBitsPerSecond = 256 << 10
	need := time.Duration(archiveBytes*8/floorBitsPerSecond) * time.Second
	if releaseDownloadTimeout < need {
		t.Fatalf("archive deadline %v cannot fetch %d bytes at %d bit/s (needs %v)",
			releaseDownloadTimeout, archiveBytes, floorBitsPerSecond, need)
	}
}

func TestUpgradeRejectsMalformedLocalVersionIdentity(t *testing.T) {
	for _, candidate := range []string{
		"", "dev", "invalid", "3.1.1\n4.0.0", "3..1",
		" 3.1.1", "3.1.1 ", "3.1.1\n", strings.Repeat("1", 129),
	} {
		if validUpgradeLocalVersion(candidate) {
			t.Errorf("malformed local version %q was accepted", candidate)
		}
	}
	for _, candidate := range []string{"3.1.1", "3.2.0-rc.1", "4.0.0+build.7"} {
		if !validUpgradeLocalVersion(candidate) {
			t.Errorf("valid local version %q was rejected", candidate)
		}
	}
}

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
	cmd := upgradeInstallCommand(context.Background(), binary, extractDir, i18n.EN)
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

func TestTrustedPATHEnvironmentReplacesCallerPATH(t *testing.T) {
	got := trustedPATHEnvironment([]string{
		"PATH=/hostile/bin", "TERM=xterm", "PATH=/second/hostile",
		"LD_PRELOAD=/tmp/attacker.so", "SUDO_ASKPASS=/tmp/attacker", "APT_CONFIG=/tmp/apt.conf",
	})
	if strings.Join(got, "\n") != "TERM=xterm\nLC_ALL=C\nPATH="+privilegedUpgradePath {
		t.Fatalf("trusted environment=%q", got)
	}
}

func TestSelfUpgradeSudoArgsPreserveWhetherLanguageWasExplicit(t *testing.T) {
	tests := []struct {
		name     string
		disp     i18n.Lang
		explicit bool
		want     []string
	}{
		{
			name: "implicit language is resolved again as root",
			disp: i18n.ZH,
			want: []string{"/usr/bin/sudo", "/usr/local/sbin/security-update-notify", "--upgrade"},
		},
		{
			name:     "explicit language survives sudo",
			disp:     i18n.EN,
			explicit: true,
			want:     []string{"/usr/bin/sudo", "/usr/local/sbin/security-update-notify", "--upgrade", "--lang", "en"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := selfUpgradeSudoArgs("/usr/bin/sudo", "/usr/local/sbin/security-update-notify", test.disp, test.explicit)
			if strings.Join(got, "\x00") != strings.Join(test.want, "\x00") {
				t.Fatalf("sudo args=%q want %q", got, test.want)
			}
		})
	}
}

func TestUpgradeInstallCommandHonorsContext(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "verified-installer")
	escaped := filepath.Join(dir, "escaped")
	body := "#!/bin/sh\n(/bin/sleep 0.25; printf escaped > '" + escaped + "') &\nwait\n"
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := upgradeInstallCommand(ctx, binary, t.TempDir(), i18n.EN).Run()
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("timed installer error=%v context=%v", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("timed installer returned after %s", elapsed)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := os.Stat(escaped); err == nil {
		t.Fatal("installer descendant survived context cancellation")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
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

func TestValidateUpgradeBinaryVersionKillsDescendants(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "version-probe")
	escaped := filepath.Join(dir, "escaped")
	body := "#!/bin/sh\nprintf 'security-update-notify 3.0.0\\n'\n(/bin/sleep 0.25; printf escaped > '" + escaped + "') &\nwait\n"
	if err := os.WriteFile(binary, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := validateUpgradeBinaryVersionContext(ctx, binary, dir, "3.0.0"); err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("version probe error=%v, want timeout", err)
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := os.Stat(escaped); err == nil {
		t.Fatal("version-probe descendant survived context cancellation")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
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

package cli

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunModeDryRunExercisesRealCollectionWithoutStateMutation(t *testing.T) {
	envPath := writeRuntimeConfig(t, `
CONFIG_VERSION=4
NOTIFY_CHANNELS=telegram
TELEGRAM_BOT_TOKEN=123456:test-token
TELEGRAM_CHAT_ID=-100123
HOST_LABEL=cli-dry-run
PUBLIC_IP=
INCLUDE_PUBLIC_IP=0
NOTIFY_OK=0
NOTIFY_UPGRADE=0
DEDUP_MODE=daily
DEDUP_INTERVAL_DAYS=3
NOTIFY_LANG=en
BACKEND=apt
CHECK_UPDATE_HEALTH=0
STALE_UPDATE_DAYS=0
CHECK_EOL=0
PENDING_ALERT_DAYS=3
RESTART_ALERT_DAYS=7
CHECK_SELF_UPDATE=0
SELF_UPDATE_CHECK_DAYS=7
`)
	stateDir := filepath.Join(t.TempDir(), "state")
	t.Setenv("SECURITY_UPDATE_NOTIFY_ENV", envPath)
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", stateDir)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", filepath.Join(t.TempDir(), "runtime.lock"))
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "runtime.log"))
	t.Setenv("PATH", runtimeCommandPath(t))

	stdout, stderr, rc := captureCLIOutput(t, func() int {
		return Main("3.0.1-test", []string{
			"run", "--test-reboot", "--no-dedupe", "--dry-run", "--wait-lock", "0", "--lang", "en",
		})
	})
	if rc != 0 {
		t.Fatalf("dry-run exit=%d stderr=%q", rc, stderr)
	}
	if !strings.Contains(stdout, "HASH\t") || !strings.Contains(stdout, "Full reboot: Required") {
		t.Fatalf("dry-run output did not contain the hash and alert: %q", stdout)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run created state directory: %v", err)
	}
}

func TestDoctorModeUsesCommandFixturesWhenSystemdAvailable(t *testing.T) {
	if info, err := os.Stat("/run/systemd/system"); err != nil || !info.IsDir() {
		t.Skip("doctor's systemd success path requires /run/systemd/system")
	}
	envPath := writeRuntimeConfig(t, `
CONFIG_VERSION=4
NOTIFY_CHANNELS=telegram
TELEGRAM_BOT_TOKEN=123456:test-token
TELEGRAM_CHAT_ID=-100123
HOST_LABEL=doctor-host
INCLUDE_PUBLIC_IP=0
NOTIFY_UPGRADE=0
NOTIFY_LANG=en
BACKEND=apt
CHECK_UPDATE_HEALTH=0
CHECK_EOL=0
CHECK_SELF_UPDATE=0
`)
	t.Setenv("SECURITY_UPDATE_NOTIFY_ENV", envPath)
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", t.TempDir())
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", filepath.Join(t.TempDir(), "runtime.lock"))
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "runtime.log"))
	t.Setenv("PATH", runtimeCommandPath(t))

	stdout, stderr, rc := captureCLIOutput(t, func() int {
		return Main("3.0.1-test", []string{"doctor", "--skip-notify", "--lang", "en"})
	})
	if rc != 0 {
		t.Fatalf("doctor exit=%d stdout=%q stderr=%q", rc, stdout, stderr)
	}
	for _, want := range []string{
		"OK config readable",
		"OK timer enabled",
		"OK package unattended-upgrades fully installed",
		"SKIP Telegram connectivity check",
		"OK automatic security-update mechanism healthy",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("doctor output missing %q: %q", want, stdout)
		}
	}
}

func TestRunModeParsingAndModePrecedence(t *testing.T) {
	envPath := writeRuntimeConfig(t, "CONFIG_VERSION=4\nNOTIFY_CHANNELS=telegram\nNOTIFY_UPGRADE=0\nBACKEND=apt\nINCLUDE_PUBLIC_IP=0\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n")
	t.Setenv("SECURITY_UPDATE_NOTIFY_ENV", envPath)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", filepath.Join(t.TempDir(), "runtime.lock"))

	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "help", args: []string{"run", "--help"}, want: 0},
		{name: "unknown", args: []string{"run", "--unknown"}, want: 2},
		{name: "missing wait", args: []string{"run", "--wait-lock"}, want: 2},
		{name: "invalid wait", args: []string{"run", "--wait-lock", "3601"}, want: 2},
		{name: "missing language", args: []string{"run", "--lang"}, want: 2},
		{name: "invalid language", args: []string{"run", "--lang", "fr"}, want: 2},
		{name: "missing from", args: []string{"run", "--upgrade-from"}, want: 2},
		{name: "missing to", args: []string{"run", "--upgrade-to"}, want: 2},
		{name: "disabled upgrade notification", args: []string{"run", "--notify-upgrade-event", "--upgrade-from", "2.9.9", "--upgrade-to", "3.0.1"}, want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, got := captureCLIOutput(t, func() int { return Main("3.0.1-test", test.args) })
			if got != test.want {
				t.Fatalf("Main(%q)=%d want %d", test.args, got, test.want)
			}
		})
	}

	badConfig := writeRuntimeConfig(t, "UNSUPPORTED_KEY=value\n")
	t.Setenv("SECURITY_UPDATE_NOTIFY_ENV", badConfig)
	_, _, rc := captureCLIOutput(t, func() int {
		return Main("3.0.1-test", []string{"run", "--dry-run", "--test-reboot"})
	})
	if rc != 2 {
		t.Fatalf("invalid config exit=%d want 2", rc)
	}
}

func TestTrustHelperExitContracts(t *testing.T) {
	for _, test := range []struct {
		args []string
		want int
	}{
		{args: []string{"version-newer"}, want: 2},
		{args: []string{"version-newer", "3.0.0", "3.0.1"}, want: 0},
		{args: []string{"version-newer", "3.0.1", "3.0.1"}, want: 1},
		{args: []string{"verify", "--bad-flag"}, want: 2},
		{args: []string{"verify"}, want: 2},
		{args: []string{"check-archive", "--bad-flag"}, want: 2},
		{args: []string{"check-archive"}, want: 2},
	} {
		_, _, got := captureCLIOutput(t, func() int { return Main("3.0.1-test", test.args) })
		if got != test.want {
			t.Fatalf("Main(%q)=%d want %d", test.args, got, test.want)
		}
	}

	dir := t.TempDir()
	archive := filepath.Join(dir, "release.tar.gz")
	writeCLITestArchive(t, archive, "release-3.0.1")
	if _, _, rc := captureCLIOutput(t, func() int {
		return Main("3.0.1-test", []string{"check-archive", "--tarball", archive, "--top-dir", "release-3.0.1"})
	}); rc != 0 {
		t.Fatalf("valid check-archive exit=%d", rc)
	}
	if _, _, rc := captureCLIOutput(t, func() int {
		return Main("3.0.1-test", []string{"check-archive", "--tarball", archive, "--top-dir", "wrong"})
	}); rc != 1 {
		t.Fatalf("mismatched check-archive exit=%d", rc)
	}
	if _, _, rc := captureCLIOutput(t, func() int {
		return Main("3.0.1-test", []string{
			"verify", "--tarball", archive, "--sha256", "missing.sha256", "--asc", "missing.asc",
			"--pubkey", "missing.pub", "--fingerprint", strings.Repeat("A", 40),
		})
	}); rc != 1 {
		t.Fatalf("invalid release verification exit=%d", rc)
	}
}

func runtimeCommandPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeCLICommand(t, dir, "systemctl", `
case "$1" in
  is-enabled) printf '%s\n' enabled ;;
  show)
    case "$4" in
      Result) printf '%s\n' success ;;
    esac
    exit 0
    ;;
esac
exit 0
`)
	writeCLICommand(t, dir, "dpkg", `
[ "$1" = "-s" ] || exit 2
printf '%s\n' "Package: $2" "Status: install ok installed"
`)
	writeCLICommand(t, dir, "apt-get", "exit 0\n")
	writeCLICommand(t, dir, "needrestart", "exit 0\n")
	writeCLICommand(t, dir, "unattended-upgrade", "exit 0\n")
	writeCLICommand(t, dir, "hostname", `
if [ "${1:-}" = "-f" ]; then printf '%s\n' fixture.example.test; else printf '%s\n' fixture; fi
`)
	writeCLICommand(t, dir, "uname", "printf '%s\n' 6.12-fixture\n")
	return dir
}

func writeCLICommand(t *testing.T, dir, name, body string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
}

func writeRuntimeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "runtime.env")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCLITestArchive(t *testing.T, path, top string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	body := []byte("VERSION=3.0.1\n")
	for _, header := range []*tar.Header{
		{Name: top + "/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: top + "/VERSION", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))},
	} {
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeReg {
			if _, err := tw.Write(body); err != nil {
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
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func captureCLIOutput(t *testing.T, fn func() int) (stdout, stderr string, rc int) {
	t.Helper()
	oldStdout, oldStderr := os.Stdout, os.Stderr
	stdoutFile, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	stderrFile, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdoutFile, stderrFile
	defer func() {
		os.Stdout, os.Stderr = oldStdout, oldStderr
	}()

	rc = fn()
	if _, err := stdoutFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := stderrFile.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	stdoutBytes, err := io.ReadAll(stdoutFile)
	if err != nil {
		t.Fatal(err)
	}
	stderrBytes, err := io.ReadAll(stderrFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := stdoutFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := stderrFile.Close(); err != nil {
		t.Fatal(err)
	}
	return string(stdoutBytes), string(stderrBytes), rc
}

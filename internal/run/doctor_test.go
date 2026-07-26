package run

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

func TestDoctorReportsControlledDNFFailures(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-doctor'\n")
	t.Setenv("PATH", dir)
	cfg := patchTestConfig(t, "BACKEND=dnf\nHOST_LABEL=doctor-host\nINCLUDE_PUBLIC_IP=0\nNOTIFY_CHANNELS=unsupported\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n")

	output, got := captureDoctorOutput(t, func() int {
		return Doctor(cfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: filepath.Join(t.TempDir(), "missing.env")})
	})
	if got != 1 {
		t.Fatalf("Doctor()=%d want 1", got)
	}
	for _, want := range []string{
		"FAIL config not readable",
		"FAIL systemd unavailable",
		"FAIL missing dnf/yum",
		"FAIL missing needs-restarting",
		"FAIL invalid notification channel configuration",
		"FAIL automatic security-update mechanism issue",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Doctor output missing %q:\n%s", want, output)
		}
	}
}

func TestDoctorDNFHappyPathWithSkippedNotificationProbe(t *testing.T) {
	if !fileExists("/run/systemd/system") {
		t.Skip("doctor's systemd success path requires /run/systemd/system")
	}
	dir := t.TempDir()
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-doctor'\n")
	writeTestCommand(t, dir, "systemctl", "exit 0\n")
	writeTestCommand(t, dir, "dnf", "exit 0\n")
	writeTestCommand(t, dir, "needs-restarting", `
case "$1" in
  -r) printf '%s\n' 'Reboot should not be necessary.' ;;
  --help) printf '%s\n' 'usage: needs-restarting [-r]' ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)
	envPath := filepath.Join(t.TempDir(), "doctor.env")
	body := "BACKEND=dnf\nHOST_LABEL=doctor-host\nINCLUDE_PUBLIC_IP=0\nNOTIFY_CHANNELS=telegram\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n"
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(envPath)
	if err != nil {
		t.Fatal(err)
	}

	if got := Doctor(cfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: envPath, SkipNotify: true}); got != 0 {
		t.Fatalf("Doctor()=%d want 0", got)
	}
}

func TestFileReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.env")
	if err := os.WriteFile(path, []byte("BACKEND=apt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileReadable(path) || fileReadable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("fileReadable did not distinguish readable and missing paths")
	}
}

func TestDPKGStatusIsInstalled(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "installed", output: "Package: test\nStatus: install ok installed\n", want: true},
		{name: "config files remain", output: "Package: test\nStatus: deinstall ok config-files\n"},
		{name: "unpacked", output: "Package: test\nStatus: install ok unpacked\n"},
		{name: "status-like description", output: "Description: Status: install ok installed\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := dpkgStatusIsInstalled(test.output); got != test.want {
				t.Fatalf("dpkgStatusIsInstalled() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDoctorAPTDependenciesRejectsConfigFilesState(t *testing.T) {
	var output bytes.Buffer
	var packages []string
	ready := doctorAPTDependencies(&output, i18n.EN, func(string) bool { return true }, func(name string, args ...string) sysexec.Result {
		if name != "dpkg" || len(args) != 2 || args[0] != "-s" {
			return sysexec.Result{Code: -1, Err: errors.New("unexpected command")}
		}
		packages = append(packages, args[1])
		status := "install ok installed"
		if args[1] == "unattended-upgrades" {
			status = "deinstall ok config-files"
		}
		return sysexec.Result{Stdout: "Status: " + status + "\n"}
	})
	if ready {
		t.Fatal("config-files package state was reported ready")
	}
	if got := strings.Join(packages, ","); got != "unattended-upgrades,needrestart,apt-listchanges,ca-certificates" {
		t.Fatalf("checked packages = %q", got)
	}
	if text := output.String(); !strings.Contains(text, "FAIL package unattended-upgrades not fully installed") || strings.Contains(text, "OK package unattended-upgrades") {
		t.Fatalf("unexpected doctor output:\n%s", text)
	}
}

func captureDoctorOutput(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	output, err := os.CreateTemp(t.TempDir(), "doctor-output")
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = output
	defer func() {
		os.Stdout = oldStdout
		_ = output.Close()
	}()

	rc := fn()
	if _, err := output.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	return string(contents), rc
}

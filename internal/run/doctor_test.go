package run

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/osrel"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

func TestDoctorReportsControlledDNFFailures(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-doctor'\n")
	t.Setenv("PATH", dir)
	cfg := patchTestConfig(t, "BACKEND=dnf\nHOST_LABEL=doctor-host\nINCLUDE_PUBLIC_IP=0\nNOTIFY_CHANNELS=unsupported\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n")

	output, got := captureDoctorOutput(t, func() int {
		return Doctor(cfg, DoctorOpts{
			Version: "2.7.3", Lang: i18n.EN, EnvPath: filepath.Join(t.TempDir(), "missing.env"),
			Systemd: &recordingSystemdQuery{},
		})
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
		"SKIP automatic security-update mechanism health check disabled",
		"SKIP patch policy, package consistency, and repository health checks disabled",
		"UNKNOWN pending security-update status could not be determined",
		"SKIP release security-support check disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Doctor output missing %q:\n%s", want, output)
		}
	}
	for _, unexpected := range []string{
		"OK automatic security-update mechanism healthy",
		"OK patch policy, package, and repository checks passed",
		"OK no pending security updates",
		"OK release within security support",
	} {
		if strings.Contains(output, unexpected) {
			t.Fatalf("Doctor output contains false success %q:\n%s", unexpected, output)
		}
	}
}

func TestDoctorDNFHappyPathWithSkippedNotificationProbe(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-doctor'\n")
	writeTestCommand(t, dir, "dnf", `
if [ "$*" = "--version" ]; then
  printf '%s\n' '4.14.0'
fi
exit 0
`)
	writeTestCommand(t, dir, "dnf-automatic", "exit 0\n")
	writeTestCommand(t, dir, "needs-restarting", `
case "$1" in
  -r) printf '%s\n' 'Reboot should not be necessary.' ;;
  --help) printf '%s\n' 'usage: needs-restarting [-r]' ;;
  *) exit 2 ;;
esac
`)
	t.Setenv("PATH", dir)
	dnfConfig := filepath.Join(t.TempDir(), "automatic.conf")
	if err := os.WriteFile(dnfConfig, []byte("[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", dnfConfig)
	envPath := filepath.Join(t.TempDir(), "doctor.env")
	body := "BACKEND=dnf\nHOST_LABEL=doctor-host\nINCLUDE_PUBLIC_IP=0\nNOTIFY_CHANNELS=telegram\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n"
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(envPath)
	if err != nil {
		t.Fatal(err)
	}
	systemdQuery := &recordingSystemdQuery{
		available: true,
		enabled: map[string]bool{
			"security-update-notify.timer": true,
			"dnf-automatic.timer":          true,
		},
		values: map[string]string{
			"dnf-automatic.service\x00Result":    "success",
			"dnf-automatic.timer\x00ActiveState": "active",
		},
	}

	output, got := captureDoctorOutput(t, func() int {
		return Doctor(cfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: envPath, SkipNotify: true, Systemd: systemdQuery})
	})
	if got != 0 {
		t.Fatalf("Doctor()=%d want 0\n%s", got, output)
	}
	for _, want := range []string{
		"SKIP automatic security-update mechanism health check disabled",
		"SKIP patch policy, package consistency, and repository health checks disabled",
		"SKIP pending security-update status was not confirmed",
		"SKIP release security-support check disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Doctor output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "OK automatic security-update mechanism healthy") || strings.Contains(output, "OK no pending security updates") {
		t.Fatalf("Doctor output reported a skipped check as successful:\n%s", output)
	}

	checkedPath := filepath.Join(t.TempDir(), "doctor-checked.env")
	checkedBody := strings.Replace(body, "CHECK_UPDATE_HEALTH=0", "CHECK_UPDATE_HEALTH=1", 1)
	if err := os.WriteFile(checkedPath, []byte(checkedBody), 0o600); err != nil {
		t.Fatal(err)
	}
	checkedCfg, err := config.Load(checkedPath)
	if err != nil {
		t.Fatal(err)
	}
	output, got = captureDoctorOutput(t, func() int {
		return Doctor(checkedCfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: checkedPath, SkipNotify: true, Systemd: systemdQuery})
	})
	if got != 0 {
		t.Fatalf("Doctor() with enabled healthy checks=%d want 0\n%s", got, output)
	}
	for _, want := range []string{
		"OK automatic security-update mechanism healthy",
		"OK patch policy, package, and repository checks passed",
		"OK no pending security updates",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Doctor output missing checked result %q:\n%s", want, output)
		}
	}

	systemdQuery.values["dnf-automatic.timer\x00ActiveState"] = "inactive"
	output, got = captureDoctorOutput(t, func() int {
		return Doctor(checkedCfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: checkedPath, SkipNotify: true, Systemd: systemdQuery})
	})
	if got != 1 || !strings.Contains(output, "enabled but not active") {
		t.Fatalf("Doctor() did not reject enabled inactive timer: rc=%d\n%s", got, output)
	}
	systemdQuery.values["dnf-automatic.timer\x00ActiveState"] = "active"

	if err := os.WriteFile(dnfConfig, []byte("[commands]\nupgrade_type = default\napply_updates = no\nreboot = when-needed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, got = captureDoctorOutput(t, func() int {
		return Doctor(cfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: envPath, SkipNotify: true, Systemd: systemdQuery})
	})
	if got != 1 {
		t.Fatalf("Doctor() with policy drift=%d want 1", got)
	}
	for _, want := range []string{
		"FAIL dnf-automatic is not configured for security-only updates",
		"FAIL dnf-automatic is not configured to apply updates",
		"FAIL dnf-automatic is not configured to avoid automatic reboots",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("Doctor output missing %q:\n%s", want, output)
		}
	}
}

func TestDoctorWatchdogStatesDistinguishCheckedSkippedAndUnknown(t *testing.T) {
	if got := doctorPendingState("apt", true, true, watchdog.Pending{}, watchdog.Patch{}); got != doctorCheckChecked {
		t.Fatalf("successful empty query state=%v want checked", got)
	}
	if got := doctorPendingState("apt", true, false, watchdog.Pending{}, watchdog.Patch{}); got != doctorCheckSkipped {
		t.Fatalf("unverified disabled query state=%v want skipped", got)
	}
	if got := doctorPendingState("apt", true, true, watchdog.Pending{}, watchdog.Patch{Sig: "apt-simulation-failed,"}); got != doctorCheckUnknown {
		t.Fatalf("failed query state=%v want unknown", got)
	}
	if got := doctorPendingState("apt", true, true, watchdog.Pending{}, watchdog.Patch{Sig: "apt-simulation-output-invalid,"}); got != doctorCheckUnknown {
		t.Fatalf("malformed query state=%v want unknown", got)
	}
	if got := doctorPendingState("dnf", true, true, watchdog.Pending{}, watchdog.Patch{Sig: "dnf-repository-failed,"}); got != doctorCheckUnknown {
		t.Fatalf("failed DNF query state=%v want unknown", got)
	}
	if got := doctorPendingState("dnf", true, true, watchdog.Pending{Count: 1}, watchdog.Patch{Sig: "dnf-security-transaction-invalid,"}); got != doctorCheckUnknown {
		t.Fatalf("conservative DNF result state=%v want unknown", got)
	}
	if got := doctorPendingState("apt", true, false, watchdog.Pending{Count: 1}, watchdog.Patch{}); got != doctorCheckChecked {
		t.Fatalf("reported pending state=%v want checked", got)
	}

	cfg := patchTestConfig(t, "CHECK_UPDATE_HEALTH=0\nCHECK_EOL=1\nCHECK_SELF_UPDATE=0\n")
	checks := collectDoctorWatchdog(cfg, "unsupported", osrel.OSRelease{ID: "future", VersionID: "1"}, backend.RestartState{}, "3.1.4", false, &recordingSystemdQuery{})
	if checks.healthState != doctorCheckSkipped || checks.patchHealthState != doctorCheckSkipped || checks.pendingState != doctorCheckUnknown || checks.eolState != doctorCheckUnknown {
		t.Fatalf("unexpected doctor states: health=%v patch=%v pending=%v eol=%v", checks.healthState, checks.patchHealthState, checks.pendingState, checks.eolState)
	}
}

func TestDoctorReportsUnknownDNFGenerationWithoutFallbackCommands(t *testing.T) {
	dir := t.TempDir()
	callLog := filepath.Join(t.TempDir(), "dnf.calls")
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-doctor'\n")
	writeTestCommand(t, dir, "systemctl", "exit 0\n")
	writeTestCommand(t, dir, "dnf", `
printf '%s\n' "dnf:$*" >> "$SUN_DNF_CALL_LOG"
if [ "$*" = "--version" ]; then
  printf '%s\n' 'dnf version future'
  exit 0
fi
exit 99
`)
	writeTestCommand(t, dir, "needs-restarting", `printf '%s\n' "needs-restarting:$*" >> "$SUN_DNF_CALL_LOG"`)
	writeTestCommand(t, dir, "dnf-automatic", `printf '%s\n' "dnf-automatic:$*" >> "$SUN_DNF_CALL_LOG"`)
	t.Setenv("PATH", dir)
	t.Setenv("SUN_DNF_CALL_LOG", callLog)
	t.Setenv("SECURITY_UPDATE_NOTIFY_DNF_AUTOMATIC_CONF", filepath.Join(t.TempDir(), "missing.conf"))
	envPath := filepath.Join(t.TempDir(), "doctor.env")
	body := "BACKEND=dnf\nHOST_LABEL=doctor-host\nINCLUDE_PUBLIC_IP=0\nNOTIFY_CHANNELS=unsupported\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n"
	if err := os.WriteFile(envPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(envPath)
	if err != nil {
		t.Fatal(err)
	}

	output, got := captureDoctorOutput(t, func() int {
		return Doctor(cfg, DoctorOpts{Version: "2.7.3", Lang: i18n.EN, EnvPath: envPath})
	})
	if got != 1 || !strings.Contains(output, "FAIL could not reliably identify DNF generation (dnf --version)") {
		t.Fatalf("Doctor()=%d output:\n%s", got, output)
	}
	calls, err := os.ReadFile(callLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Fields(string(calls)) {
		if line != "dnf:--version" {
			t.Fatalf("fallback command executed; calls=%q", calls)
		}
	}
	if strings.Count(string(calls), "dnf:--version\n") < 2 {
		t.Fatalf("expected doctor and watchdog probes; calls=%q", calls)
	}
}

func TestFileReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.env")
	if err := os.WriteFile(path, []byte("BACKEND=apt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !fileReadable(path) || fileReadable(filepath.Join(t.TempDir(), "missing")) {
		t.Fatal("fileReadable did not distinguish readable and missing paths")
	}
	link := filepath.Join(dir, "linked.env")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if fileReadable(link) {
		t.Fatal("fileReadable accepted a symlink")
	}
	fifo := filepath.Join(dir, "fifo.env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if fileReadable(fifo) {
		t.Fatal("fileReadable accepted a FIFO")
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

func TestDoctorAPTDependenciesRejectsTruncatedPackageStatus(t *testing.T) {
	var output bytes.Buffer
	ready := doctorAPTDependencies(&output, i18n.EN, func(string) bool { return true }, func(string, ...string) sysexec.Result {
		return sysexec.Result{
			Stdout:          "Status: install ok installed\n",
			StdoutTruncated: true,
		}
	})
	if ready || !strings.Contains(output.String(), "not fully installed") {
		t.Fatalf("truncated dpkg status was accepted:\n%s", output.String())
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

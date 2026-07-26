package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	configpkg "github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/uninstaller"
)

type fakeLocker struct {
	mu       sync.Mutex
	busyPath string
	calls    []string
	waits    []time.Duration
}

type failMarkerBackupFS struct {
	FileSystem
	enabled bool
}

func (f *failMarkerBackupFS) CopyRegularFileAtomic(source, destination string, maxBytes int64) error {
	if f.enabled && source == aptAbsentMarkerPath && strings.HasPrefix(destination, BackupRoot+"/") {
		return errors.New("forced marker backup failure")
	}
	return f.FileSystem.CopyRegularFileAtomic(source, destination, maxBytes)
}

func (l *fakeLocker) Acquire(_ context.Context, lockPath string, wait time.Duration) (UnlockFunc, error) {
	l.mu.Lock()
	l.calls = append(l.calls, lockPath)
	l.waits = append(l.waits, wait)
	l.mu.Unlock()
	if lockPath == l.busyPath {
		return nil, ErrLockBusy
	}
	return func() error { return nil }, nil
}

func TestExplicitZeroRuntimeLockWaitIsPreserved(t *testing.T) {
	installer, root, _, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
	values := cloneConfig(configDefaults)
	values["NOTIFY_CHANNELS"] = "telegram"
	values["TELEGRAM_BOT_TOKEN"] = "123456:old_token"
	values["TELEGRAM_CHAT_ID"] = "-100"
	values["BACKEND"] = "apt"
	writeConfig(t, root, values)
	write(t, root, BinaryPath, "old-runtime", 0o755)
	options := telegramOptions()
	options.LockWaitSet = true
	options.LockWait = 0
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if len(locker.calls) < 2 || locker.calls[1] != RuntimeLockPath || locker.waits[1] != 0 {
		t.Fatalf("lock calls=%v waits=%v, want explicit zero runtime wait", locker.calls, locker.waits)
	}
}

type fakeRunner struct {
	fs                      *RootFS
	mu                      sync.Mutex
	commands                []string
	missingPackages         map[string]bool
	dpkgStatuses            map[string]string
	missingCommands         map[string]bool
	systemdCreds            bool
	timerActive             bool
	failListTimers          bool
	createAPTDefaultInstall bool
	aptMarkerBeforeWrite    bool
	aptWriteObserved        bool
	doctorResult            CommandResult
	testResult              CommandResult
}

func (r *fakeRunner) LookPath(name string) bool {
	if name == "systemd-creds" {
		return r.systemdCreds
	}
	return !r.missingCommands[name]
}

func (r *fakeRunner) Run(_ context.Context, command Command) CommandResult {
	r.mu.Lock()
	r.commands = append(r.commands, command.Name+" "+strings.Join(command.Args, " "))
	r.mu.Unlock()
	result := CommandResult{}
	switch command.Name {
	case "systemctl":
		return r.systemctl(command.Args)
	case "dpkg":
		if len(command.Args) < 2 {
			return CommandResult{Code: 2, Stderr: []byte("missing package argument")}
		}
		if len(command.Args) >= 2 && r.missingPackages[command.Args[1]] {
			result.Code = 1
			return result
		}
		status := "install ok installed"
		if len(command.Args) >= 2 && r.dpkgStatuses[command.Args[1]] != "" {
			status = r.dpkgStatuses[command.Args[1]]
		}
		result.Stdout = []byte("Package: " + command.Args[1] + "\nStatus: " + status + "\n")
		return result
	case "rpm":
		if len(command.Args) >= 2 && r.missingPackages[command.Args[1]] {
			result.Code = 1
		}
		return result
	case "apt-get", "dnf", "microdnf", "yum":
		if command.Name == "apt-get" && len(command.Args) > 0 && (command.Args[0] == "update" || command.Args[0] == "install") {
			data, err := r.fs.ReadFile(aptAbsentMarkerPath)
			markerValid := err == nil && string(data) == aptAbsentMarkerContents
			if !r.aptWriteObserved {
				r.aptMarkerBeforeWrite = markerValid
			} else {
				r.aptMarkerBeforeWrite = r.aptMarkerBeforeWrite && markerValid
			}
			r.aptWriteObserved = true
		}
		if len(command.Args) > 0 && command.Args[0] == "install" {
			for _, pkg := range command.Args[2:] {
				delete(r.missingPackages, pkg)
				delete(r.dpkgStatuses, pkg)
			}
			if r.createAPTDefaultInstall {
				_ = r.fs.MkdirAll("/etc/apt/apt.conf.d", 0o755)
				_ = r.fs.WriteFileAtomic("/etc/apt/apt.conf.d/20auto-upgrades", []byte("dependency-default\n"), 0o644)
			}
		}
		return result
	case "systemd-creds":
		if len(command.Args) > 0 && command.Args[0] == "encrypt" {
			result.Stdout = append([]byte("encrypted:"), command.Stdin...)
		}
		if len(command.Args) > 0 && command.Args[0] == "decrypt" {
			result.Stdout = []byte("existing-secret")
		}
		return result
	case BinaryPath:
		if len(command.Args) > 0 && command.Args[0] == "--version" {
			data, _ := r.fs.ReadFile(BinaryPath)
			version := "3.0.0"
			if bytes.Equal(data, []byte("old-runtime")) {
				version = "2.3.0"
			}
			result.Stdout = []byte("security-update-notify " + version + "\n")
		}
		if len(command.Args) > 0 && command.Args[0] == "--doctor" {
			return r.doctorResult
		}
		if len(command.Args) > 0 && command.Args[0] == "--test-ok" {
			return r.testResult
		}
		return result
	default:
		return result
	}
}

func (r *fakeRunner) systemctl(args []string) CommandResult {
	result := CommandResult{}
	if len(args) == 0 {
		return result
	}
	switch args[0] {
	case "is-enabled":
		if existsNoErr(r.fs, PersistentTimerLink) {
			result.Stdout = []byte("enabled\n")
			return result
		}
		if existsNoErr(r.fs, RuntimeTimerLink) {
			result.Stdout = []byte("enabled-runtime\n")
			return result
		}
		if existsNoErr(r.fs, TimerPath) {
			result.Stdout, result.Code = []byte("disabled\n"), 1
			return result
		}
		result.Stdout, result.Code = []byte("not-found\n"), 1
	case "is-active":
		if !r.timerActive {
			result.Code = 3
		}
	case "disable":
		_ = r.fs.Remove(PersistentTimerLink)
		_ = r.fs.Remove(RuntimeTimerLink)
		r.timerActive = false
	case "enable":
		project := false
		for _, arg := range args {
			project = project || arg == "security-update-notify.timer"
		}
		if project {
			_ = r.fs.MkdirAll(path.Dir(PersistentTimerLink), 0o755)
			_ = r.fs.Remove(PersistentTimerLink)
			_ = r.fs.Symlink("../security-update-notify.timer", PersistentTimerLink)
			for _, arg := range args {
				if arg == "--now" {
					r.timerActive = true
				}
			}
		}
	case "start":
		r.timerActive = true
	case "list-timers":
		if r.failListTimers {
			result.Code, result.Stderr = 1, []byte("forced list-timers failure")
		}
	}
	return result
}

func existsNoErr(filesystem FileSystem, name string) bool {
	_, err := filesystem.Lstat(name)
	return err == nil
}

func setupInstaller(t *testing.T, release string) (*Installer, *RootFS, *fakeRunner, *fakeLocker) {
	t.Helper()
	root, err := NewRootFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		"/etc", "/run/systemd/system", "/etc/systemd/system", "/etc/apt/apt.conf.d",
		"/etc/logrotate.d", "/var/log", "/usr/local/sbin",
	} {
		if err := root.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := root.WriteFileAtomic("/etc/os-release", []byte(release), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{
		fs: root, missingPackages: map[string]bool{}, dpkgStatuses: map[string]string{}, missingCommands: map[string]bool{},
	}
	locker := &fakeLocker{}
	installer, err := New(Dependencies{
		FS: root, Runner: runner, Locker: locker, EffectiveUID: func() int { return 0 },
		RootOwnerUID: uint32(os.Geteuid()),
		Now:          func() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return installer, root, runner, locker
}

func telegramOptions() Options {
	return Options{
		Config: map[string]string{
			"NOTIFY_CHANNELS": "telegram", "TELEGRAM_BOT_TOKEN": "123456:abc_DEF-ghi",
			"TELEGRAM_CHAT_ID": "-100123", "NOTIFY_LANG": "en",
		},
		Payload: Payload{Runtime: []byte("new-runtime")},
	}
}

func TestFreshAPTInstall(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
	options := telegramOptions()
	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Upgrade || result.Backend != "apt" || result.SupportTier != "supported" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if got := readFile(t, root, BinaryPath); got != "new-runtime" {
		t.Fatalf("runtime=%q", got)
	}
	configData := readFile(t, root, ConfigPath)
	for _, want := range []string{"CONFIG_VERSION='4'", "BACKEND='apt'", "NOTIFY_CHANNELS='telegram'", "NOTIFY_LANG='en'"} {
		if !strings.Contains(configData, want) {
			t.Errorf("config missing %q:\n%s", want, configData)
		}
	}
	assertMode(t, root, ConfigPath, 0o600)
	assertMode(t, root, BinaryPath, 0o755)
	if got := readFile(t, root, "/etc/apt/apt.conf.d/20auto-upgrades"); got != aptPeriodicConfig {
		t.Errorf("apt periodic config drifted:\n%s", got)
	}
	if !existsNoErr(root, PersistentTimerLink) || !runner.timerActive {
		t.Fatal("project timer was not enabled and started")
	}
	if len(locker.calls) != 1 || locker.calls[0] != InstallLockPath {
		t.Fatalf("fresh install unexpectedly crossed runtime lock: %v", locker.calls)
	}
	if result.BackupDir == "" || !existsNoErr(root, result.BackupDir+"/manifest") {
		t.Fatalf("backup was not created: %+v", result)
	}
}

func TestPostInstallDoctorFailureIsAdvisoryAndReturned(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
	runner.doctorResult = CommandResult{
		Stdout: []byte("FAIL low disk\n"),
		Stderr: []byte("doctor detail\n"),
		Code:   1,
	}

	result, err := installer.Install(context.Background(), telegramOptions())
	if err != nil {
		t.Fatalf("advisory doctor result rolled back installation: %v", err)
	}
	if result.PostInstallDoctor == nil {
		t.Fatal("post-install doctor result was not returned")
	}
	if got := string(result.PostInstallDoctor.Stdout); got != "FAIL low disk\n" {
		t.Fatalf("doctor stdout=%q", got)
	}
	if got := string(result.PostInstallDoctor.Stderr); got != "doctor detail\n" {
		t.Fatalf("doctor stderr=%q", got)
	}
	if result.PostInstallDoctor.Code != 1 || result.PostInstallDoctor.Err != nil {
		t.Fatalf("doctor result=%+v", *result.PostInstallDoctor)
	}
	if !existsNoErr(root, PersistentTimerLink) || !runner.timerActive {
		t.Fatal("advisory doctor failure rolled back or disabled the project timer")
	}
}

func TestExplicitPostInstallTestFailureIsAdvisoryAndReturned(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
	runner.testResult = CommandResult{
		Stderr: []byte("temporary delivery failure\n"),
		Code:   75,
		Err:    context.DeadlineExceeded,
	}
	options := telegramOptions()
	options.SendTest = true

	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatalf("advisory test result rolled back installation: %v", err)
	}
	if result.PostInstallTest == nil {
		t.Fatal("post-install test result was not returned")
	}
	if got := string(result.PostInstallTest.Stderr); got != "temporary delivery failure\n" {
		t.Fatalf("test stderr=%q", got)
	}
	if result.PostInstallTest.Code != 75 || !errors.Is(result.PostInstallTest.Err, context.DeadlineExceeded) {
		t.Fatalf("test result=%+v", *result.PostInstallTest)
	}
	if !existsNoErr(root, PersistentTimerLink) || !runner.timerActive {
		t.Fatal("advisory test failure rolled back or disabled the project timer")
	}
}

func TestInstallReadsStandardOSReleaseSymlink(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=placeholder\nVERSION_ID=0\n")
	if err := root.Remove("/etc/os-release"); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/usr/lib/os-release", "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n", 0o644)
	if err := root.Symlink("../usr/lib/os-release", "/etc/os-release"); err != nil {
		t.Fatal(err)
	}
	result, err := installer.Install(context.Background(), telegramOptions())
	if err != nil {
		t.Fatal(err)
	}
	if result.Backend != "apt" || result.SupportTier != "supported" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestCustomFilesystemRequiresExplicitRunner(t *testing.T) {
	root, err := NewRootFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Dependencies{FS: root}); err == nil || !strings.Contains(err.Error(), "explicit command runner") {
		t.Fatalf("custom filesystem selected host runner: %v", err)
	}
}

func TestFreshDNFInstall(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=42\nPRETTY_NAME='Fedora Linux 42'\n")
	write(t, root, "/etc/dnf/automatic.conf", "[commands]\nupgrade_type = default\napply_updates = no\n", 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Backend != "dnf" || result.SupportTier != "supported" {
		t.Fatalf("unexpected result: %+v", result)
	}
	dnfConfig := readFile(t, root, "/etc/dnf/automatic.conf")
	for _, setting := range []string{"upgrade_type = security", "apply_updates = yes", "emit_via = stdio", "debuglevel = 1"} {
		if !strings.Contains(dnfConfig, setting) {
			t.Errorf("dnf config missing %q:\n%s", setting, dnfConfig)
		}
	}
	if !strings.Contains(readFile(t, root, ConfigPath), "BACKEND='dnf'") {
		t.Fatal("resolved dnf backend was not persisted")
	}
	if commandIndex(runner.commands, "systemctl enable --now dnf-automatic.timer") < 0 {
		t.Fatal("dnf-automatic.timer was not enabled")
	}
}

func TestDNFDependencyInstallFallsBackToMicrodnf(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	write(t, root, dnfAutomaticPath, "[commands]\nupgrade_type = default\napply_updates = no\n", 0o644)
	for _, pkg := range []string{"dnf-automatic", "ca-certificates", "yum-utils"} {
		runner.missingPackages[pkg] = true
	}
	runner.missingCommands["dnf"] = true
	runner.missingCommands["yum"] = true

	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		want := []string{"dnf-automatic", "ca-certificates", "yum-utils"}
		if request.Backend != "dnf" || !reflect.DeepEqual(request.Packages, want) {
			return false, fmt.Errorf("unexpected dependency request: %+v", request)
		}
		return true, nil
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	want := "microdnf install -y dnf-automatic ca-certificates yum-utils"
	if commandIndex(runner.commands, want) < 0 {
		t.Fatalf("microdnf fallback was not used; commands:\n%s", strings.Join(runner.commands, "\n"))
	}
}

func TestDNFDependencyInstallReportsAllSupportedManagers(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\n")
	write(t, root, dnfAutomaticPath, "[commands]\n", 0o644)
	runner.missingPackages["dnf-automatic"] = true
	for _, manager := range []string{"dnf", "microdnf", "yum"} {
		runner.missingCommands[manager] = true
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "dnf, microdnf, or yum is required") {
		t.Fatalf("error = %v, want supported-manager diagnostic", err)
	}
}

func TestUpgradeFailureRollsBackAfterDependencyMutation(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	oldValues := cloneConfig(configDefaults)
	oldValues["NOTIFY_CHANNELS"] = "telegram,feishu"
	oldValues["TELEGRAM_BOT_TOKEN"] = "123456:old_token"
	oldValues["TELEGRAM_CHAT_ID"] = "-100"
	oldValues["FEISHU_APP_ID"] = "cli_old"
	oldValues["FEISHU_RECEIVE_ID"] = "ou_old"
	oldValues["BACKEND"] = "apt"
	writeConfig(t, root, oldValues)
	write(t, root, BinaryPath, "old-runtime", 0o755)
	write(t, root, ServicePath, "old-service", 0o644)
	write(t, root, TimerPath, renderTimer("08:30"), 0o644)
	write(t, root, FeishuPlainCredentialPath, "existing-secret", 0o600)
	if err := root.MkdirAll(path.Dir(PersistentTimerLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("../security-update-notify.timer", PersistentTimerLink); err != nil {
		t.Fatal(err)
	}
	runner.timerActive = true
	runner.missingPackages["apt-listchanges"] = true
	runner.createAPTDefaultInstall = true
	runner.failListTimers = true
	preflightCalled := false
	options := Options{
		Config:  map[string]string{"HOST_LABEL": "changed"},
		Payload: Payload{Runtime: []byte("new-runtime")},
		ConfirmDependencies: func(_ context.Context, request DependencyRequest) (bool, error) {
			if request.Backend != "apt" || len(request.Packages) != 1 || request.Packages[0] != "apt-listchanges" {
				return false, fmt.Errorf("unexpected dependency request: %+v", request)
			}
			return true, nil
		},
		Preflight: func(_ context.Context, prepared *Prepared) error {
			preflightCalled = true
			if string(prepared.FeishuSecret) != "existing-secret" || !prepared.Upgrade {
				return fmt.Errorf("unexpected preflight: %+v", prepared)
			}
			return nil
		},
	}
	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("expected forced late failure, got %v", err)
	}
	if !preflightCalled {
		t.Fatal("preflight was not called")
	}
	if got := readFile(t, root, BinaryPath); got != "old-runtime" {
		t.Fatalf("runtime not rolled back: %q", got)
	}
	if got := readFile(t, root, ServicePath); got != "old-service" {
		t.Fatalf("service not rolled back: %q", got)
	}
	if got := readFile(t, root, FeishuPlainCredentialPath); got != "existing-secret" {
		t.Fatalf("credential not rolled back: %q", got)
	}
	if strings.Contains(readFile(t, root, ConfigPath), "HOST_LABEL='changed'") {
		t.Fatal("config override survived rollback")
	}
	if got := readFile(t, root, "/etc/apt/apt.conf.d/20auto-upgrades"); got != "dependency-default\n" {
		t.Fatalf("dependency-created default not restored: %q", got)
	}
	if !existsNoErr(root, PersistentTimerLink) || !runner.timerActive {
		t.Fatal("old timer enablement/activity was not restored")
	}
	if len(locker.calls) < 3 || locker.calls[0] != InstallLockPath || locker.calls[1] != RuntimeLockPath || locker.calls[2] != RuntimeLockPath {
		t.Fatalf("unexpected transaction lock sequence: %v", locker.calls)
	}
	assertCommandOrder(t, runner.commands,
		"systemctl disable --now security-update-notify.timer",
		"dpkg -s apt-listchanges",
		"apt-get update",
	)
}

func TestDependencyInstallRequiresApprovalBeforePackageManagerWrites(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.missingPackages["apt-listchanges"] = true
	options := telegramOptions()
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		if request.Backend != "apt" || len(request.Packages) != 1 || request.Packages[0] != "apt-listchanges" {
			t.Fatalf("unexpected dependency request: %+v", request)
		}
		request.Packages[0] = "mutated-by-caller"
		return false, nil
	}
	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "declined") {
		t.Fatalf("declined dependency install err=%v", err)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "apt-get ") || strings.HasPrefix(command, "dnf ") ||
			strings.HasPrefix(command, "microdnf ") || strings.HasPrefix(command, "yum ") {
			t.Fatalf("package manager wrote before approval: %s", command)
		}
	}
}

func TestMissingDependencyWithoutConfirmationDoesNotWrite(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.missingPackages["needrestart"] = true
	_, err := installer.Install(context.Background(), telegramOptions())
	if err == nil || !strings.Contains(err.Error(), "no confirmation callback") {
		t.Fatalf("missing callback err=%v", err)
	}
	if commandIndex(runner.commands, "apt-get update") >= 0 {
		t.Fatal("apt-get update ran without dependency confirmation")
	}
}

func TestAPTConfigFilesPackageStateIsReinstalled(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.dpkgStatuses["unattended-upgrades"] = "deinstall ok config-files"
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		if request.Backend != "apt" || !reflect.DeepEqual(request.Packages, []string{"unattended-upgrades"}) {
			return false, fmt.Errorf("unexpected dependency request: %+v", request)
		}
		return true, nil
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if commandIndex(runner.commands, "apt-get install -y unattended-upgrades") < 0 {
		t.Fatalf("config-files package was not reinstalled:\n%s", strings.Join(runner.commands, "\n"))
	}
}

func TestFreshAPTAbsentBaselineIsRemovedByPurge(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.missingPackages["unattended-upgrades"] = true
	runner.createAPTDefaultInstall = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		return reflect.DeepEqual(request.Packages, []string{"unattended-upgrades"}), nil
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("APT absence marker = %q", got)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("dependency-created APT default was incorrectly recorded as the original baseline")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("purge did not restore the originally absent APT configuration")
	}
}

func TestAPTAbsentMarkerPrecedesPackageManagerWrites(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.missingPackages["unattended-upgrades"] = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, _ DependencyRequest) (bool, error) { return true, nil }
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if !runner.aptWriteObserved || !runner.aptMarkerBeforeWrite {
		t.Fatal("APT absence marker was not durable before package-manager writes")
	}
}

func TestLegacyAPTMetadataMigratesToSilentNames(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	legacyTimestamp := aptStableBackupPath + ".20260725010203"
	currentTimestamp := aptPeriodicPath + ".security-update-notify.20260725010203.bak"
	write(t, root, aptLegacyAbsentPath, aptAbsentMarkerContents, 0o600)
	write(t, root, legacyTimestamp, "legacy timestamp\n", 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptLegacyAbsentPath) || existsNoErr(root, legacyTimestamp) {
		t.Fatal("legacy APT metadata names survived migration")
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("migrated APT marker = %q", got)
	}
	if got := readFile(t, root, currentTimestamp); got != "legacy timestamp\n" {
		t.Fatalf("migrated APT timestamp backup = %q", got)
	}
	for _, name := range []string{path.Base(aptAbsentMarkerPath), path.Base(currentTimestamp)} {
		if !strings.HasSuffix(name, ".bak") {
			t.Fatalf("APT metadata name is not silently ignored: %s", name)
		}
	}
}

func TestLegacyAPTMetadataMigrationRejectsSymlink(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	legacyTimestamp := aptStableBackupPath + ".20260725010203"
	if err := root.Symlink("/etc/passwd", legacyTimestamp); err != nil {
		t.Fatal(err)
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "inspect legacy apt backup") {
		t.Fatalf("install error = %v, want unsafe legacy-backup rejection", err)
	}
	if target, readErr := root.Readlink(legacyTimestamp); readErr != nil || target != "/etc/passwd" {
		t.Fatalf("legacy symlink changed during failed migration: target=%q err=%v", target, readErr)
	}
	if existsNoErr(root, BinaryPath) {
		t.Fatal("failed metadata migration installed the runtime")
	}
}

func TestLegacyAPTMetadataMigrationIgnoresUnknownSuffix(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	unknown := aptStableBackupPath + ".not-a-timestamp"
	write(t, root, unknown, "unrelated\n", 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, unknown); got != "unrelated\n" {
		t.Fatalf("unknown APT metadata was changed: %q", got)
	}
	unexpectedDestination := aptPeriodicPath + ".security-update-notify.not-a-timestamp.bak"
	if existsNoErr(root, unexpectedDestination) {
		t.Fatal("unknown APT metadata suffix was migrated")
	}
}

func TestLegacyAPTMetadataMigrationRollsBackOnLateFailure(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	legacyTimestamp := aptStableBackupPath + ".20260725010203"
	currentTimestamp := aptPeriodicPath + ".security-update-notify.20260725010203.bak"
	write(t, root, aptLegacyAbsentPath, aptAbsentMarkerContents, 0o600)
	write(t, root, legacyTimestamp, "legacy timestamp\n", 0o600)
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("install error = %v, want late activation failure", err)
	}
	if got := readFile(t, root, aptLegacyAbsentPath); got != aptAbsentMarkerContents {
		t.Fatalf("legacy APT marker after rollback = %q", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("migrated APT marker survived rollback")
	}
	if got := readFile(t, root, legacyTimestamp); got != "legacy timestamp\n" {
		t.Fatalf("legacy APT timestamp after rollback = %q", got)
	}
	if existsNoErr(root, currentTimestamp) {
		t.Fatal("migrated APT timestamp survived rollback")
	}
}

func TestLegacyAPTMetadataMigrationRollsBackExactlyOnLateFailure(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	legacyTimestamp := aptStableBackupPath + ".20260725010203"
	currentTimestamp := aptPeriodicPath + ".security-update-notify.20260725010203.bak"
	write(t, root, aptLegacyAbsentPath, aptAbsentMarkerContents, 0o600)
	write(t, root, legacyTimestamp, "legacy timestamp\n", 0o600)
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("install error = %v, want late activation failure", err)
	}
	if got := readFile(t, root, aptLegacyAbsentPath); got != aptAbsentMarkerContents {
		t.Fatalf("legacy APT marker after rollback = %q", got)
	}
	if got := readFile(t, root, legacyTimestamp); got != "legacy timestamp\n" {
		t.Fatalf("legacy APT timestamp after rollback = %q", got)
	}
	for _, unexpected := range []string{aptAbsentMarkerPath, currentTimestamp, aptPeriodicPath} {
		if existsNoErr(root, unexpected) {
			t.Fatalf("migration artifact survived rollback: %s", unexpected)
		}
	}
}

func TestCaptureDependencyDefaultsPreservesAnyManagedPathCreatedAfterSnapshot(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	b, err := installer.createBackup()
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, ServicePath, "package-created default\n", 0o644)
	if err := installer.captureDependencyDefaults(b); err != nil {
		t.Fatal(err)
	}
	snapshot := b.snapshots[ServicePath]
	if !snapshot.exists {
		t.Fatal("managed path created after the transaction snapshot was not captured")
	}
	if got := readFile(t, root, snapshot.backupPath); got != "package-created default\n" {
		t.Fatalf("captured managed path = %q", got)
	}
}

func TestFreshAPTAbsentBaselineSurvivesFailedInstallRetryAndPurge(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.missingPackages["unattended-upgrades"] = true
	runner.createAPTDefaultInstall = true
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		return reflect.DeepEqual(request.Packages, []string{"unattended-upgrades"}), nil
	}

	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("first install error = %v, want late failure", err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != "dependency-default\n" {
		t.Fatalf("dependency-created APT default after rollback = %q", got)
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("APT absence marker after rollback = %q", got)
	}

	runner.failListTimers = false
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("retry replaced the original absent baseline with a stable file backup")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("purge after a failed first attempt and retry did not restore the originally absent APT configuration")
	}
}

func TestAPTAbsentBaselineSurvivesMarkerCaptureFailureRetryAndPurge(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	faults := &failMarkerBackupFS{FileSystem: root, enabled: true}
	installer.fs = faults
	runner.missingPackages["unattended-upgrades"] = true
	runner.createAPTDefaultInstall = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		return reflect.DeepEqual(request.Packages, []string{"unattended-upgrades"}), nil
	}

	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "forced marker backup failure") {
		t.Fatalf("first install error = %v, want marker capture failure", err)
	}
	if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("failed marker capture did not roll back to the original absent state")
	}

	faults.enabled = false
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("retry recorded the dependency default as the original APT baseline")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("purge after marker capture failure and retry did not restore the original absent state")
	}
}

func TestInstallRejectsInvalidAPTAbsenceMarker(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, aptAbsentMarkerPath, "invalid\n", 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "invalid contents") {
		t.Fatalf("error = %v, want invalid marker failure", err)
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != "invalid\n" {
		t.Fatalf("invalid pre-existing marker was changed during rollback: %q", got)
	}
	if existsNoErr(root, BinaryPath) || existsNoErr(root, aptPeriodicPath) {
		t.Fatal("failed install left managed files")
	}
}

func TestDNFOriginalBaselineSurvivesNormalUninstallAndReinstall(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=42\nPRETTY_NAME='Fedora Linux 42'\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendor {
		t.Fatalf("initial DNF baseline = %q", got)
	}
	uninstall := func(purge bool) error {
		_, err := uninstaller.Uninstall(uninstaller.Options{
			RootDir: root.Root, PurgeConfig: purge, EffectiveUID: func() int { return 0 },
			RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
		})
		return err
	}
	if err := uninstall(false); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendor {
		t.Fatalf("reinstall replaced DNF baseline = %q", got)
	}
	if err := uninstall(true); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("purge restored DNF config = %q, want vendor baseline", got)
	}
}

func TestDNFLegacyTimestampBackupsMigrateToStableOriginalBaseline(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=42\n")
	write(t, root, dnfAutomaticPath, "managed-current", 0o644)
	write(t, root, dnfStableBackupPath+".20260725000000", "vendor-original", 0o644)
	write(t, root, dnfStableBackupPath+".20260726000000", "managed-previous", 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != "vendor-original" {
		t.Fatalf("migrated DNF baseline = %q, want first project backup", got)
	}
}

func TestDNFLegacyMigrationIgnoresUnknownBackupSuffix(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=42\n")
	write(t, root, dnfAutomaticPath, "vendor-original", 0o644)
	unknown := dnfStableBackupPath + ".not-a-timestamp"
	write(t, root, unknown, "unrelated", 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != "vendor-original" {
		t.Fatalf("stable DNF baseline = %q, want vendor original", got)
	}
	if got := readFile(t, root, unknown); got != "unrelated" {
		t.Fatalf("unknown DNF backup was changed: %q", got)
	}
}

func TestFeishuCredentialEncryptionAndDisable(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=ubuntu\nVERSION_ID=24.04\n")
	runner.systemdCreds = true
	options := Options{
		Config: map[string]string{
			"NOTIFY_CHANNELS": "feishu", "FEISHU_APP_ID": "cli_test",
			"FEISHU_RECEIVE_ID": "ou_test", "NOTIFY_LANG": "zh",
		},
		Payload:              Payload{Runtime: []byte("new-runtime")},
		FeishuSecret:         []byte("fresh-secret"),
		SkipPostInstallCheck: true,
	}
	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialStorage != "encrypted" {
		t.Fatalf("storage=%q", result.CredentialStorage)
	}
	if got := readFile(t, root, FeishuEncryptedCredPath); got != "encrypted:fresh-secret" {
		t.Fatalf("encrypted credential=%q", got)
	}
	if existsNoErr(root, FeishuPlainCredentialPath) {
		t.Fatal("plaintext credential remained after encryption")
	}
	if !strings.Contains(readFile(t, root, FeishuCredentialDropIn), "LoadCredentialEncrypted=") {
		t.Fatal("encrypted credential drop-in missing")
	}

	runner.systemdCreds = false
	disable := telegramOptions()
	disable.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), disable); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{FeishuEncryptedCredPath, FeishuPlainCredentialPath, FeishuCredentialDropIn} {
		if existsNoErr(root, name) {
			t.Errorf("disabled Feishu left %s", name)
		}
	}
}

func TestTransactionPreflightSelectsFeishuRecipient(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	oldValues := cloneConfig(configDefaults)
	oldValues["NOTIFY_CHANNELS"] = "feishu"
	oldValues["FEISHU_APP_ID"] = "cli_old"
	oldValues["FEISHU_RECEIVE_ID"] = "ou_old"
	oldValues["BACKEND"] = "apt"
	writeConfig(t, root, oldValues)
	write(t, root, BinaryPath, "old-runtime", 0o755)
	write(t, root, ServicePath, "old-service", 0o644)
	write(t, root, TimerPath, renderTimer("09:00"), 0o644)
	write(t, root, FeishuPlainCredentialPath, "existing-secret", 0o600)
	if err := root.MkdirAll(path.Dir(PersistentTimerLink), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("../security-update-notify.timer", PersistentTimerLink); err != nil {
		t.Fatal(err)
	}
	runner.timerActive = true
	hookCalled := false
	options := Options{
		Config: map[string]string{
			"FEISHU_APP_ID": "cli_new",
		},
		Payload:              Payload{Runtime: []byte("new-runtime")},
		FeishuSecret:         []byte("new-secret"),
		SkipPostInstallCheck: true,
		Preflight: func(_ context.Context, prepared *Prepared) error {
			hookCalled = true
			if prepared.Config["FEISHU_RECEIVE_ID"] != "" {
				return fmt.Errorf("old app-scoped open_id was reused: %q", prepared.Config["FEISHU_RECEIVE_ID"])
			}
			if commandIndex(runner.commands, "systemctl disable --now security-update-notify.timer") < 0 {
				return errors.New("directory hook ran before the old timer was quiesced")
			}
			if commandIndex(runner.commands, "dpkg -s ca-certificates") < 0 {
				return errors.New("directory hook ran before dependency checks")
			}
			prepared.Config["FEISHU_RECEIVE_ID"] = "ou_selected"
			return nil
		},
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if !hookCalled {
		t.Fatal("transaction preflight was not called")
	}
	configData := readFile(t, root, ConfigPath)
	if !strings.Contains(configData, "FEISHU_APP_ID='cli_new'") || !strings.Contains(configData, "FEISHU_RECEIVE_ID='ou_selected'") {
		t.Fatalf("selected recipient was not committed:\n%s", configData)
	}
}

func TestTransactionPreflightMustSelectRecipientAndRollsBack(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	options := Options{
		Config: map[string]string{
			"NOTIFY_CHANNELS": "feishu", "FEISHU_APP_ID": "cli_new",
		},
		Payload:      Payload{Runtime: []byte("new-runtime")},
		FeishuSecret: []byte("new-secret"),
		Preflight: func(_ context.Context, _ *Prepared) error {
			return nil
		},
	}
	_, err := installer.Install(context.Background(), options)
	if ExitCode(err) != 2 || !strings.Contains(err.Error(), "recipient") {
		t.Fatalf("missing recipient exit=%d err=%v", ExitCode(err), err)
	}
	for _, name := range []string{BinaryPath, ConfigPath, TimerPath, PersistentTimerLink} {
		if existsNoErr(root, name) {
			t.Errorf("failed directory selection left %s", name)
		}
	}
}

func TestTransactionPreflightCanReplaceFeishuSecret(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	options := Options{
		Config: map[string]string{
			"NOTIFY_CHANNELS": "feishu", "FEISHU_APP_ID": "cli_new",
			"FEISHU_RECEIVE_ID": "ou_selected",
		},
		Payload:              Payload{Runtime: []byte("new-runtime")},
		FeishuSecret:         []byte("rejected-secret"),
		SkipPostInstallCheck: true,
		Preflight: func(_ context.Context, prepared *Prepared) error {
			prepared.FeishuSecret = []byte("corrected-secret")
			return nil
		},
	}
	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialStorage != "plain" {
		t.Fatalf("storage=%q", result.CredentialStorage)
	}
	if got := readFile(t, root, FeishuPlainCredentialPath); got != "corrected-secret" {
		t.Fatalf("preflight secret replacement was not committed: %q", got)
	}
}

func TestRootValidationAndInstallerLockExitCodes(t *testing.T) {
	installer, root, _, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	nonRoot, err := New(Dependencies{
		FS: root, Runner: installer.runner, Locker: locker, EffectiveUID: func() int { return 1000 },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nonRoot.Install(context.Background(), telegramOptions()); ExitCode(err) != 1 {
		t.Fatalf("non-root exit=%d err=%v", ExitCode(err), err)
	}
	bad := telegramOptions()
	bad.Config["TELEGRAM_BOT_TOKEN"] = "bad"
	if _, err := installer.Install(context.Background(), bad); ExitCode(err) != 2 {
		t.Fatalf("validation exit=%d err=%v", ExitCode(err), err)
	}
	if existsNoErr(root, BackupRoot) {
		t.Fatal("validation failure created a backup transaction")
	}
	locker.busyPath = InstallLockPath
	if _, err := installer.Install(context.Background(), telegramOptions()); ExitCode(err) != 75 {
		t.Fatalf("busy installer exit=%d err=%v", ExitCode(err), err)
	}
}

func TestCredentialSymlinkRejectedBeforeBackup(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	if err := root.MkdirAll(path.Dir(FeishuPlainCredentialPath), 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/tmp-secret", "secret", 0o600)
	if err := root.Symlink("/tmp-secret", FeishuPlainCredentialPath); err != nil {
		t.Fatal(err)
	}
	_, err := installer.Install(context.Background(), telegramOptions())
	if err == nil || !strings.Contains(err.Error(), "not a symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	if existsNoErr(root, BackupRoot) {
		t.Fatal("credential validation failure created backup")
	}
}

func TestSafeSecretFileReaders(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, "/token", "123456:abc_DEF-ghi\n", 0o644)
	token, err := installer.ReadTelegramTokenFile("/token")
	if err != nil || token != "123456:abc_DEF-ghi" {
		t.Fatalf("token=%q err=%v", token, err)
	}
	write(t, root, "/bad-token", "first\nsecond\n", 0o600)
	if _, err := installer.ReadTelegramTokenFile("/bad-token"); ExitCode(err) != 2 {
		t.Fatalf("multiline token accepted: %v", err)
	}
	write(t, root, "/secret", "app-secret\r\n", 0o600)
	secret, err := installer.ReadFeishuSecretFile("/secret")
	if err != nil || string(secret) != "app-secret" {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
	write(t, root, "/wide-secret", "app-secret", 0o640)
	if _, err := installer.ReadFeishuSecretFile("/wide-secret"); ExitCode(err) != 2 {
		t.Fatalf("group-readable secret accepted: %v", err)
	}
	if err := root.Symlink("token", "/token-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.ReadTelegramTokenFile("/token-link"); ExitCode(err) != 2 {
		t.Fatalf("symlink token accepted: %v", err)
	}
}

func TestSetINI(t *testing.T) {
	input := []byte("[commands]\napply_updates = no\n\n[base]\n")
	got := setINI(input, "commands", "apply_updates", "yes")
	got = setINI(got, "emitters", "emit_via", "stdio")
	text := string(got)
	if strings.Count(text, "apply_updates = yes") != 1 || strings.Contains(text, "apply_updates = no") {
		t.Fatalf("existing setting not replaced:\n%s", text)
	}
	if !strings.Contains(text, "[emitters]\nemit_via = stdio\n") {
		t.Fatalf("missing section not appended:\n%s", text)
	}
}

func TestFileLockerRejectsSymlink(t *testing.T) {
	root, err := NewRootFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := root.MkdirAll("/run", 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/target", "x", 0o600)
	if err := root.Symlink("../target", InstallLockPath); err != nil {
		t.Fatal(err)
	}
	locker := FileLocker{FS: root}
	if unlock, err := locker.Acquire(context.Background(), InstallLockPath, 0); err == nil {
		_ = unlock()
		t.Fatal("symlink lock path was accepted")
	}
}

func writeConfig(t *testing.T, root *RootFS, values map[string]string) {
	t.Helper()
	if err := root.MkdirAll(path.Dir(ConfigPath), 0o750); err != nil {
		t.Fatal(err)
	}
	var buffer bytes.Buffer
	if err := configpkg.Write(&buffer, values); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFileAtomic(ConfigPath, buffer.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, root *RootFS, name, data string, mode fs.FileMode) {
	t.Helper()
	if err := root.MkdirAll(path.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFileAtomic(name, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, root *RootFS, name string) string {
	t.Helper()
	data, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func assertMode(t *testing.T, root *RootFS, name string, want fs.FileMode) {
	t.Helper()
	info, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Errorf("%s mode=%04o want %04o", name, got, want)
	}
}

func assertCommandOrder(t *testing.T, commands []string, ordered ...string) {
	t.Helper()
	position := -1
	for _, want := range ordered {
		found := -1
		for index := position + 1; index < len(commands); index++ {
			if commands[index] == want {
				found = index
				break
			}
		}
		if found < 0 {
			t.Fatalf("command %q missing after position %d:\n%s", want, position, strings.Join(commands, "\n"))
		}
		position = found
	}
}

func commandIndex(commands []string, want string) int {
	for index, command := range commands {
		if command == want {
			return index
		}
	}
	return -1
}

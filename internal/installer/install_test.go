package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	configpkg "github.com/xxvcc/security-update-notify/internal/config"
)

type fakeLocker struct {
	mu       sync.Mutex
	busyPath string
	calls    []string
	waits    []time.Duration
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
	missingCommands         map[string]bool
	systemdCreds            bool
	timerActive             bool
	failListTimers          bool
	createAPTDefaultInstall bool
	doctorResult            CommandResult
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
	case "dpkg", "rpm":
		if len(command.Args) >= 2 && r.missingPackages[command.Args[1]] {
			result.Code = 1
		}
		return result
	case "apt-get", "dnf", "yum":
		if len(command.Args) > 0 && command.Args[0] == "install" {
			for _, pkg := range command.Args[2:] {
				delete(r.missingPackages, pkg)
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
	runner := &fakeRunner{fs: root, missingPackages: map[string]bool{}, missingCommands: map[string]bool{}}
	locker := &fakeLocker{}
	installer, err := New(Dependencies{
		FS: root, Runner: runner, Locker: locker, EffectiveUID: func() int { return 0 },
		Now: func() time.Time { return time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC) },
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
		if strings.HasPrefix(command, "apt-get ") || strings.HasPrefix(command, "dnf ") || strings.HasPrefix(command, "yum ") {
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

package installer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	configpkg "github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/osrel"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/uninstaller"
)

type fakeLocker struct {
	mu           sync.Mutex
	busyPath     string
	calls        []string
	waits        []time.Duration
	held         map[string]bool
	unlocks      []string
	unlockErrors map[string]error
}

type failMarkerBackupFS struct {
	FileSystem
	enabled bool
}

type failAtomicWriteFS struct {
	FileSystem
	path string
	err  error
}

type failDependencyCaptureFS struct {
	FileSystem
	source string
	err    error
}

type failRemoveFS struct {
	FileSystem
	path string
	err  error
}

type failBackupCleanupFS struct {
	FileSystem
	source    string
	copyErr   error
	removeErr error
}

type replaceLockPathFS struct {
	FileSystem
	afterOpen func() error
}

func (f *failAtomicWriteFS) WriteFileAtomic(name string, data []byte, perm fs.FileMode) error {
	if name == f.path {
		return f.err
	}
	return f.FileSystem.WriteFileAtomic(name, data, perm)
}

func (f *failDependencyCaptureFS) CopyTrustedRegularFileAtomic(source, destination string, maxBytes int64, ownerUID uint32) error {
	if source == f.source && strings.HasPrefix(destination, BackupRoot+"/") {
		return f.err
	}
	return f.FileSystem.CopyTrustedRegularFileAtomic(source, destination, maxBytes, ownerUID)
}

func (f *failMarkerBackupFS) CopyTrustedRegularFileAtomic(source, destination string, maxBytes int64, ownerUID uint32) error {
	if f.enabled && source == aptAbsentMarkerPath && strings.HasPrefix(destination, BackupRoot+"/") {
		return errors.New("forced marker backup failure")
	}
	return f.FileSystem.CopyTrustedRegularFileAtomic(source, destination, maxBytes, ownerUID)
}

func (f *failRemoveFS) Remove(name string) error {
	if name == f.path {
		return f.err
	}
	return f.FileSystem.Remove(name)
}

func (f *failBackupCleanupFS) CopyTrustedRegularFileAtomic(source, destination string, maxBytes int64, ownerUID uint32) error {
	if source == f.source && strings.HasPrefix(destination, BackupRoot+"/") {
		return f.copyErr
	}
	return f.FileSystem.CopyTrustedRegularFileAtomic(source, destination, maxBytes, ownerUID)
}

func (f *failBackupCleanupFS) RemoveAll(name string) error {
	if strings.HasPrefix(name, BackupRoot+"/") {
		return f.removeErr
	}
	return f.FileSystem.RemoveAll(name)
}

func (f *replaceLockPathFS) OpenFileNoFollow(name string, flag int, mode fs.FileMode) (*os.File, error) {
	file, err := f.FileSystem.OpenFileNoFollow(name, flag, mode)
	if err != nil || f.afterOpen == nil {
		return file, err
	}
	followErr := f.afterOpen()
	f.afterOpen = nil
	if followErr != nil {
		_ = file.Close()
		return nil, followErr
	}
	return file, nil
}

func (l *fakeLocker) Acquire(_ context.Context, lockPath string, wait time.Duration) (UnlockFunc, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, lockPath)
	l.waits = append(l.waits, wait)
	if lockPath == l.busyPath {
		return nil, ErrLockBusy
	}
	if l.held == nil {
		l.held = make(map[string]bool)
	}
	if l.held[lockPath] {
		return nil, ErrLockBusy
	}
	l.held[lockPath] = true
	return func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.held[lockPath] {
			return errors.New("fake lock released more than once")
		}
		delete(l.held, lockPath)
		l.unlocks = append(l.unlocks, lockPath)
		return l.unlockErrors[lockPath]
	}, nil
}

func (l *fakeLocker) isHeld(lockPath string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held[lockPath]
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
	invocations             []Command
	runtimeLockHeld         []bool
	locker                  *fakeLocker
	missingPackages         map[string]bool
	dpkgStatuses            map[string]string
	missingCommands         map[string]bool
	systemdCreds            bool
	systemdDecryptHook      func(Command) CommandResult
	timerActive             bool
	enabledUnits            map[string]bool
	unitEnablements         map[string]string
	activeUnits             map[string]bool
	failListTimers          bool
	createAPTDefaultInstall bool
	dependencyInstallHook   func(Command) CommandResult
	aptMarkerBeforeWrite    bool
	aptWriteObserved        bool
	doctorResult            CommandResult
	testResult              CommandResult
	failedCommands          map[string]CommandResult
	lookPathHook            func(string) bool
}

func (r *fakeRunner) LookPath(name string) bool {
	if r.lookPathHook != nil {
		return r.lookPathHook(name)
	}
	if name == "systemd-creds" {
		return r.systemdCreds
	}
	return !r.missingCommands[name]
}

func (r *fakeRunner) Run(_ context.Context, command Command) CommandResult {
	commandLine := command.Name + " " + strings.Join(command.Args, " ")
	invocation := command
	invocation.Args = append([]string(nil), command.Args...)
	invocation.Stdin = append([]byte(nil), command.Stdin...)
	invocation.Env = cloneConfig(command.Env)
	runtimeHeld := r.locker != nil && r.locker.isHeld(RuntimeLockPath)
	r.mu.Lock()
	r.commands = append(r.commands, commandLine)
	r.invocations = append(r.invocations, invocation)
	r.runtimeLockHeld = append(r.runtimeLockHeld, runtimeHeld)
	r.mu.Unlock()
	if result, failed := r.failedCommands[commandLine]; failed {
		delete(r.failedCommands, commandLine)
		return result
	}
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
	case "apt-get", "dnf", "dnf5", "microdnf", "yum":
		if len(command.Args) > 0 && command.Args[0] == "--version" {
			if command.Name == "dnf5" {
				result.Stdout = []byte("dnf5 version 5.2.0\n")
			} else if command.Name == "dnf" || command.Name == "yum" {
				result.Stdout = []byte("4.14.0\n")
			}
			return result
		}
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
				if pkg == "dnf" || pkg == "dnf-automatic" || pkg == "dnf5-plugin-automatic" {
					delete(r.missingCommands, "dnf")
				}
			}
			if r.createAPTDefaultInstall {
				_ = r.fs.MkdirAll("/etc/apt/apt.conf.d", 0o755)
				_ = r.fs.WriteFileAtomic("/etc/apt/apt.conf.d/20auto-upgrades", []byte("dependency-default\n"), 0o644)
			}
			if r.dependencyInstallHook != nil {
				return r.dependencyInstallHook(command)
			}
		}
		return result
	case "systemd-creds":
		if len(command.Args) > 0 && command.Args[0] == "encrypt" {
			result.Stdout = append([]byte("encrypted:"), command.Stdin...)
		}
		if len(command.Args) > 0 && command.Args[0] == "decrypt" {
			if r.systemdDecryptHook != nil {
				return r.systemdDecryptHook(command)
			}
			result.Stdout = []byte("existing-secret")
		}
		return result
	case "env":
		if len(command.Args) == 2 && command.Args[0] == "/proc/self/fd/3" && command.Args[1] == "--version" {
			if len(command.ExtraFiles) != 1 {
				return CommandResult{Err: fmt.Errorf("version extra files = %d", len(command.ExtraFiles))}
			}
			data := make([]byte, len("old-runtime"))
			n, _ := command.ExtraFiles[0].ReadAt(data, 0)
			version := "3.0.0"
			if bytes.Equal(data[:n], []byte("old-runtime")) {
				version = "2.3.0"
			}
			return CommandResult{Stdout: []byte("security-update-notify " + version + "\n")}
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
		unit := args[len(args)-1]
		state := r.unitEnablement(unit)
		result.Stdout = []byte(state + "\n")
		result.Code = fakeIsEnabledCode(state)
	case "is-active":
		unit := args[len(args)-1]
		active := r.activeUnits[unit]
		if unit == "security-update-notify.timer" {
			active = r.timerActive
		}
		if active {
			result.Stdout = []byte("active\n")
		} else {
			result.Stdout, result.Code = []byte("inactive\n"), 3
		}
	case "disable":
		for _, arg := range args[1:] {
			if !strings.HasSuffix(arg, ".timer") && !strings.HasSuffix(arg, ".service") {
				continue
			}
			state := r.unitEnablement(arg)
			if arg != "security-update-notify.timer" && !fakeReadOnlyEnablement(state) && !isMaskedEnablement(state) {
				r.setUnitEnablement(arg, "disabled")
			}
			if slicesContain(args, "--now") {
				delete(r.activeUnits, arg)
			}
			if arg == "security-update-notify.timer" {
				_ = r.fs.Remove(PersistentTimerLink)
				_ = r.fs.Remove(RuntimeTimerLink)
				if slicesContain(args, "--now") {
					r.timerActive = false
				}
			}
		}
	case "enable":
		project := false
		startNow := slicesContain(args, "--now")
		runtime := slicesContain(args, "--runtime")
		for _, arg := range args {
			project = project || arg == "security-update-notify.timer"
			if strings.HasSuffix(arg, ".timer") || strings.HasSuffix(arg, ".service") {
				state := r.unitEnablement(arg)
				if isMaskedEnablement(state) {
					return CommandResult{Code: 1, Stderr: []byte("unit is masked\n")}
				}
				if arg != "security-update-notify.timer" && !fakeReadOnlyEnablement(state) {
					next := "enabled"
					if runtime {
						next = "enabled-runtime"
					}
					r.setUnitEnablement(arg, next)
				}
				if startNow {
					r.activeUnits[arg] = true
				}
			}
		}
		if project {
			_ = r.fs.MkdirAll(path.Dir(PersistentTimerLink), 0o755)
			_ = r.fs.Remove(PersistentTimerLink)
			_ = r.fs.Symlink("../security-update-notify.timer", PersistentTimerLink)
			r.timerActive = startNow
		}
	case "start":
		unit := args[len(args)-1]
		if isMaskedEnablement(r.unitEnablement(unit)) {
			return CommandResult{Code: 1, Stderr: []byte("unit is masked\n")}
		}
		r.activeUnits[unit] = true
		if unit == "security-update-notify.timer" {
			r.timerActive = true
		}
	case "stop":
		unit := args[len(args)-1]
		delete(r.activeUnits, unit)
		if unit == "security-update-notify.timer" {
			r.timerActive = false
		}
	case "unmask":
		unit := args[len(args)-1]
		state := r.unitEnablement(unit)
		runtime := slicesContain(args, "--runtime")
		if (state == "masked" && !runtime) || (state == "masked-runtime" && runtime) {
			r.setUnitEnablement(unit, "disabled")
		}
	case "mask":
		unit := args[len(args)-1]
		state := "masked"
		if slicesContain(args, "--runtime") {
			state = "masked-runtime"
		}
		r.setUnitEnablement(unit, state)
	case "list-timers":
		if r.failListTimers {
			result.Code, result.Stderr = 1, []byte("forced list-timers failure")
		}
	}
	return result
}

func (r *fakeRunner) unitEnablement(unit string) string {
	if state := r.unitEnablements[unit]; state != "" {
		return state
	}
	if r.enabledUnits[unit] {
		return "enabled"
	}
	if unit != "security-update-notify.timer" {
		return "disabled"
	}
	if existsNoErr(r.fs, PersistentTimerLink) {
		return "enabled"
	}
	if existsNoErr(r.fs, RuntimeTimerLink) {
		return "enabled-runtime"
	}
	if existsNoErr(r.fs, TimerPath) {
		return "disabled"
	}
	return "not-found"
}

func (r *fakeRunner) setUnitEnablement(unit, state string) {
	r.unitEnablements[unit] = state
	if state == "enabled" || state == "enabled-runtime" {
		r.enabledUnits[unit] = true
	} else {
		delete(r.enabledUnits, unit)
	}
}

func fakeIsEnabledCode(state string) int {
	switch state {
	case "enabled", "enabled-runtime", "static", "alias", "indirect", "generated", "transient":
		return 0
	default:
		return 1
	}
}

func fakeReadOnlyEnablement(state string) bool {
	switch state {
	case "static", "alias", "indirect", "generated", "transient":
		return true
	default:
		return false
	}
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
		fs: root, missingPackages: map[string]bool{}, dpkgStatuses: map[string]string{}, missingCommands: map[string]bool{"dnf5": true}, enabledUnits: map[string]bool{}, unitEnablements: map[string]string{}, activeUnits: map[string]bool{}, failedCommands: map[string]CommandResult{},
	}
	locker := &fakeLocker{}
	runner.locker = locker
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
	if err := root.Chmod("/var/log", 0o775); err != nil {
		t.Fatal(err)
	}
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
	assertMode(t, root, "/var/log", 0o775)
	assertMode(t, root, LogPath, 0o640)
	logInfo, err := root.Lstat(LogPath)
	if err != nil {
		t.Fatal(err)
	}
	logStat, ok := logInfo.Sys().(*syscall.Stat_t)
	if !ok || logStat == nil || logStat.Uid != uint32(os.Geteuid()) || logStat.Nlink != 1 {
		t.Fatalf("installed log metadata = %#v, want owner %d and one link", logStat, os.Geteuid())
	}
	if got := readFile(t, root, "/etc/apt/apt.conf.d/20auto-upgrades"); got != aptPeriodicConfig {
		t.Errorf("apt periodic config drifted:\n%s", got)
	}
	if !existsNoErr(root, PersistentTimerLink) || !runner.timerActive {
		t.Fatal("project timer was not enabled and started")
	}
	if !reflect.DeepEqual(locker.calls, []string{InstallLockPath, RuntimeLockPath}) {
		t.Fatalf("fresh install lock sequence = %v", locker.calls)
	}
	if locker.isHeld(InstallLockPath) || locker.isHeld(RuntimeLockPath) {
		t.Fatal("successful install leaked a transaction lock")
	}
	if result.BackupDir == "" || !existsNoErr(root, result.BackupDir+"/manifest") {
		t.Fatalf("backup was not created: %+v", result)
	}
}

func TestInstallSupportsFedoraStandardLocalSbinAlias(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\nPRETTY_NAME='Fedora Linux 43'\n")
	hostSbin := filepath.Join(root.Root, "usr/local/sbin")
	if err := os.Remove(hostSbin); err != nil {
		t.Fatal(err)
	}
	if err := root.MkdirAll("/usr/local/bin", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("bin", "/usr/local/sbin"); err != nil {
		t.Fatal(err)
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, BinaryPath); got != "new-runtime" {
		t.Fatalf("runtime through standard alias = %q", got)
	}
	if target, err := root.Readlink("/usr/local/sbin"); err != nil || target != "bin" {
		t.Fatalf("standard alias changed: target=%q err=%v", target, err)
	}
	if _, err := root.Lstat("/usr/local/bin/security-update-notify"); err != nil {
		t.Fatalf("physical runtime target missing: %v", err)
	}
}

func TestManagedDirectoryMustBeRootOwnedBeforePermissionsChange(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	const directory = "/etc/security-update-notify"
	if err := root.MkdirAll(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	installer.rootOwnerUID = uint32(os.Geteuid() + 1)

	err := installer.ensureManagedDir(directory, 0o750)
	if err == nil || !strings.Contains(err.Error(), "must be owned by root") {
		t.Fatalf("non-root-owned managed directory error = %v", err)
	}
	info, statErr := root.Lstat(directory)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o777 {
		t.Fatalf("mode changed before owner validation: %04o", got)
	}
}

func TestNewManagedDirectoryOwnerIsVerified(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	installer.rootOwnerUID = uint32(os.Geteuid() + 1)

	err := installer.ensureManagedDir("/var/lib/security-update-notify", 0o750)
	if err == nil || !strings.Contains(err.Error(), "must be owned by root") {
		t.Fatalf("new managed directory owner error = %v", err)
	}
	if _, statErr := root.Lstat("/var/lib/security-update-notify"); statErr != nil {
		t.Fatalf("directory was not created before post-create validation: %v", statErr)
	}
}

func TestPrivilegedDirectoriesRejectUnsafePermissionsBeforeChmod(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	for _, test := range []struct {
		name      string
		directory string
		managed   bool
		sharedLog bool
	}{
		{name: "managed service drop-in", directory: "/etc/systemd/system/security-update-notify.service.d", managed: true},
		{name: "shared install parent", directory: "/var/log", sharedLog: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := root.MkdirAll(test.directory, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := root.Chmod(test.directory, 0o777); err != nil {
				t.Fatal(err)
			}
			planted := path.Join(test.directory, "attacker.conf")
			write(t, root, planted, "untrusted", 0o644)

			var err error
			if test.managed {
				err = installer.ensureManagedDir(test.directory, 0o755)
			} else if test.sharedLog {
				err = installer.ensureSharedLogDir()
			} else {
				err = installer.ensureDir(test.directory, 0o755)
			}
			if err == nil || !strings.Contains(err.Error(), "must not be writable by other users") &&
				!strings.Contains(err.Error(), "must not be writable by group or other users") {
				t.Fatalf("unsafe directory error = %v", err)
			}
			info, statErr := root.Lstat(test.directory)
			if statErr != nil {
				t.Fatal(statErr)
			}
			if info.Mode().Perm() != 0o777 || readFile(t, root, planted) != "untrusted" {
				t.Fatal("unsafe directory was modified before trust validation")
			}
		})
	}
}

func TestSharedLogDirectoryAllowsOnlyGroupWrite(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=ubuntu\nVERSION_ID=24.04\n")
	if err := root.Chmod("/var/log", 0o775); err != nil {
		t.Fatal(err)
	}
	write(t, root, "/var/log/existing.log", "existing", 0o640)
	if err := installer.ensureSharedLogDir(); err != nil {
		t.Fatal(err)
	}
	info, err := root.Lstat("/var/log")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o775 {
		t.Fatalf("shared log directory mode changed to %04o", info.Mode().Perm())
	}
	if readFile(t, root, "/var/log/existing.log") != "existing" {
		t.Fatal("shared log directory contents changed during validation")
	}
	installer.rootOwnerUID = uint32(os.Geteuid() + 1)
	if err := installer.ensureSharedLogDir(); err == nil || !strings.Contains(err.Error(), "must be owned by root") {
		t.Fatalf("wrong-owner shared log directory error = %v", err)
	}
	installer.rootOwnerUID = uint32(os.Geteuid())
	if err := installer.ensureDir("/etc/systemd/system", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := root.Chmod("/etc/systemd/system", 0o775); err != nil {
		t.Fatal(err)
	}
	if err := installer.ensureDir("/etc/systemd/system", 0o755); err == nil {
		t.Fatal("group-writable non-log privileged directory was accepted")
	}
}

func TestSharedLogDirectoryRejectsSymlinkAndNonDirectory(t *testing.T) {
	for _, test := range []struct {
		name  string
		plant func(*testing.T, *RootFS)
	}{
		{
			name: "symlink",
			plant: func(t *testing.T, root *RootFS) {
				if err := root.Symlink("/tmp", "/var/log"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "regular file",
			plant: func(t *testing.T, root *RootFS) {
				write(t, root, "/var/log", "not a directory", 0o644)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=ubuntu\nVERSION_ID=24.04\n")
			if err := os.Remove(filepath.Join(root.Root, "var/log")); err != nil {
				t.Fatal(err)
			}
			test.plant(t, root)
			if err := installer.ensureSharedLogDir(); err == nil {
				t.Fatalf("shared log policy accepted %s", test.name)
			}
		})
	}
}

func TestSystemdRuntimeDirectoryMustBeTrusted(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Installer, *RootFS) error
	}{
		{
			name: "group-writable",
			mutate: func(_ *Installer, root *RootFS) error {
				return root.Chmod("/run/systemd/system", 0o777)
			},
		},
		{
			name: "wrong-owner",
			mutate: func(installer *Installer, _ *RootFS) error {
				installer.rootOwnerUID = uint32(os.Geteuid() + 1)
				return nil
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			if err := test.mutate(installer, root); err != nil {
				t.Fatal(err)
			}
			if err := installer.requireSystemd(); err == nil {
				t.Fatal("unsafe systemd runtime directory was accepted")
			}
			if _, err := root.Lstat(BackupRoot); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("systemd trust failure created installation state: %v", err)
			}
		})
	}
}

func TestPostInstallDoctorFailureIsAdvisoryAndReturned(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
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
	assertRuntimeInvocationLock(t, runner, "--doctor")
	assertIndependentRuntimeLock(t, runner, "--doctor")
	if locker.isHeld(RuntimeLockPath) {
		t.Fatal("successful install leaked the runtime lock")
	}
}

func TestInferredDerivativeDoctorFailureRollsBack(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=custom-apt\nVERSION_ID=1\nID_LIKE=debian\nPRETTY_NAME='Custom apt derivative'\n")
	runner.doctorResult = CommandResult{Code: 1, Stderr: []byte("repository gate failed\n")}
	options := telegramOptions()
	options.AllowBestEffort = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "verify inferred derivative with doctor") {
		t.Fatalf("inferred derivative doctor error=%v", err)
	}
	if existsNoErr(root, BinaryPath) || runner.timerActive {
		t.Fatal("inferred derivative survived a failed mandatory doctor gate")
	}
	if !reflect.DeepEqual(locker.calls, []string{InstallLockPath, RuntimeLockPath}) {
		t.Fatalf("rollback reacquired or skipped a transaction lock: %v", locker.calls)
	}
	assertRuntimeInvocationLock(t, runner, "--doctor")
	assertRuntimeInvocationLock(t, runner, "disable")
	if locker.isHeld(RuntimeLockPath) {
		t.Fatal("failed install leaked the runtime lock")
	}
}

func TestContendedRuntimeLockAbortsBeforeBackupOrMutation(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	locker.busyPath = RuntimeLockPath
	options := telegramOptions()

	_, err := installer.Install(context.Background(), options)
	if ExitCode(err) != 75 || !strings.Contains(err.Error(), "timed out waiting") {
		t.Fatalf("runtime contention exit=%d error=%v", ExitCode(err), err)
	}
	if existsNoErr(root, BackupRoot) || existsNoErr(root, BinaryPath) || runner.timerActive {
		t.Fatal("runtime contention crossed the transaction mutation boundary")
	}
	if !reflect.DeepEqual(locker.calls, []string{InstallLockPath, RuntimeLockPath}) {
		t.Fatalf("runtime contention lock sequence = %v", locker.calls)
	}
}

func TestInstallJoinsPrimaryAndBothUnlockErrors(t *testing.T) {
	installer, _, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	primaryErr := errors.New("forced daemon reload failure")
	runtimeUnlockErr := errors.New("forced runtime unlock failure")
	installUnlockErr := errors.New("forced installer unlock failure")
	runner.failedCommands["systemctl daemon-reload"] = CommandResult{Err: primaryErr}
	locker.unlockErrors = map[string]error{
		RuntimeLockPath: runtimeUnlockErr,
		InstallLockPath: installUnlockErr,
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	for _, want := range []error{primaryErr, runtimeUnlockErr, installUnlockErr} {
		if !errors.Is(err, want) {
			t.Fatalf("Install() error %v does not include %v", err, want)
		}
	}
	if !reflect.DeepEqual(locker.unlocks, []string{RuntimeLockPath, InstallLockPath}) {
		t.Fatalf("unlock order = %v", locker.unlocks)
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
	assertRuntimeInvocationLock(t, runner, "--test-ok")
	assertIndependentRuntimeLock(t, runner, "--test-ok")
}

func TestUpgradeNotificationUsesIndependentLock(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
	values := cloneConfig(configDefaults)
	values["NOTIFY_CHANNELS"] = "telegram"
	values["TELEGRAM_BOT_TOKEN"] = "123456:old_token"
	values["TELEGRAM_CHAT_ID"] = "-100"
	values["NOTIFY_UPGRADE"] = "1"
	values["BACKEND"] = "apt"
	writeConfig(t, root, values)
	write(t, root, BinaryPath, "old-runtime", 0o755)

	result, err := installer.Install(context.Background(), telegramOptions())
	if err != nil {
		t.Fatal(err)
	}
	if result.PreviousVersion != "2.3.0" {
		t.Fatalf("PreviousVersion = %q, want descriptor-bound old version", result.PreviousVersion)
	}
	versionCalls := 0
	for index, invocation := range runner.invocations {
		if invocation.Name != "env" || !reflect.DeepEqual(invocation.Args, []string{"/proc/self/fd/3", "--version"}) {
			continue
		}
		versionCalls++
		if len(invocation.ExtraFiles) != 1 || !runner.runtimeLockHeld[index] {
			t.Fatalf("version invocation was not descriptor-bound under runtime lock: %+v", invocation)
		}
	}
	if versionCalls != 2 {
		t.Fatalf("version calls = %d, want old and new descriptor-bound probes", versionCalls)
	}
	assertRuntimeInvocationLock(t, runner, "--notify-upgrade-event")
	assertIndependentRuntimeLock(t, runner, "--notify-upgrade-event")
}

func TestCurrentInstalledVersionRejectsUnsafeRuntimeMetadata(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *RootFS)
	}{
		{name: "group writable", prepare: func(t *testing.T, root *RootFS) {
			if err := root.Chmod(BinaryPath, 0o775); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hard linked", prepare: func(t *testing.T, root *RootFS) {
			if err := os.Link(filepath.Join(root.Root, strings.TrimPrefix(BinaryPath, "/")), filepath.Join(root.Root, "runtime-alias")); err != nil {
				t.Fatal(err)
			}
		}},
	}
	if os.Geteuid() == 0 {
		tests = append(tests, struct {
			name    string
			prepare func(*testing.T, *RootFS)
		}{name: "wrong owner", prepare: func(t *testing.T, root *RootFS) {
			if err := os.Chown(filepath.Join(root.Root, strings.TrimPrefix(BinaryPath, "/")), 1, 1); err != nil {
				t.Fatal(err)
			}
		}})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, BinaryPath, "old-runtime", 0o755)
			test.prepare(t, root)

			if got := installer.currentInstalledVersion(context.Background()); got != "unknown" {
				t.Fatalf("currentInstalledVersion = %q, want unknown", got)
			}
			for _, invocation := range runner.invocations {
				if invocation.Name == "env" {
					t.Fatalf("unsafe runtime was executed: %+v", invocation)
				}
			}
		})
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

func TestInstallFallsBackToUsrLibOSReleaseOnlyWhenEtcIsMissing(t *testing.T) {
	t.Run("missing primary", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=placeholder\nVERSION_ID=0\n")
		if err := root.Remove("/etc/os-release"); err != nil {
			t.Fatal(err)
		}
		write(t, root, "/usr/lib/os-release", "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n", 0o644)
		result, err := installer.Install(context.Background(), telegramOptions())
		if err != nil {
			t.Fatal(err)
		}
		if result.Backend != "apt" || result.SupportTier != osrel.Supported {
			t.Fatalf("fallback result = %+v", result)
		}
	})

	t.Run("primary takes precedence", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
		write(t, root, "/usr/lib/os-release", "ID=fedora\nVERSION_ID=43\n", 0o644)
		result, err := installer.Install(context.Background(), telegramOptions())
		if err != nil {
			t.Fatal(err)
		}
		if result.Backend != "apt" {
			t.Fatalf("fallback overrode primary: %+v", result)
		}
	})

	t.Run("unsafe primary is not hidden", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=placeholder\nVERSION_ID=0\n")
		if err := root.Remove("/etc/os-release"); err != nil {
			t.Fatal(err)
		}
		write(t, root, "/usr/lib/os-release", "ID=debian\nVERSION_ID=13\n", 0o644)
		if err := root.Symlink(filepath.Join(t.TempDir(), "outside-os-release"), "/etc/os-release"); err != nil {
			t.Fatal(err)
		}
		if _, err := installer.Install(context.Background(), telegramOptions()); err == nil || !strings.Contains(err.Error(), "read /etc/os-release") {
			t.Fatalf("unsafe primary error=%v", err)
		}
	})

	t.Run("invalid primary identity is not replaced", func(t *testing.T) {
		installer, root, _, _ := setupInstaller(t, "ID=debian\n")
		write(t, root, "/usr/lib/os-release", "ID=fedora\nVERSION_ID=43\n", 0o644)
		if _, err := installer.Install(context.Background(), telegramOptions()); err == nil || !strings.Contains(err.Error(), "ID=debian VERSION_ID=") {
			t.Fatalf("invalid primary error=%v", err)
		}
	})
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
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\nPRETTY_NAME='Fedora Linux 43'\n")
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
	for _, setting := range []string{"upgrade_type = security", "apply_updates = yes", "reboot = never", "emit_via = stdio", "debuglevel = 1"} {
		if !strings.Contains(dnfConfig, setting) {
			t.Errorf("dnf config missing %q:\n%s", setting, dnfConfig)
		}
	}
	if !strings.Contains(readFile(t, root, ConfigPath), "BACKEND='dnf'") {
		t.Fatal("resolved dnf backend was not persisted")
	}
	if commandIndex(runner.commands, "systemctl enable --now dnf5-automatic.timer") < 0 {
		t.Fatal("dnf5-automatic.timer was not enabled")
	}
}

func TestFedoraDNF5DependenciesAndNativeTimer(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\nPRETTY_NAME='Fedora Linux 43'\n")
	for _, pkg := range []string{"dnf5-plugin-automatic", "ca-certificates", "dnf5-plugins"} {
		runner.missingPackages[pkg] = true
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		want := []string{"dnf5-plugin-automatic", "ca-certificates", "dnf5-plugins"}
		if request.Backend != "dnf" || !reflect.DeepEqual(request.Packages, want) {
			return false, fmt.Errorf("unexpected dependency request: %+v", request)
		}
		return true, nil
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"dnf install -y dnf5-plugin-automatic ca-certificates dnf5-plugins",
		"dnf automatic --help",
		"systemctl enable --now dnf5-automatic.timer",
		"systemctl is-enabled dnf5-automatic.timer",
	} {
		if commandIndex(runner.commands, want) < 0 {
			t.Errorf("missing command %q; commands:\n%s", want, strings.Join(runner.commands, "\n"))
		}
	}
	if !existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("originally absent DNF5 override did not retain an absence baseline")
	}
}

func TestEL10MinimalInstallsRuntimeDNFThroughMicrodnf(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=almalinux\nVERSION_ID=10.1\nPRETTY_NAME='AlmaLinux 10.1'\n")
	write(t, root, dnfAutomaticPath, "[commands]\n", 0o644)
	wantPackages := []string{"dnf", "dnf-automatic", "ca-certificates", "yum-utils"}
	for _, pkg := range wantPackages {
		runner.missingPackages[pkg] = true
	}
	runner.missingCommands["dnf"] = true
	runner.missingCommands["yum"] = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		if !reflect.DeepEqual(request.Packages, wantPackages) {
			return false, fmt.Errorf("unexpected dependency request: %+v", request)
		}
		return true, nil
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if want := "microdnf install -y dnf dnf-automatic ca-certificates yum-utils"; commandIndex(runner.commands, want) < 0 {
		t.Fatalf("EL10 did not bootstrap dnf through microdnf; commands:\n%s", strings.Join(runner.commands, "\n"))
	}
}

func TestAmazonLinux2023InstallsDNFUtils(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=amzn\nVERSION_ID=2023\nPRETTY_NAME='Amazon Linux 2023'\n")
	wantPackages := []string{"dnf-automatic", "ca-certificates", "dnf-utils"}
	for _, pkg := range append(append([]string(nil), wantPackages...), "yum-utils") {
		runner.missingPackages[pkg] = true
	}
	runner.dependencyInstallHook = func(Command) CommandResult {
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte("[commands]\n"), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		return CommandResult{}
	}
	options := telegramOptions()
	options.AllowBestEffort = true
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		if request.Backend != "dnf" || !reflect.DeepEqual(request.Packages, wantPackages) {
			return false, fmt.Errorf("unexpected dependency request: %+v", request)
		}
		return true, nil
	}
	result, err := installer.Install(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Backend != "dnf" || result.SupportTier != "best-effort" {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, want := range []string{
		"rpm -q dnf-utils",
		"dnf install -y dnf-automatic ca-certificates dnf-utils",
	} {
		if commandIndex(runner.commands, want) < 0 {
			t.Errorf("missing command %q; commands:\n%s", want, strings.Join(runner.commands, "\n"))
		}
	}
	if commandIndex(runner.commands, "rpm -q yum-utils") >= 0 {
		t.Fatalf("Amazon Linux probed yum-utils; commands:\n%s", strings.Join(runner.commands, "\n"))
	}
}

func TestAutomaticTimerReadinessFailureRollsBack(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.Preflight = func(context.Context, *Prepared) error {
		runner.failedCommands["systemctl is-enabled dnf5-automatic.timer"] = CommandResult{Code: 1, Stderr: []byte("disabled")}
		return nil
	}
	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "verify automatic-update timer") {
		t.Fatalf("readiness error = %v", err)
	}
	got := readFile(t, root, dnfAutomaticPath)
	if existsNoErr(root, BinaryPath) || got != vendor {
		t.Fatalf("readiness failure did not roll back: binary=%v config=%q", existsNoErr(root, BinaryPath), got)
	}
	if runner.enabledUnits["dnf5-automatic.timer"] || runner.activeUnits["dnf5-automatic.timer"] {
		t.Fatalf("DNF5 timer state survived rollback: enabled=%t active=%t", runner.enabledUnits["dnf5-automatic.timer"], runner.activeUnits["dnf5-automatic.timer"])
	}
}

func TestAutomaticTimerStaticStateFailsReadinessGateAndRollsBack(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	runner.unitEnablements["dnf5-automatic.timer"] = "static"
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), `enablement state "static"`) {
		t.Fatalf("static timer readiness error = %v", err)
	}
	if strings.Contains(err.Error(), "rollback was incomplete") {
		t.Fatalf("static timer caused incomplete rollback: %v", err)
	}
	if existsNoErr(root, BinaryPath) || readFile(t, root, dnfAutomaticPath) != vendor {
		t.Fatal("static timer readiness failure did not roll back installed files")
	}
	if got, active := runner.unitEnablement("dnf5-automatic.timer"), runner.activeUnits["dnf5-automatic.timer"]; got != "static" || active {
		t.Fatalf("static timer after rollback: enablement=%q active=%t", got, active)
	}
}

func TestAutomaticUnitUnrestorableEnablementFailsBeforeActivation(t *testing.T) {
	for _, enablement := range []string{"linked", "linked-runtime", "indirect"} {
		t.Run(enablement, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
			vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
			write(t, root, dnfAutomaticPath, vendor, 0o644)
			unit := "dnf5-automatic.timer"
			runner.unitEnablements[unit] = enablement
			options := telegramOptions()
			options.SkipPostInstallCheck = true

			_, err := installer.Install(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), "cannot be restored without changing related units") {
				t.Fatalf("enablement %q error=%v", enablement, err)
			}
			if strings.Contains(err.Error(), "rollback was incomplete") {
				t.Fatalf("enablement %q caused incomplete rollback: %v", enablement, err)
			}
			if got := runner.unitEnablement(unit); got != enablement || existsNoErr(root, BinaryPath) {
				t.Fatalf("state changed after rejection: enablement=%q binary=%t", got, existsNoErr(root, BinaryPath))
			}
			for _, command := range runner.commands {
				if strings.HasPrefix(command, "systemctl enable ") || strings.HasPrefix(command, "systemctl disable ") || strings.HasPrefix(command, "systemctl stop ") {
					t.Fatalf("unit mutation ran after rejecting %q: %s", enablement, command)
				}
			}
		})
	}
}

func TestAutomaticUnitUnrestorableActivityFailsBeforeActivation(t *testing.T) {
	for _, test := range []struct {
		activity string
		code     int
	}{
		{activity: "activating", code: 0},
		{activity: "deactivating", code: 3},
		{activity: "failed", code: 3},
		{activity: "maintenance", code: 3},
		{activity: "reloading", code: 0},
		{activity: "unknown", code: 4},
	} {
		t.Run(test.activity, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
			unit := "dnf5-automatic.timer"
			runner.failedCommands["systemctl is-active "+unit] = CommandResult{
				Stdout: []byte(test.activity + "\n"), Code: test.code,
			}
			options := telegramOptions()
			options.SkipPostInstallCheck = true

			_, err := installer.Install(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), `activity state "`+test.activity+`" cannot be restored exactly`) {
				t.Fatalf("activity %q error=%v", test.activity, err)
			}
			if strings.Contains(err.Error(), "rollback was incomplete") || existsNoErr(root, BinaryPath) {
				t.Fatalf("activity %q was not rejected cleanly: %v", test.activity, err)
			}
			for _, command := range runner.commands {
				if strings.HasPrefix(command, "systemctl enable ") || strings.HasPrefix(command, "systemctl disable ") ||
					strings.HasPrefix(command, "systemctl start ") || strings.HasPrefix(command, "systemctl stop ") {
					t.Fatalf("unit mutation ran after rejecting %q: %s", test.activity, command)
				}
			}
		})
	}
}

func TestSnapshotAutomaticUnitRejectsInconsistentSystemctlResults(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		result  CommandResult
	}{
		{
			name: "enablement stderr", command: "systemctl is-enabled dnf5-automatic.timer",
			result: CommandResult{Stdout: []byte("disabled\n"), Stderr: []byte("D-Bus failure\n"), Code: 1},
		},
		{
			name: "enablement exit mismatch", command: "systemctl is-enabled dnf5-automatic.timer",
			result: CommandResult{Stdout: []byte("enabled\n"), Code: 1},
		},
		{
			name: "activity stderr", command: "systemctl is-active dnf5-automatic.timer",
			result: CommandResult{Stdout: []byte("inactive\n"), Stderr: []byte("D-Bus failure\n"), Code: 3},
		},
		{
			name: "activity exit mismatch", command: "systemctl is-active dnf5-automatic.timer",
			result: CommandResult{Stdout: []byte("active\n"), Code: 3},
		},
		{
			name: "enablement truncated", command: "systemctl is-enabled dnf5-automatic.timer",
			result: CommandResult{Stdout: []byte("enabled\n"), StdoutTruncated: true},
		},
		{
			name: "activity truncated", command: "systemctl is-active dnf5-automatic.timer",
			result: CommandResult{Stdout: []byte("active\n"), StderrTruncated: true},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, _, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
			runner.failedCommands[test.command] = test.result
			if _, err := installer.snapshotUnit(context.Background(), "dnf5-automatic.timer"); err == nil {
				t.Fatalf("snapshot accepted inconsistent result for %s", test.command)
			}
		})
	}
}

func TestSnapshotAutomaticUnitAcceptsStructurallyConfirmedMissingUnit(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	const unit = "optional-update.timer"
	runner.failedCommands["systemctl is-enabled "+unit] = CommandResult{
		Code: 1, Stderr: []byte("Failed to get unit file state: No such file or directory\n"),
	}
	runner.failedCommands["systemctl show --property=LoadState --value "+unit] = CommandResult{
		Stdout: []byte("not-found\n"),
	}
	runner.unitEnablements[unit] = "not-found"

	snapshot, err := installer.snapshotUnit(context.Background(), unit)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.name != unit || snapshot.enablement != "not-found" || snapshot.active {
		t.Fatalf("missing unit snapshot = %+v", snapshot)
	}
}

func TestSnapshotAutomaticUnitRejectsUnconfirmedMissingDiagnostic(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	const unit = "optional-update.timer"
	runner.failedCommands["systemctl is-enabled "+unit] = CommandResult{
		Code: 1, Stderr: []byte("D-Bus permission denied\n"),
	}
	runner.failedCommands["systemctl show --property=LoadState --value "+unit] = CommandResult{
		Stdout: []byte("loaded\n"),
	}
	if _, err := installer.snapshotUnit(context.Background(), unit); err == nil {
		t.Fatal("snapshot accepted an unconfirmed missing-unit diagnostic")
	}
}

func TestSnapshotProjectTimerTreatsMissingUnitAsFreshInstall(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	snapshot, err := installer.snapshotTimer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.active || snapshot.enablement != "not-found" {
		t.Fatalf("fresh-install timer snapshot = %+v", snapshot)
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "security-update-notify.timer") {
			t.Fatalf("fresh install queried missing project timer: %s", command)
		}
	}
}

func TestSnapshotProjectTimerRejectsInconsistentSystemctlResults(t *testing.T) {
	for _, test := range []struct {
		name    string
		command string
		result  CommandResult
	}{
		{
			name: "enablement execution error", command: "systemctl is-enabled security-update-notify.timer",
			result: CommandResult{Err: errors.New("D-Bus unavailable")},
		},
		{
			name: "enablement stderr", command: "systemctl is-enabled security-update-notify.timer",
			result: CommandResult{Stdout: []byte("disabled\n"), Stderr: []byte("D-Bus warning\n"), Code: 1},
		},
		{
			name: "enablement exit mismatch", command: "systemctl is-enabled security-update-notify.timer",
			result: CommandResult{Stdout: []byte("enabled\n"), Code: 1},
		},
		{
			name: "activity execution error", command: "systemctl is-active security-update-notify.timer",
			result: CommandResult{Err: errors.New("systemctl timed out")},
		},
		{
			name: "activity stderr", command: "systemctl is-active security-update-notify.timer",
			result: CommandResult{Stdout: []byte("inactive\n"), Stderr: []byte("D-Bus warning\n"), Code: 3},
		},
		{
			name: "activity exit mismatch", command: "systemctl is-active security-update-notify.timer",
			result: CommandResult{Stdout: []byte("active\n"), Code: 3},
		},
		{
			name: "activating state", command: "systemctl is-active security-update-notify.timer",
			result: CommandResult{Stdout: []byte("activating\n")},
		},
		{
			name: "failed state", command: "systemctl is-active security-update-notify.timer",
			result: CommandResult{Stdout: []byte("failed\n"), Code: 3},
		},
		{
			name: "reloading state", command: "systemctl is-active security-update-notify.timer",
			result: CommandResult{Stdout: []byte("reloading\n")},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, TimerPath, renderTimer("09:00"), 0o644)
			runner.failedCommands[test.command] = test.result
			if _, err := installer.snapshotTimer(context.Background()); err == nil {
				t.Fatalf("snapshot accepted inconsistent result for %s", test.command)
			}
		})
	}
}

func TestInstallRejectsUnrestorableProjectTimerBeforeMutation(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	const originalTimer = "[Timer]\nOnCalendar=*-*-* 09:00:00\n"
	write(t, root, TimerPath, originalTimer, 0o644)
	runner.failedCommands["systemctl is-active security-update-notify.timer"] = CommandResult{
		Stdout: []byte("activating\n"),
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), `activity state "activating" cannot be restored exactly`) {
		t.Fatalf("install accepted unrestorable project timer: %v", err)
	}
	if existsNoErr(root, BackupRoot) || existsNoErr(root, BinaryPath) {
		t.Fatalf("timer snapshot failure mutated installation: backup=%t binary=%t",
			existsNoErr(root, BackupRoot), existsNoErr(root, BinaryPath))
	}
	if got := readFile(t, root, TimerPath); got != originalTimer {
		t.Fatalf("timer changed before snapshot completed: %q", got)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "dpkg ") || strings.HasPrefix(command, "rpm ") ||
			strings.HasPrefix(command, "apt-get ") || strings.HasPrefix(command, "dnf ") ||
			strings.HasPrefix(command, "microdnf ") || strings.HasPrefix(command, "yum ") ||
			strings.HasPrefix(command, "systemctl enable ") || strings.HasPrefix(command, "systemctl disable ") ||
			strings.HasPrefix(command, "systemctl start ") || strings.HasPrefix(command, "systemctl stop ") {
			t.Fatalf("mutation ran after timer snapshot failure: %s", command)
		}
	}
}

func TestMaskedSelectedAutomaticUnitFailsBeforeMutation(t *testing.T) {
	for _, enablement := range []string{"masked", "masked-runtime"} {
		t.Run(enablement, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
			write(t, root, dnfAutomaticPath, "[commands]\n", 0o644)
			unit := "dnf5-automatic.timer"
			runner.unitEnablements[unit] = enablement
			runner.activeUnits[unit] = true
			options := telegramOptions()
			options.SkipPostInstallCheck = true

			_, err := installer.Install(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), "unmask it before installation") {
				t.Fatalf("masked timer activation error = %v", err)
			}
			if strings.Contains(err.Error(), "rollback was incomplete") {
				t.Fatalf("masked active timer caused incomplete rollback: %v", err)
			}
			if got, active := runner.unitEnablement(unit), runner.activeUnits[unit]; got != enablement || !active {
				t.Fatalf("timer after rejection: enablement=%q active=%t, want %q active", got, active, enablement)
			}
			for _, command := range runner.commands {
				if strings.HasPrefix(command, "systemctl enable ") || strings.HasPrefix(command, "systemctl disable ") ||
					strings.HasPrefix(command, "systemctl start ") || strings.HasPrefix(command, "systemctl stop ") ||
					strings.HasPrefix(command, "systemctl mask ") || strings.HasPrefix(command, "systemctl unmask ") {
					t.Fatalf("masked selected timer was mutated: %s\n%s", command, strings.Join(runner.commands, "\n"))
				}
			}
		})
	}
}

func TestInstallRejectsUnrestorableProjectTimerEnablementBeforeMutation(t *testing.T) {
	for _, enablement := range []string{
		"alias", "bad", "generated", "indirect", "linked", "linked-runtime",
		"masked", "masked-runtime", "not-found", "transient",
	} {
		t.Run(enablement, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			const originalTimer = "[Timer]\nOnCalendar=*-*-* 09:00:00\n"
			write(t, root, TimerPath, originalTimer, 0o644)
			runner.unitEnablements["security-update-notify.timer"] = enablement
			runner.timerActive = true
			options := telegramOptions()
			options.SkipPostInstallCheck = true

			_, err := installer.Install(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), "cannot be restored exactly") {
				t.Fatalf("install accepted project timer enablement %q: %v", enablement, err)
			}
			if existsNoErr(root, BackupRoot) || existsNoErr(root, BinaryPath) {
				t.Fatalf("timer enablement rejection mutated installation: backup=%t binary=%t",
					existsNoErr(root, BackupRoot), existsNoErr(root, BinaryPath))
			}
			if got := readFile(t, root, TimerPath); got != originalTimer {
				t.Fatalf("timer changed before enablement rejection: %q", got)
			}
			for _, command := range runner.commands {
				if strings.HasPrefix(command, "dpkg ") || strings.HasPrefix(command, "rpm ") ||
					strings.HasPrefix(command, "apt-get ") || strings.HasPrefix(command, "dnf ") ||
					strings.HasPrefix(command, "microdnf ") || strings.HasPrefix(command, "yum ") ||
					strings.HasPrefix(command, "systemctl enable ") || strings.HasPrefix(command, "systemctl disable ") ||
					strings.HasPrefix(command, "systemctl start ") || strings.HasPrefix(command, "systemctl stop ") ||
					strings.HasPrefix(command, "systemctl mask ") || strings.HasPrefix(command, "systemctl unmask ") {
					t.Fatalf("mutation ran after timer enablement rejection: %s", command)
				}
			}
		})
	}
}

func TestAPTAutomaticUnitStatesRollBackExactly(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=ubuntu\nVERSION_ID=26.04\n")
	runner.unitEnablements["apt-daily.timer"] = "enabled-runtime"
	runner.activeUnits["unattended-upgrades.service"] = true
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("expected late readiness failure, got %v", err)
	}
	for unit, want := range map[string]struct {
		enablement string
		active     bool
	}{
		"apt-daily.timer":             {enablement: "enabled-runtime", active: false},
		"apt-daily-upgrade.timer":     {enablement: "disabled", active: false},
		"unattended-upgrades.service": {enablement: "disabled", active: true},
	} {
		if gotEnablement, gotActive := runner.unitEnablement(unit), runner.activeUnits[unit]; gotEnablement != want.enablement || gotActive != want.active {
			t.Errorf("%s after rollback: enablement=%q active=%t, want enablement=%q active=%t", unit, gotEnablement, gotActive, want.enablement, want.active)
		}
	}
}

func TestDNF4AutomaticTimerVariantsAreMutuallyExclusive(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=10.1\n")
	write(t, root, dnfAutomaticPath, "[commands]\n", 0o644)
	selected := "dnf-automatic.timer"
	variants := []string{
		"dnf-automatic-notifyonly.timer",
		"dnf-automatic-download.timer",
		"dnf-automatic-install.timer",
	}
	for _, unit := range append([]string{selected}, variants...) {
		runner.setUnitEnablement(unit, "enabled")
		runner.activeUnits[unit] = true
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got, active := runner.unitEnablement(selected), runner.activeUnits[selected]; got != "enabled" || !active {
		t.Fatalf("selected timer after install: enablement=%q active=%t", got, active)
	}
	for _, unit := range variants {
		if got, active := runner.unitEnablement(unit), runner.activeUnits[unit]; got != "disabled" || active {
			t.Errorf("variant %s after install: enablement=%q active=%t", unit, got, active)
		}
		if commandIndex(runner.commands, "systemctl disable --now "+unit) < 0 {
			t.Errorf("variant %s was not disabled; commands:\n%s", unit, strings.Join(runner.commands, "\n"))
		}
	}
}

func TestDNF5CompatibilityTimerIsMutuallyExclusive(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	write(t, root, dnfAutomaticPath, "[commands]\n", 0o644)
	runner.setUnitEnablement("dnf-automatic.timer", "enabled")
	runner.activeUnits["dnf-automatic.timer"] = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got, active := runner.unitEnablement("dnf5-automatic.timer"), runner.activeUnits["dnf5-automatic.timer"]; got != "enabled" || !active {
		t.Fatalf("native DNF5 timer after install: enablement=%q active=%t", got, active)
	}
	if got, active := runner.unitEnablement("dnf-automatic.timer"), runner.activeUnits["dnf-automatic.timer"]; got != "disabled" || active {
		t.Fatalf("compatibility DNF5 timer after install: enablement=%q active=%t", got, active)
	}
	if commandIndex(runner.commands, "systemctl disable --now dnf-automatic.timer") < 0 {
		t.Fatalf("compatibility DNF5 timer was not disabled; commands:\n%s", strings.Join(runner.commands, "\n"))
	}
}

func TestDNF5CompatibilityTimerRollsBackExactly(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	runner.setUnitEnablement("dnf-automatic.timer", "enabled-runtime")
	runner.activeUnits["dnf-automatic.timer"] = true
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("late DNF5 failure = %v", err)
	}
	if got, active := runner.unitEnablement("dnf5-automatic.timer"), runner.activeUnits["dnf5-automatic.timer"]; got != "disabled" || active {
		t.Fatalf("native DNF5 timer after rollback: enablement=%q active=%t", got, active)
	}
	if got, active := runner.unitEnablement("dnf-automatic.timer"), runner.activeUnits["dnf-automatic.timer"]; got != "enabled-runtime" || !active {
		t.Fatalf("compatibility DNF5 timer after rollback: enablement=%q active=%t", got, active)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("DNF5 configuration after rollback = %q", got)
	}
}

func TestDNF4AutomaticTimerVariantDisableFailuresRollBackExactly(t *testing.T) {
	variants := []string{
		"dnf-automatic-notifyonly.timer",
		"dnf-automatic-download.timer",
		"dnf-automatic-install.timer",
	}
	want := map[string]struct {
		enablement string
		active     bool
	}{
		"dnf-automatic.timer":            {enablement: "disabled", active: false},
		"dnf-automatic-notifyonly.timer": {enablement: "enabled", active: true},
		"dnf-automatic-download.timer":   {enablement: "enabled-runtime", active: true},
		"dnf-automatic-install.timer":    {enablement: "enabled", active: false},
	}
	for _, failedUnit := range variants {
		t.Run(failedUnit, func(t *testing.T) {
			installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=10.1\n")
			vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
			write(t, root, dnfAutomaticPath, vendor, 0o644)
			for unit, state := range want {
				runner.setUnitEnablement(unit, state.enablement)
				runner.activeUnits[unit] = state.active
			}
			args := "disable --now " + failedUnit
			if want[failedUnit].enablement == "enabled-runtime" {
				args = "disable --runtime --now " + failedUnit
			}
			runner.failedCommands["systemctl "+args] = CommandResult{Code: 1, Stderr: []byte("forced variant disable failure\n")}
			options := telegramOptions()
			options.SkipPostInstallCheck = true

			_, err := installer.Install(context.Background(), options)
			if err == nil || !strings.Contains(err.Error(), "forced variant disable failure") || !strings.Contains(err.Error(), failedUnit) {
				t.Fatalf("variant disable error = %v", err)
			}
			if strings.Contains(err.Error(), "rollback was incomplete") {
				t.Fatalf("variant disable failure caused incomplete rollback: %v", err)
			}
			if existsNoErr(root, BinaryPath) || readFile(t, root, dnfAutomaticPath) != vendor {
				t.Fatal("variant disable failure did not roll back installed files")
			}
			for unit, state := range want {
				if gotEnablement, gotActive := runner.unitEnablement(unit), runner.activeUnits[unit]; gotEnablement != state.enablement || gotActive != state.active {
					t.Errorf("%s after rollback: enablement=%q active=%t, want enablement=%q active=%t", unit, gotEnablement, gotActive, state.enablement, state.active)
				}
			}
		})
	}
}

func TestDNF4AutomaticTimerVariantDisableIsVerified(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=10.1\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	unit := "dnf-automatic-notifyonly.timer"
	runner.setUnitEnablement(unit, "enabled")
	runner.activeUnits[unit] = true
	// A successful result bypasses fakeRunner's state mutation and models a
	// systemctl invocation that returned success without disabling the timer.
	runner.failedCommands["systemctl disable --now "+unit] = CommandResult{}
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "verify conflicting automatic-update timer") {
		t.Fatalf("variant verification error = %v", err)
	}
	if strings.Contains(err.Error(), "rollback was incomplete") {
		t.Fatalf("variant verification failure caused incomplete rollback: %v", err)
	}
	if got, active := runner.unitEnablement(unit), runner.activeUnits[unit]; got != "enabled" || !active {
		t.Fatalf("variant after rollback: enablement=%q active=%t", got, active)
	}
	if existsNoErr(root, BinaryPath) || readFile(t, root, dnfAutomaticPath) != vendor {
		t.Fatal("variant verification failure did not roll back installed files")
	}
}

func TestDNF4AutomaticTimerVariantsRollBackAfterLateFailure(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=10.1\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	want := map[string]struct {
		enablement string
		active     bool
	}{
		"dnf-automatic.timer":            {enablement: "disabled", active: false},
		"dnf-automatic-notifyonly.timer": {enablement: "enabled", active: true},
		"dnf-automatic-download.timer":   {enablement: "enabled-runtime", active: false},
		"dnf-automatic-install.timer":    {enablement: "masked-runtime", active: true},
	}
	for unit, state := range want {
		runner.setUnitEnablement(unit, state.enablement)
		runner.activeUnits[unit] = state.active
	}
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("late activation error = %v", err)
	}
	if strings.Contains(err.Error(), "rollback was incomplete") {
		t.Fatalf("late activation failure caused incomplete rollback: %v", err)
	}
	for unit, state := range want {
		if gotEnablement, gotActive := runner.unitEnablement(unit), runner.activeUnits[unit]; gotEnablement != state.enablement || gotActive != state.active {
			t.Errorf("%s after rollback: enablement=%q active=%t, want enablement=%q active=%t", unit, gotEnablement, gotActive, state.enablement, state.active)
		}
	}
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func assertRuntimeInvocationLock(t *testing.T, runner *fakeRunner, operation string) {
	t.Helper()
	found := false
	for index, invocation := range runner.invocations {
		if len(invocation.Args) == 0 || invocation.Args[0] != operation {
			continue
		}
		found = true
		if !runner.runtimeLockHeld[index] {
			t.Fatalf("%s ran without the transaction runtime lock: %+v", operation, invocation)
		}
	}
	if !found {
		t.Fatalf("did not observe command operation %q", operation)
	}
}

func assertIndependentRuntimeLock(t *testing.T, runner *fakeRunner, operation string) {
	t.Helper()
	for _, invocation := range runner.invocations {
		if invocation.Name == BinaryPath && len(invocation.Args) > 0 && invocation.Args[0] == operation {
			if got := invocation.Env["SECURITY_UPDATE_NOTIFY_LOCK_FILE"]; got != InstallCheckLockPath {
				t.Fatalf("%s lock override = %q, want %q", operation, got, InstallCheckLockPath)
			}
			return
		}
	}
	t.Fatalf("did not observe runtime operation %q", operation)
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
	if !reflect.DeepEqual(locker.calls, []string{InstallLockPath, RuntimeLockPath}) {
		t.Fatalf("unexpected transaction lock sequence: %v", locker.calls)
	}
	assertRuntimeInvocationLock(t, runner, "list-timers")
	assertRuntimeInvocationLock(t, runner, "disable")
	if locker.isHeld(RuntimeLockPath) {
		t.Fatal("rollback leaked the runtime lock")
	}
	assertCommandOrder(t, runner.commands,
		"systemctl disable --now security-update-notify.timer",
		"dpkg -s apt-listchanges",
		"apt-get update",
	)
}

func TestRollbackContinuesAfterIndependentPathFailure(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	oldValues := cloneConfig(configDefaults)
	oldValues["NOTIFY_CHANNELS"] = "telegram,feishu"
	oldValues["TELEGRAM_BOT_TOKEN"] = "123456:old_token"
	oldValues["TELEGRAM_CHAT_ID"] = "-100"
	oldValues["FEISHU_APP_ID"] = "cli_old"
	oldValues["FEISHU_RECEIVE_ID"] = "ou_old"
	oldValues["BACKEND"] = "apt"
	writeConfig(t, root, oldValues)
	oldConfig := readFile(t, root, ConfigPath)
	write(t, root, BinaryPath, "old-runtime", 0o755)
	write(t, root, ServicePath, "old-service", 0o644)
	write(t, root, TimerPath, renderTimer("08:30"), 0o644)
	write(t, root, FeishuPlainCredentialPath, "old-secret", 0o600)
	runner.timerActive = true

	removeErr := errors.New("forced binary rollback removal failure")
	installer.fs = &failRemoveFS{FileSystem: root, path: BinaryPath, err: removeErr}
	runner.failListTimers = true
	_, err := installer.Install(context.Background(), Options{
		Config:       map[string]string{"HOST_LABEL": "changed"},
		Payload:      Payload{Runtime: []byte("new-runtime")},
		FeishuSecret: []byte("new-secret"),
	})
	if err == nil || !errors.Is(err, removeErr) || !strings.Contains(err.Error(), "rollback was incomplete") ||
		!strings.Contains(err.Error(), "project timer was not reactivated") {
		t.Fatalf("Install() error = %v, want joined incomplete rollback error", err)
	}
	if got := readFile(t, root, BinaryPath); got != "new-runtime" {
		t.Fatalf("faulted binary rollback unexpectedly changed runtime: %q", got)
	}
	if got := readFile(t, root, ServicePath); got != "old-service" {
		t.Fatalf("service restoration stopped after binary failure: %q", got)
	}
	if got := readFile(t, root, ConfigPath); got != oldConfig {
		t.Fatalf("config restoration stopped after binary failure:\n%s", got)
	}
	if got := readFile(t, root, FeishuPlainCredentialPath); got != "old-secret" {
		t.Fatalf("credential restoration stopped after binary failure: %q", got)
	}
	if runner.timerActive {
		t.Fatal("project timer was reactivated after an incomplete file rollback")
	}
	for _, unit := range []string{"apt-daily.timer", "apt-daily-upgrade.timer", "unattended-upgrades.service"} {
		if runner.unitEnablement(unit) != "disabled" || runner.activeUnits[unit] {
			t.Fatalf("automatic unit %s was not contained after incomplete rollback: enablement=%q active=%t",
				unit, runner.unitEnablement(unit), runner.activeUnits[unit])
		}
	}
}

func TestRollbackContinuesAcrossAutomaticUnitFailures(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=10.1\n")
	first := unitSnapshot{name: "dnf-automatic-notifyonly.timer", enablement: "enabled", active: true}
	second := unitSnapshot{name: "dnf-automatic-download.timer", enablement: "enabled-runtime", active: true}
	runner.setUnitEnablement(first.name, "disabled")
	runner.setUnitEnablement(second.name, "disabled")
	firstErr := errors.New("forced first unit enable failure")
	runner.failedCommands["systemctl enable "+first.name] = CommandResult{Err: firstErr}

	err := installer.restoreAutomaticUnits([]unitSnapshot{first, second})
	if !errors.Is(err, firstErr) {
		t.Fatalf("restoreAutomaticUnits() error = %v, want first unit failure", err)
	}
	if got, active := runner.unitEnablement(second.name), runner.activeUnits[second.name]; got != second.enablement || !active {
		t.Fatalf("second unit restoration stopped after first failure: enablement=%q active=%t", got, active)
	}
	assertCommandOrder(t, runner.commands,
		"systemctl enable "+first.name,
		"systemctl enable --runtime "+second.name,
		"systemctl start "+second.name,
	)

	runner.commands = nil
	runner.activeUnits[first.name] = true
	runner.activeUnits[second.name] = true
	stopErr := errors.New("forced first unit stop failure")
	runner.failedCommands["systemctl stop "+first.name] = CommandResult{Err: stopErr}
	err = installer.quiesceAutomaticUnits([]unitSnapshot{first, second})
	if !errors.Is(err, stopErr) {
		t.Fatalf("quiesceAutomaticUnits() error = %v, want first unit failure", err)
	}
	if !runner.activeUnits[first.name] || runner.activeUnits[second.name] {
		t.Fatalf("quiesce continuation states: first=%t second=%t", runner.activeUnits[first.name], runner.activeUnits[second.name])
	}
	assertCommandOrder(t, runner.commands,
		"systemctl stop "+first.name,
		"systemctl stop "+second.name,
	)

	runner.commands = nil
	write(t, root, ServicePath, "service", 0o644)
	timerErr := errors.New("forced project timer disable failure")
	runner.failedCommands["systemctl disable --now security-update-notify.timer"] = CommandResult{Err: timerErr}
	err = installer.quiesceForRollback(timerSnapshot{active: true})
	if !errors.Is(err, timerErr) {
		t.Fatalf("quiesceForRollback() error = %v, want timer failure", err)
	}
	assertCommandOrder(t, runner.commands,
		"systemctl disable --now security-update-notify.timer",
		"systemctl stop security-update-notify.service",
	)
}

func TestRollbackUsesOneSystemctlAvailabilityDecision(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	lookups := 0
	runner.lookPathHook = func(name string) bool {
		if name != "systemctl" {
			return true
		}
		lookups++
		return lookups == 1
	}
	b := &backup{snapshots: map[string]nodeSnapshot{}}
	private := map[string]privateSnapshot{
		FeishuEncryptedCredPath:   {},
		FeishuPlainCredentialPath: {},
	}

	if err := installer.restoreBackup(b, private, timerSnapshot{enablement: "not-found"}, nil); err != nil {
		t.Fatalf("restoreBackup() unexpectedly followed a later LookPath result: %v", err)
	}
	if lookups != 1 {
		t.Fatalf("systemctl availability was probed %d times during rollback, want one", lookups)
	}
}

func TestRollbackContainsUnitsAfterPartialAutomaticRestore(t *testing.T) {
	installer, _, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=10.1\n")
	first := unitSnapshot{name: "dnf-automatic-notifyonly.timer", enablement: "enabled", active: true}
	second := unitSnapshot{name: "dnf-automatic-download.timer", enablement: "enabled-runtime", active: true}
	runner.setUnitEnablement(first.name, "disabled")
	runner.setUnitEnablement(second.name, "disabled")
	firstErr := errors.New("forced first unit enable failure")
	runner.failedCommands["systemctl enable "+first.name] = CommandResult{Err: firstErr}
	b := &backup{snapshots: map[string]nodeSnapshot{}}
	private := map[string]privateSnapshot{
		FeishuEncryptedCredPath:   {},
		FeishuPlainCredentialPath: {},
	}

	err := installer.restoreBackup(b, private, timerSnapshot{enablement: "not-found"}, []unitSnapshot{first, second})
	if !errors.Is(err, firstErr) || !strings.Contains(err.Error(), "project timer was not reactivated") {
		t.Fatalf("restoreBackup() error = %v, want partial unit failure and containment", err)
	}
	for _, unit := range []string{first.name, second.name} {
		if got, active := runner.unitEnablement(unit), runner.activeUnits[unit]; got != "disabled" || active {
			t.Fatalf("unit %s escaped incomplete-rollback containment: enablement=%q active=%t", unit, got, active)
		}
	}
	assertCommandOrder(t, runner.commands,
		"systemctl enable --runtime "+second.name,
		"systemctl start "+second.name,
		"systemctl disable --now security-update-notify.timer",
		"systemctl disable --now "+first.name,
		"systemctl disable --now "+second.name,
	)
}

func TestDependencyInstallRequiresApprovalBeforePackageManagerWrites(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
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
	if existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("declined dependency installation left an absence marker")
	}
}

func TestFailedDependencyInstallPreservesPackageDefaultsAndAutomaticUnits(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	runner.missingPackages["dnf-automatic"] = true
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if command.Name != "dnf" {
			return CommandResult{Err: fmt.Errorf("unexpected package manager: %s", command.Name)}
		}
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		runner.setUnitEnablement("dnf-automatic.timer", "enabled")
		runner.activeUnits["dnf-automatic.timer"] = true
		return CommandResult{Code: 1, Stderr: []byte("forced partial package transaction failure")}
	}
	options := telegramOptions()
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		return reflect.DeepEqual(request.Packages, []string{"dnf-automatic"}), nil
	}

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced partial package transaction failure") {
		t.Fatalf("dependency install error = %v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorConfig {
		t.Fatalf("package-created DNF default after rollback = %q", got)
	}
	if existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("partial dependency transaction prematurely created a stable DNF baseline")
	}
	if got := readFile(t, root, dnfAbsentMarkerPath); got != dnfAbsentMarkerContents {
		t.Fatalf("partial dependency DNF marker = %q", got)
	}
	if got, want := readFile(t, root, dnfDependencyProofPath), string(dnfDependencyProofContents([]byte(vendorConfig))); got != want {
		t.Fatalf("partial dependency DNF proof = %q, want %q", got, want)
	}
	if info, statErr := root.Lstat(dnfDependencyProofPath); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("partial dependency DNF proof mode: info=%v err=%v", info, statErr)
	}
	if runner.unitEnablement("dnf-automatic.timer") != "enabled" || !runner.activeUnits["dnf-automatic.timer"] {
		t.Fatal("rollback changed automatic-unit state created by the retained dependency package")
	}
	if commandIndex(runner.commands, "systemctl is-enabled dnf-automatic.timer") >= 0 ||
		commandIndex(runner.commands, "systemctl disable --now dnf-automatic.timer") >= 0 {
		t.Fatalf("SUN tried to roll back an automatic unit it had not changed:\n%s", strings.Join(runner.commands, "\n"))
	}

	runner.dependencyInstallHook = nil
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("retry after partial dependency transaction: %v", err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendorConfig {
		t.Fatalf("retry DNF baseline = %q, want package-created vendor config", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("retry retained superseded DNF dependency metadata")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorConfig {
		t.Fatalf("purge after dependency retry restored %q, want vendor config", got)
	}
	if existsNoErr(root, dnfStableBackupPath) || existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("purge after dependency retry left DNF baseline metadata")
	}
}

func TestDNFDependencyDefaultCaptureFailurePreservesPackageConfigurationAndTimer(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	installer.fs = &failDependencyCaptureFS{
		FileSystem: root,
		source:     dnfAutomaticPath,
		err:        errors.New("forced DNF dependency default capture failure"),
	}
	runner.missingPackages["dnf-automatic"] = true
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		runner.setUnitEnablement("dnf-automatic.timer", "enabled")
		runner.activeUnits["dnf-automatic.timer"] = true
		return CommandResult{}
	}
	options := telegramOptions()
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced DNF dependency default capture failure") {
		t.Fatalf("dependency capture error = %v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorConfig {
		t.Fatalf("dependency-created DNF configuration after rollback = %q", got)
	}
	if runner.unitEnablement("dnf-automatic.timer") != "enabled" || !runner.activeUnits["dnf-automatic.timer"] {
		t.Fatal("rollback changed the retained DNF dependency timer")
	}
	if existsNoErr(root, BinaryPath) {
		t.Fatal("dependency capture failure left the SUN runtime installed")
	}
}

func TestDNF4DependencyProofWriteFailurePromotesSafeBaselineBeforeAbort(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	installer.fs = &failAtomicWriteFS{
		FileSystem: root,
		path:       dnfDependencyProofPath,
		err:        errors.New("forced dependency proof write failure"),
	}
	runner.missingPackages["dnf-automatic"] = true
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if command.Name != "dnf" {
			return CommandResult{Err: fmt.Errorf("unexpected package manager: %s", command.Name)}
		}
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		runner.setUnitEnablement("dnf-automatic.timer", "enabled")
		runner.activeUnits["dnf-automatic.timer"] = true
		return CommandResult{}
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced dependency proof write failure") {
		t.Fatalf("dependency proof write error = %v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorConfig {
		t.Fatalf("package-created DNF default after proof failure = %q", got)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendorConfig {
		t.Fatalf("DNF stable baseline after proof failure = %q", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) || existsNoErr(root, BinaryPath) {
		t.Fatal("proof failure retained transient DNF metadata or installed the runtime")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorConfig {
		t.Fatalf("purge after proof failure restored %q, want vendor config", got)
	}
	if existsNoErr(root, dnfStableBackupPath) || existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("purge after proof failure retained DNF metadata")
	}
	if runner.unitEnablement("dnf-automatic.timer") != "enabled" || !runner.activeUnits["dnf-automatic.timer"] {
		t.Fatal("purge after proof failure changed the retained dependency package timer")
	}
}

func TestFailedDNF4DependencyInstallCanBePurgedImmediately(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	runner.missingPackages["dnf-automatic"] = true
	const vendorConfig = "[commands]\nupgrade_type = default\napply_updates = no\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if command.Name != "dnf" {
			return CommandResult{Err: fmt.Errorf("unexpected package manager: %s", command.Name)}
		}
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		runner.setUnitEnablement("dnf-automatic.timer", "enabled")
		runner.activeUnits["dnf-automatic.timer"] = true
		return CommandResult{Code: 1, Stderr: []byte("forced partial package transaction failure")}
	}
	options := telegramOptions()
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced partial package transaction failure") {
		t.Fatalf("dependency install error = %v", err)
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorConfig {
		t.Fatalf("immediate purge changed dependency default to %q", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) || existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("immediate purge retained DNF dependency metadata")
	}
	if runner.unitEnablement("dnf-automatic.timer") != "enabled" || !runner.activeUnits["dnf-automatic.timer"] {
		t.Fatal("immediate purge changed the retained dependency package timer")
	}
}

func TestFailedAPTDependencyInstallPreservesProofAcrossRetryAndPurge(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	runner.missingPackages["unattended-upgrades"] = true
	const vendorConfig = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if command.Name != "apt-get" {
			return CommandResult{Err: fmt.Errorf("unexpected package manager: %s", command.Name)}
		}
		if err := root.WriteFileAtomic(aptPeriodicPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		runner.setUnitEnablement("apt-daily-upgrade.timer", "enabled")
		runner.activeUnits["apt-daily-upgrade.timer"] = true
		return CommandResult{Code: 1, Stderr: []byte("forced partial apt package transaction failure")}
	}
	options := telegramOptions()
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced partial apt package transaction failure") {
		t.Fatalf("dependency install error = %v", err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != vendorConfig {
		t.Fatalf("package-created APT default after rollback = %q", got)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("partial dependency transaction prematurely created a stable APT baseline")
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("partial dependency APT marker = %q", got)
	}
	if got, want := readFile(t, root, aptDependencyProofPath), string(aptDependencyProofContents([]byte(vendorConfig))); got != want {
		t.Fatalf("partial dependency APT proof = %q, want %q", got, want)
	}
	if info, statErr := root.Lstat(aptDependencyProofPath); statErr != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("partial dependency APT proof mode: info=%v err=%v", info, statErr)
	}
	if runner.unitEnablement("apt-daily-upgrade.timer") != "enabled" || !runner.activeUnits["apt-daily-upgrade.timer"] {
		t.Fatal("rollback changed the retained APT package timer")
	}

	runner.dependencyInstallHook = nil
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("retry after partial APT dependency transaction: %v", err)
	}
	if got := readFile(t, root, aptStableBackupPath); got != vendorConfig {
		t.Fatalf("retry APT baseline = %q, want package-created vendor config", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("retry retained superseded APT dependency metadata")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != vendorConfig {
		t.Fatalf("purge after APT dependency retry restored %q, want vendor config", got)
	}
	if existsNoErr(root, aptStableBackupPath) || existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("purge after APT dependency retry left baseline metadata")
	}
}

func TestAPTDependencyDefaultCaptureFailurePreservesPackageConfigurationAndTimer(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	installer.fs = &failDependencyCaptureFS{
		FileSystem: root,
		source:     aptPeriodicPath,
		err:        errors.New("forced APT dependency default capture failure"),
	}
	runner.missingPackages["unattended-upgrades"] = true
	const vendorConfig = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if err := root.WriteFileAtomic(aptPeriodicPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		runner.setUnitEnablement("apt-daily-upgrade.timer", "enabled")
		runner.activeUnits["apt-daily-upgrade.timer"] = true
		return CommandResult{}
	}
	options := telegramOptions()
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced APT dependency default capture failure") {
		t.Fatalf("dependency capture error = %v", err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != vendorConfig {
		t.Fatalf("dependency-created APT configuration after rollback = %q", got)
	}
	if runner.unitEnablement("apt-daily-upgrade.timer") != "enabled" || !runner.activeUnits["apt-daily-upgrade.timer"] {
		t.Fatal("rollback changed the retained APT dependency timer")
	}
	if existsNoErr(root, BinaryPath) {
		t.Fatal("dependency capture failure left the SUN runtime installed")
	}
}

func TestAPTDependencyProofWriteFailurePromotesSafeBaselineBeforeAbort(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME='Debian 13'\n")
	installer.fs = &failAtomicWriteFS{
		FileSystem: root,
		path:       aptDependencyProofPath,
		err:        errors.New("forced apt dependency proof write failure"),
	}
	runner.missingPackages["unattended-upgrades"] = true
	const vendorConfig = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if command.Name != "apt-get" {
			return CommandResult{Err: fmt.Errorf("unexpected package manager: %s", command.Name)}
		}
		if err := root.WriteFileAtomic(aptPeriodicPath, []byte(vendorConfig), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		return CommandResult{}
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced apt dependency proof write failure") {
		t.Fatalf("dependency proof write error = %v", err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != vendorConfig {
		t.Fatalf("package-created APT default after proof failure = %q", got)
	}
	if got := readFile(t, root, aptStableBackupPath); got != vendorConfig {
		t.Fatalf("APT stable baseline after proof failure = %q", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) || existsNoErr(root, BinaryPath) {
		t.Fatal("proof failure retained transient APT metadata or installed the runtime")
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

func TestAPTUpdateFailureDoesNotRetainDependencyBaselineMetadata(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	runner.missingPackages["unattended-upgrades"] = true
	runner.failedCommands["apt-get update"] = CommandResult{Code: 1, Stderr: []byte("forced apt update failure")}
	options := telegramOptions()
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced apt update failure") {
		t.Fatalf("apt update error = %v", err)
	}
	if existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptPeriodicPath) {
		t.Fatal("package-list update failure retained dependency baseline metadata")
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

func TestFreshAPTDependencyDefaultIsPreservedByPurge(t *testing.T) {
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
	if got := readFile(t, root, aptStableBackupPath); got != "dependency-default\n" {
		t.Fatalf("APT dependency baseline = %q", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("promoted APT dependency baseline retained transient metadata")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != "dependency-default\n" {
		t.Fatalf("purge restored %q, want the retained dependency default", got)
	}
	if existsNoErr(root, aptStableBackupPath) || existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("purge retained APT dependency metadata")
	}
}

func TestFreshAPTAbsenceSurvivesManagedUpgradeHistoryAndPurge(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("fresh APT absence marker = %q", got)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("fresh APT absence unexpectedly created a fixed baseline")
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := installer.Install(context.Background(), options); err != nil {
			t.Fatalf("managed upgrade %d: %v", attempt+1, err)
		}
	}
	managedTimestamp := aptPeriodicPath + ".security-update-notify.20260726120000.bak"
	if got := readFile(t, root, managedTimestamp); got != aptPeriodicConfig {
		t.Fatalf("managed APT timestamp = %q", got)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("managed SUN timestamp was promoted as a vendor baseline")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, managedTimestamp) {
		t.Fatal("purge did not restore the original APT absence after managed upgrades")
	}
}

func TestLegacyAPTMarkerDoesNotPromoteManagedTimestamp(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	legacyTimestamp := aptPeriodicPath + ".security-update-notify.20260725010203.bak"
	write(t, root, aptPeriodicPath, aptPeriodicConfig, 0o644)
	write(t, root, aptAbsentMarkerPath, aptAbsentMarkerContents, 0o600)
	write(t, root, legacyTimestamp, aptPeriodicConfig, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptStableBackupPath) {
		t.Fatal("legacy SUN-managed timestamp was promoted as a vendor baseline")
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("legacy APT absence marker = %q", got)
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, aptPeriodicPath) || existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, legacyTimestamp) {
		t.Fatal("legacy managed-history purge did not restore APT absence")
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
	if got := readFile(t, root, aptStableBackupPath); got != "legacy timestamp\n" {
		t.Fatalf("promoted APT baseline = %q", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("promoted APT baseline retained the migrated absence marker")
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

func TestLegacyAPTBaselinePromotionSurvivesLateFailure(t *testing.T) {
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
	if got := readFile(t, root, aptStableBackupPath); got != "legacy timestamp\n" {
		t.Fatalf("promoted APT baseline after rollback = %q", got)
	}
	if existsNoErr(root, aptLegacyAbsentPath) || existsNoErr(root, aptAbsentMarkerPath) {
		t.Fatal("superseded APT absence marker survived baseline promotion")
	}
	if got := readFile(t, root, legacyTimestamp); got != "legacy timestamp\n" {
		t.Fatalf("legacy APT timestamp after rollback = %q", got)
	}
	if existsNoErr(root, currentTimestamp) {
		t.Fatal("migrated APT timestamp survived rollback")
	}
}

func TestLegacyAPTBaselinePromotionRollsBackTransientMigrationExactly(t *testing.T) {
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
	if got := readFile(t, root, aptStableBackupPath); got != "legacy timestamp\n" {
		t.Fatalf("promoted APT baseline after rollback = %q", got)
	}
	if got := readFile(t, root, legacyTimestamp); got != "legacy timestamp\n" {
		t.Fatalf("legacy APT timestamp after rollback = %q", got)
	}
	for _, unexpected := range []string{aptLegacyAbsentPath, aptAbsentMarkerPath, aptDependencyProofPath, currentTimestamp, aptPeriodicPath} {
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

func TestCreateBackupReportsPrimaryAndCleanupFailures(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, BinaryPath, "runtime", 0o755)
	copyErr := errors.New("forced backup copy failure")
	removeErr := errors.New("forced incomplete backup removal failure")
	installer.fs = &failBackupCleanupFS{
		FileSystem: root,
		source:     BinaryPath,
		copyErr:    copyErr,
		removeErr:  removeErr,
	}

	if _, err := installer.createBackup(); err == nil || !errors.Is(err, copyErr) || !errors.Is(err, removeErr) ||
		!strings.Contains(err.Error(), "remove incomplete backup") {
		t.Fatalf("createBackup error = %v, want primary and cleanup failures", err)
	}
}

func TestPruneBackupsRecoversInterruptedRemovalQuarantine(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	if err := root.MkdirAll(BackupRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	artifact := path.Join(BackupRoot, removalPrefix+strings.Repeat("c", 32))
	if err := root.MkdirAll(artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	write(t, root, path.Join(artifact, "telegram.env"), "token", 0o600)
	current := path.Join(BackupRoot, "20260731010101")
	if err := root.Mkdir(current, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := installer.pruneBackups(current); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, artifact) {
		t.Fatal("interrupted backup-removal quarantine survived pruning retry")
	}
}

func TestFreshAPTDependencyBaselineSurvivesFailedInstallRetryAndPurge(t *testing.T) {
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
	if got := readFile(t, root, aptStableBackupPath); got != "dependency-default\n" {
		t.Fatalf("APT dependency baseline after rollback = %q", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("late rollback resurrected promoted APT dependency metadata")
	}

	runner.failListTimers = false
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != "dependency-default\n" {
		t.Fatalf("purge after retry restored %q, want dependency default", got)
	}
	if existsNoErr(root, aptStableBackupPath) || existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("purge after retry retained APT dependency metadata")
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
	if got := readFile(t, root, aptPeriodicPath); got != "dependency-default\n" {
		t.Fatalf("failed marker capture lost the retained dependency default: %q", got)
	}
	if existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) || existsNoErr(root, aptStableBackupPath) {
		t.Fatal("failed marker capture retained incomplete APT metadata")
	}

	faults.enabled = false
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("retry install: %v", err)
	}
	if got := readFile(t, root, aptStableBackupPath); got != "dependency-default\n" {
		t.Fatalf("retry APT baseline = %q, want dependency default", got)
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != "dependency-default\n" {
		t.Fatalf("purge after marker capture failure restored %q", got)
	}
	if existsNoErr(root, aptStableBackupPath) || existsNoErr(root, aptAbsentMarkerPath) || existsNoErr(root, aptDependencyProofPath) {
		t.Fatal("purge after marker capture failure retained APT metadata")
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

func TestInstallRejectsUnprovenAPTDependencyDefault(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	const unknown = "APT::Periodic::Unattended-Upgrade \"1\";\n"
	write(t, root, aptPeriodicPath, unknown, 0o644)
	write(t, root, aptAbsentMarkerPath, aptAbsentMarkerContents, 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("unproven APT dependency-default error = %v", err)
	}
	if got := readFile(t, root, aptPeriodicPath); got != unknown {
		t.Fatalf("unproven APT config changed during rollback: %q", got)
	}
	if got := readFile(t, root, aptAbsentMarkerPath); got != aptAbsentMarkerContents {
		t.Fatalf("unproven APT marker changed during rollback: %q", got)
	}
	if existsNoErr(root, aptStableBackupPath) || existsNoErr(root, BinaryPath) {
		t.Fatal("unproven APT default left a stable baseline or installed runtime")
	}
}

func TestFreshDNF5AbsentBaselineIsRemovedByPurge(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if !existsNoErr(root, dnfAutomaticPath) || !existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("fresh DNF install did not record the absent configuration baseline")
	}
	if got := readFile(t, root, dnfAbsentMarkerPath); got != dnf5AbsentMarkerContents {
		t.Fatalf("fresh DNF5 absence marker = %q, want %q", got, dnf5AbsentMarkerContents)
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if existsNoErr(root, dnfAutomaticPath) || existsNoErr(root, dnfAbsentMarkerPath) {
		t.Fatal("purge did not restore the originally absent DNF configuration")
	}
}

func TestDNF4RejectsInstalledDependencyWithoutVendorConfiguration(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "automatic.conf is missing after dependency verification") {
		t.Fatalf("missing DNF4 vendor config error = %v", err)
	}
	if existsNoErr(root, dnfAutomaticPath) || existsNoErr(root, dnfStableBackupPath) || existsNoErr(root, BinaryPath) {
		t.Fatal("failed DNF4 readiness check changed the host configuration")
	}
}

func TestFreshDNF4DependencyBaselineIsRestoredByPurge(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	runner.missingPackages["dnf-automatic"] = true
	const vendor = "[commands]\nupgrade_type = default\napply_updates = no\n"
	runner.dependencyInstallHook = func(command Command) CommandResult {
		if command.Name != "dnf" {
			return CommandResult{Err: fmt.Errorf("unexpected package manager: %s", command.Name)}
		}
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte(vendor), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		return CommandResult{}
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(_ context.Context, request DependencyRequest) (bool, error) {
		return reflect.DeepEqual(request.Packages, []string{"dnf-automatic"}), nil
	}
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendor {
		t.Fatalf("DNF4 stable baseline = %q, want dependency vendor config", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) {
		t.Fatal("DNF4 absence marker survived vendor-baseline adoption")
	}
	if existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("DNF4 dependency proof survived vendor-baseline adoption")
	}
	if got := readFile(t, root, dnfAutomaticPath); !strings.Contains(got, "apply_updates = yes") {
		t.Fatalf("DNF4 managed configuration was not installed: %q", got)
	}

	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("DNF4 purge restored %q, want dependency vendor config", got)
	}
	if existsNoErr(root, dnfStableBackupPath) || existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("DNF4 purge left SUN baseline metadata")
	}
}

func TestDNF4LegacyAbsenceMarkerMigratesEarliestTimestampBaseline(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	managedCurrent := "[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"
	vendorOriginal := "[commands]\nupgrade_type = default\napply_updates = no\n"
	managedPrevious := "[commands]\nupgrade_type = security\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, managedCurrent, 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	write(t, root, dnfDependencyProofPath, "stale proof\n", 0o600)
	write(t, root, dnfStableBackupPath+".20260725000000", vendorOriginal, 0o644)
	write(t, root, dnfStableBackupPath+".20260726000000", managedPrevious, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendorOriginal {
		t.Fatalf("migrated DNF4 baseline = %q, want earliest timestamp", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("legacy DNF4 dependency metadata survived timestamp baseline migration")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendorOriginal {
		t.Fatalf("legacy DNF4 purge restored %q, want earliest vendor config", got)
	}
}

func TestDNF4MissingCurrentUsesTrustedTimestampAsManagedTemplate(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	vendorOriginal := "[commands]\nupgrade_type = default\napply_updates = no\n[email]\nemail_to = root@example.test\n"
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	write(t, root, dnfStableBackupPath+".20260725000000", vendorOriginal, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendorOriginal {
		t.Fatalf("recovered DNF4 baseline = %q, want timestamped vendor config", got)
	}
	managed := readFile(t, root, dnfAutomaticPath)
	for _, want := range []string{"email_to = root@example.test", "upgrade_type = security", "apply_updates = yes", "reboot = never"} {
		if !strings.Contains(managed, want) {
			t.Fatalf("recovered DNF4 managed config omitted %q: %q", want, managed)
		}
	}
	if existsNoErr(root, dnfAbsentMarkerPath) {
		t.Fatal("recovered DNF4 installation retained its obsolete absence marker")
	}
}

func TestDNF4LegacyMarkerNeverAdoptsCurrentManagedConfigWithoutHistory(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	managedCurrent := "[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"
	write(t, root, dnfAutomaticPath, managedCurrent, 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("ambiguous managed DNF4 config error = %v", err)
	}
	if existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("legacy current managed DNF4 config was adopted as a vendor baseline")
	}
	if got := readFile(t, root, dnfAbsentMarkerPath); got != dnfAbsentMarkerContents {
		t.Fatalf("legacy DNF4 marker = %q, want preserved marker", got)
	}
}

func TestDNF4UpgradeNeverAdoptsCurrentConfigWithoutHistory(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	write(t, root, BinaryPath, "old-runtime", 0o755)
	write(t, root, dnfAutomaticPath, "[commands]\nupgrade_type = default\napply_updates = no\n", 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("ambiguous DNF4 upgrade error = %v", err)
	}
	if existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("upgrade adopted an ambiguous current DNF4 config as the original baseline")
	}
	if got := readFile(t, root, BinaryPath); got != "old-runtime" {
		t.Fatalf("ambiguous DNF4 upgrade changed the old runtime: %q", got)
	}
	if got := readFile(t, root, dnfAbsentMarkerPath); got != dnfAbsentMarkerContents {
		t.Fatalf("upgrade DNF4 marker = %q, want preserved marker", got)
	}
}

func TestDNF4FreshInstallNeverAdoptsCurrentConfigWithoutProofOrHistory(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	write(t, root, dnfAutomaticPath, "[commands]\nupgrade_type = default\napply_updates = no\n", 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "cannot prove") {
		t.Fatalf("ambiguous fresh DNF4 config error = %v", err)
	}
	if existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("fresh install adopted an ambiguous current DNF4 config without provenance")
	}
	if existsNoErr(root, BinaryPath) {
		t.Fatal("ambiguous fresh DNF4 config installed a runtime")
	}
	if got := readFile(t, root, dnfAbsentMarkerPath); got != dnfAbsentMarkerContents {
		t.Fatalf("fresh-install DNF4 marker = %q, want preserved marker", got)
	}
}

func TestDNF4RetryPromotesProvenVendorConfigWithoutTimestampHistory(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	// Reproduce residue from a retained partial dependency transaction. The
	// content-bound proof is the only authority for adopting the current file.
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	write(t, root, dnfDependencyProofPath, string(dnfDependencyProofContents([]byte(vendor))), 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendor {
		t.Fatalf("retry DNF4 baseline = %q, want proven vendor config", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("retry retained superseded DNF4 dependency metadata")
	}
	if _, err := uninstaller.Uninstall(uninstaller.Options{
		RootDir: root.Root, PurgeConfig: true, EffectiveUID: func() int { return 0 },
		RunCommand: func(string, ...string) sysexec.Result { return sysexec.Result{} },
	}); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("retry purge restored %q, want proven vendor config", got)
	}
}

func TestDNF4RetryRejectsMismatchedDependencyProof(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	proof := string(dnfDependencyProofContents([]byte("[commands]\nupgrade_type = security\napply_updates = yes\n")))
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	write(t, root, dnfDependencyProofPath, proof, 0o600)
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "dependency proof does not match") {
		t.Fatalf("mismatched DNF dependency proof error = %v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("mismatched-proof rollback changed DNF config: %q", got)
	}
	if got := readFile(t, root, dnfAbsentMarkerPath); got != dnfAbsentMarkerContents {
		t.Fatalf("mismatched-proof rollback changed absence marker: %q", got)
	}
	if got := readFile(t, root, dnfDependencyProofPath); got != proof {
		t.Fatalf("mismatched-proof rollback changed proof: %q", got)
	}
	if existsNoErr(root, dnfStableBackupPath) || existsNoErr(root, BinaryPath) {
		t.Fatal("mismatched dependency proof left an installed runtime or stable baseline")
	}
}

func TestDNF4ProofPromotionSurvivesLateInstallRollback(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	vendor := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendor, 0o644)
	write(t, root, dnfAbsentMarkerPath, dnfAbsentMarkerContents, 0o600)
	write(t, root, dnfDependencyProofPath, string(dnfDependencyProofContents([]byte(vendor))), 0o600)
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("late proof-promotion failure = %v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("proof-promotion rollback restored %q, want vendor config", got)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendor {
		t.Fatalf("proof-promotion rollback baseline = %q, want vendor config", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) || existsNoErr(root, dnfDependencyProofPath) {
		t.Fatal("late rollback resurrected promoted DNF4 dependency metadata")
	}
}

func TestDNF4VendorBaselineSurvivesLateInstallRollback(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=rocky\nVERSION_ID=9.6\nPRETTY_NAME='Rocky Linux 9.6'\n")
	runner.missingPackages["dnf-automatic"] = true
	runner.failListTimers = true
	const vendor = "[commands]\nupgrade_type = default\napply_updates = no\n"
	runner.dependencyInstallHook = func(Command) CommandResult {
		if err := root.MkdirAll("/etc/dnf", 0o755); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(dnfAutomaticPath, []byte(vendor), 0o644); err != nil {
			return CommandResult{Err: err}
		}
		return CommandResult{}
	}
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	options.ConfirmDependencies = func(context.Context, DependencyRequest) (bool, error) { return true, nil }

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("late DNF4 failure = %v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != vendor {
		t.Fatalf("DNF4 config after rollback = %q, want vendor config", got)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendor {
		t.Fatalf("DNF4 stable baseline after rollback = %q, want vendor config", got)
	}
	if existsNoErr(root, dnfAbsentMarkerPath) {
		t.Fatal("DNF4 rollback resurrected the superseded absence marker")
	}
	if runner.unitEnablement("dnf-automatic.timer") != "disabled" || runner.activeUnits["dnf-automatic.timer"] {
		t.Fatal("DNF4 rollback did not restore the post-dependency automatic timer state")
	}
}

func TestDNFOriginalBaselineSurvivesNormalUninstallAndReinstall(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\nPRETTY_NAME='Fedora Linux 43'\n")
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
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	managedCurrent := "[commands]\nupgrade_type = security\napply_updates = yes\n"
	vendorOriginal := "[commands]\nupgrade_type = default\napply_updates = no\n"
	managedPrevious := "[commands]\nupgrade_type = security\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, managedCurrent, 0o644)
	write(t, root, dnfStableBackupPath+".20260725000000", vendorOriginal, 0o644)
	write(t, root, dnfStableBackupPath+".20260726000000", managedPrevious, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendorOriginal {
		t.Fatalf("migrated DNF baseline = %q, want first project backup", got)
	}
}

func TestDNFLegacyMigrationIgnoresUnknownBackupSuffix(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	vendorOriginal := "[commands]\nupgrade_type = default\napply_updates = no\n"
	write(t, root, dnfAutomaticPath, vendorOriginal, 0o644)
	unknown := dnfStableBackupPath + ".not-a-timestamp"
	write(t, root, unknown, "unrelated", 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != vendorOriginal {
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
	write(t, root, "/linked-secret", "app-secret", 0o600)
	if err := os.Link(filepath.Join(root.Root, "linked-secret"), filepath.Join(root.Root, "linked-secret-alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.ReadFeishuSecretFile("/linked-secret"); ExitCode(err) != 2 {
		t.Fatalf("hard-linked secret accepted: %v", err)
	}
	if err := root.Symlink("token", "/token-link"); err != nil {
		t.Fatal(err)
	}
	if _, err := installer.ReadTelegramTokenFile("/token-link"); ExitCode(err) != 2 {
		t.Fatalf("symlink token accepted: %v", err)
	}
}

func TestLoadFeishuSecretUsesVerifiedDescriptorAfterPathReplacement(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	write(t, root, FeishuEncryptedCredPath, "encrypted-original", 0o600)
	runner.systemdCreds = true
	runner.systemdDecryptHook = func(command Command) CommandResult {
		if !reflect.DeepEqual(command.Args, []string{"decrypt", "--name=feishu_app_secret", "/proc/self/fd/3", "-"}) {
			return CommandResult{Err: fmt.Errorf("decrypt args = %v", command.Args)}
		}
		if len(command.ExtraFiles) != 1 {
			return CommandResult{Err: fmt.Errorf("decrypt extra files = %d", len(command.ExtraFiles))}
		}
		if err := root.Remove(FeishuEncryptedCredPath); err != nil {
			return CommandResult{Err: err}
		}
		if err := root.WriteFileAtomic(FeishuEncryptedCredPath, []byte("attacker-replacement"), 0o600); err != nil {
			return CommandResult{Err: err}
		}
		buf := make([]byte, len("encrypted-original"))
		n, err := command.ExtraFiles[0].ReadAt(buf, 0)
		if err != nil || n != len(buf) || string(buf) != "encrypted-original" {
			return CommandResult{Err: fmt.Errorf("descriptor content = %q (%d bytes): %v", buf[:n], n, err)}
		}
		return CommandResult{Stdout: []byte("descriptor-secret")}
	}

	secret, err := installer.loadFeishuSecret(context.Background())
	if err != nil || string(secret) != "descriptor-secret" {
		t.Fatalf("descriptor-bound secret = %q, err=%v", secret, err)
	}
	if got := readFile(t, root, FeishuEncryptedCredPath); got != "attacker-replacement" {
		t.Fatalf("replacement fixture = %q", got)
	}
}

func TestStoredFeishuCredentialRejectsUnsafeMetadata(t *testing.T) {
	for _, test := range []struct {
		name  string
		mode  fs.FileMode
		setup func(*testing.T, *Installer, *RootFS)
	}{
		{name: "group-readable", mode: 0o640},
		{name: "wrong-owner", mode: 0o600, setup: func(_ *testing.T, installer *Installer, _ *RootFS) {
			installer.rootOwnerUID = uint32(os.Geteuid() + 1)
		}},
		{name: "hard-linked", mode: 0o600, setup: func(t *testing.T, _ *Installer, root *RootFS) {
			if err := os.Link(
				filepath.Join(root.Root, strings.TrimPrefix(FeishuPlainCredentialPath, "/")),
				filepath.Join(root.Root, "credential-alias"),
			); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			write(t, root, FeishuPlainCredentialPath, "stored-secret", test.mode)
			if test.setup != nil {
				test.setup(t, installer, root)
			}
			if _, err := installer.loadFeishuSecret(context.Background()); err == nil {
				t.Fatal("unsafe stored credential was accepted")
			}
		})
	}
}

func TestSetINI(t *testing.T) {
	input := []byte("[COMMANDS]\nAPPLY_UPDATES = no\n\n[base]\n")
	got := setINI(input, "commands", "apply_updates", "yes")
	got = setINI(got, "emitters", "emit_via", "stdio")
	text := string(got)
	if strings.Count(text, "apply_updates = yes") != 1 || strings.Contains(strings.ToLower(text), "apply_updates = no") {
		t.Fatalf("existing setting not replaced:\n%s", text)
	}
	if !strings.Contains(text, "[emitters]\nemit_via = stdio\n") {
		t.Fatalf("missing section not appended:\n%s", text)
	}
}

// setINI and parseStrictINI run as a pair over the same file, so they must agree on which header
// names a section. A padded "[ commands ]" that only parseStrictINI matched used to make setINI
// append a second "[commands]", and the managed config then failed its own duplicate-section
// validation, aborting the install on any host with that vendor shape.
func TestSetINIMatchesPaddedSectionHeader(t *testing.T) {
	data := []byte("[ commands ]\nupgrade_type = default\napply_updates = no\n")
	for _, setting := range [][3]string{
		{"commands", "upgrade_type", "security"},
		{"commands", "apply_updates", "yes"},
	} {
		data = setINI(data, setting[0], setting[1], setting[2])
	}
	text := string(data)
	if strings.Contains(text, "[commands]") {
		t.Fatalf("duplicate section appended instead of editing in place:\n%s", text)
	}
	values, err := parseStrictINI(data)
	if err != nil {
		t.Fatalf("managed config failed validation: %v\n%s", err, text)
	}
	if values["commands.upgrade_type"] != "security" || values["commands.apply_updates"] != "yes" {
		t.Fatalf("policy not applied to the padded section: %v\n%s", values, text)
	}
}

func TestParseStrictINIAcceptsVendorShapeCaseInsensitively(t *testing.T) {
	input := []byte("# vendor config\r\n[COMMANDS]\r\nUpgrade_Type = SECURITY\r\nApply_Updates = YES\r\nReboot = NEVER\r\n\r\n[emitters]\r\nemit_via = stdio\r\n[base]\r\ndebuglevel = 1\r\n")
	values, err := parseStrictINI(input)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"commands.upgrade_type":  "security",
		"commands.apply_updates": "yes",
		"commands.reboot":        "never",
	} {
		if got := values[key]; got != want {
			t.Errorf("%s=%q want %q", key, got, want)
		}
	}
}

func TestParseStrictINIRejectsAmbiguousOrMalformedData(t *testing.T) {
	for _, test := range []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "NUL", input: []byte("[commands]\napply_updates=yes\x00\n"), want: "NUL"},
		{name: "broken section", input: []byte("[commands\napply_updates=yes\n"), want: "invalid DNF INI section"},
		{name: "setting before section", input: []byte("apply_updates=yes\n[commands]\n"), want: "before a section"},
		{name: "missing delimiter", input: []byte("[commands]\napply_updates yes\n"), want: "invalid DNF INI setting"},
		{name: "duplicate section", input: []byte("[commands]\napply_updates=yes\n[COMMANDS]\nreboot=never\n"), want: "duplicate DNF INI section"},
		{name: "duplicate key", input: []byte("[commands]\napply_updates=yes\nAPPLY_UPDATES=no\n"), want: "duplicate DNF INI setting"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseStrictINI(test.input)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseStrictINI() error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestMalformedDNFConfigFailsBeforePolicyReplacementAndRollsBack(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	malformed := "[commands\nupgrade_type = default\n"
	write(t, root, dnfAutomaticPath, malformed, 0o644)
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if err == nil || !strings.Contains(err.Error(), "validate dnf automatic config") {
		t.Fatalf("malformed DNF config error=%v", err)
	}
	if got := readFile(t, root, dnfAutomaticPath); got != malformed {
		t.Fatalf("malformed DNF config was not rolled back exactly: %q", got)
	}
	if existsNoErr(root, BinaryPath) || runner.enabledUnits["dnf5-automatic.timer"] {
		t.Fatal("malformed DNF config failure left an installed runtime or enabled timer")
	}
	if existsNoErr(root, dnfAutomaticPath+".security-update-notify.bak.20260726120000") || existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("malformed DNF config failure left backup metadata that could poison a later purge baseline")
	}
}

func TestLateDNFFailureRemovesTimestampBackupFromPurgeBaseline(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=fedora\nVERSION_ID=43\n")
	firstConfig := "[commands]\nupgrade_type = default\napply_updates = no\n# first\n"
	secondConfig := "[commands]\nupgrade_type = default\napply_updates = no\n# second\n"
	write(t, root, dnfAutomaticPath, firstConfig, 0o644)
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("late failure error=%v", err)
	}
	timestampBackup := dnfAutomaticPath + ".security-update-notify.bak.20260726120000"
	if existsNoErr(root, timestampBackup) || existsNoErr(root, dnfStableBackupPath) {
		t.Fatal("late failure left DNF backup metadata that could poison a retry")
	}
	if got := readFile(t, root, dnfAutomaticPath); got != firstConfig {
		t.Fatalf("late failure did not restore first config: %q", got)
	}

	write(t, root, dnfAutomaticPath, secondConfig, 0o644)
	runner.failListTimers = false
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, dnfStableBackupPath); got != secondConfig {
		t.Fatalf("retry stable baseline=%q want second administrator config", got)
	}
	if got := readFile(t, root, timestampBackup); got != secondConfig {
		t.Fatalf("retry timestamp baseline=%q want second administrator config", got)
	}
}

func TestLateAPTFailureRemovesTimestampBackupFromPurgeBaseline(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	firstConfig := "APT::Periodic::Update-Package-Lists \"0\";\n"
	secondConfig := "APT::Periodic::Update-Package-Lists \"1\";\n"
	write(t, root, aptPeriodicPath, firstConfig, 0o644)
	runner.failListTimers = true
	options := telegramOptions()
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err == nil || !strings.Contains(err.Error(), "forced list-timers failure") {
		t.Fatalf("late failure error=%v", err)
	}
	timestampBackup := aptPeriodicPath + ".security-update-notify.20260726120000.bak"
	if existsNoErr(root, timestampBackup) || existsNoErr(root, aptStableBackupPath) {
		t.Fatal("late failure left APT backup metadata that could poison a retry")
	}
	if got := readFile(t, root, aptPeriodicPath); got != firstConfig {
		t.Fatalf("late failure did not restore first APT config: %q", got)
	}

	write(t, root, aptPeriodicPath, secondConfig, 0o644)
	runner.failListTimers = false
	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, root, aptStableBackupPath); got != secondConfig {
		t.Fatalf("retry stable APT baseline=%q want second administrator config", got)
	}
	if got := readFile(t, root, timestampBackup); got != secondConfig {
		t.Fatalf("retry timestamp APT baseline=%q want second administrator config", got)
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
	locker := FileLocker{FS: root, OwnerUID: uint32(os.Geteuid())}
	if unlock, err := locker.Acquire(context.Background(), InstallLockPath, 0); err == nil {
		_ = unlock()
		t.Fatal("symlink lock path was accepted")
	}
}

func TestFileLockerRejectsPathReplacedAfterOpen(t *testing.T) {
	root, err := NewRootFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := root.MkdirAll("/run", 0o755); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root.Root, strings.TrimPrefix(InstallLockPath, "/"))
	heldPath := lockPath + ".held"
	filesystem := &replaceLockPathFS{FileSystem: root}
	filesystem.afterOpen = func() error {
		if err := os.Rename(lockPath, heldPath); err != nil {
			return err
		}
		return os.WriteFile(lockPath, nil, 0o600)
	}
	locker := FileLocker{FS: filesystem, OwnerUID: uint32(os.Geteuid())}
	unlock, err := locker.Acquire(context.Background(), InstallLockPath, 0)
	if err == nil || !strings.Contains(err.Error(), "lock path changed while acquiring") {
		if unlock != nil {
			_ = unlock()
		}
		t.Fatalf("replaced lock path was accepted: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("replacement lock path disappeared: %v", err)
	}
	if _, err := os.Stat(heldPath); err != nil {
		t.Fatalf("opened lock inode disappeared: %v", err)
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

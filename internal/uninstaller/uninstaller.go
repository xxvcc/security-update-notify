package uninstaller

import (
	"errors"
	"fmt"

	"os"
	"path/filepath"
	"strings"
	"syscall"

	"time"

	"github.com/xxvcc/security-update-notify/internal/commandpath"
	"github.com/xxvcc/security-update-notify/internal/filetrust"

	runlock "github.com/xxvcc/security-update-notify/internal/lock"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

const (
	timerUnit              = "security-update-notify.timer"
	serviceUnit            = "security-update-notify.service"
	aptPeriodicLogical     = "/etc/apt/apt.conf.d/20auto-upgrades"
	aptStableLogical       = aptPeriodicLogical + ".security-update-notify.bak"
	aptAbsentLogical       = aptPeriodicLogical + ".security-update-notify.absent.bak"
	aptLegacyAbsent        = aptPeriodicLogical + ".security-update-notify.absent"
	aptDependencyProof     = aptPeriodicLogical + ".security-update-notify.dependency-default.bak"
	aptAbsentContents      = "security-update-notify: original file absent\n"
	dnfAutomaticName       = "automatic.conf"
	dnfStableName          = dnfAutomaticName + ".security-update-notify.bak"
	dnfAbsentName          = dnfAutomaticName + ".security-update-notify.absent.bak"
	dnfDependencyProofName = dnfAutomaticName + ".security-update-notify.dependency-default.bak"
	dnf4AbsentContents     = "security-update-notify: original file absent; engine=dnf4\n"
	dnf5AbsentContents     = "security-update-notify: original file absent; engine=dnf5\n"
	installLockLogical     = "/run/security-update-notify.install.lock"
	runtimeLockLogical     = "/run/security-update-notify.lock"
	systemctlTimeout       = 30 * time.Second
	atRemoveDir            = 0x200
	oPath                  = 0x200000
	uninstallRemovalPrefix = "security-update-notify-remove"
)

var ErrLockBusy = errors.New("lock is busy")

// ExitError carries the stable process status used by the command layer.
type ExitError struct {
	Code int
	Op   string
	Err  error
}

func (e *ExitError) Error() string { return fmt.Sprintf("%s: %v", e.Op, e.Err) }
func (e *ExitError) Unwrap() error { return e.Err }

// ExitCode maps validation/runtime errors to the public CLI contract.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return 1
}

// RunCommand is the external-command boundary used for best-effort systemd
// cleanup. A nil RunCommand uses sysexec.RunTimeout with a 30-second bound.
type RunCommand func(name string, args ...string) sysexec.Result

// LockFunc acquires an exclusive advisory lock and returns its release function.
type LockFunc func(path string, wait time.Duration) (func() error, error)

// Options controls an uninstall operation.
type Options struct {
	// PurgeConfig additionally removes configuration, credentials, state, logs,
	// and upgrade backups, and restores apt/dnf configuration backups.
	PurgeConfig bool

	// RootDir prefixes all absolute installation paths. It defaults to "/" and
	// exists so callers can test the operation without touching the host.
	RootDir string

	// RunCommand overrides external command execution. Filesystem cleanup never
	// shells out; only best-effort systemctl calls use this function. A private
	// RootDir defaults to a no-op runner so tests can never touch host systemd.
	RunCommand RunCommand

	// Lock overrides the install/runtime lock boundary. The default uses flock.
	Lock LockFunc

	// LockWait bounds the runtime barrier. Zero selects 60 seconds.
	LockWait time.Duration

	// EffectiveUID is injectable for root-gate tests. Nil uses os.Geteuid.
	EffectiveUID func() int
}

// Report describes configuration restored during a purge. Paths are returned
// as logical host paths (for example, /etc/apt/...), independent of RootDir.
type Report struct {
	RestoredAPTFrom       string
	RestoredDNFFrom       string
	UsedLegacyDNFBackup   bool
	SystemctlFailureCount int
}

// Uninstall removes the installed runtime. systemctl failures are deliberately
// tolerated so that a missing or unavailable systemd bus cannot leave secrets
// behind. Filesystem failures are joined and returned after all independent
// cleanup operations have been attempted.
func Uninstall(opts Options) (report Report, returnErr error) {
	root, err := normalizeRoot(opts.RootDir)
	if err != nil {
		return Report{}, err
	}
	effectiveUID := opts.EffectiveUID
	if effectiveUID == nil {
		effectiveUID = os.Geteuid
	}
	if effectiveUID() != 0 {
		return Report{}, &ExitError{Code: 1, Op: "require root", Err: errors.New("please run as root")}
	}
	if opts.LockWait == 0 {
		opts.LockWait = 60 * time.Second
	}
	if opts.LockWait < 0 || opts.LockWait > time.Hour {
		return Report{}, &ExitError{Code: 2, Op: "validate lock wait", Err: errors.New("expected 0..3600 seconds")}
	}
	run := opts.RunCommand
	if run == nil {
		if root != string(filepath.Separator) {
			run = func(string, ...string) sysexec.Result { return sysexec.Result{} }
		} else {
			run = func(name string, args ...string) sysexec.Result {
				resolved, resolveErr := commandpath.Resolve(name)
				if resolveErr != nil {
					return sysexec.Result{Code: -1, Err: resolveErr}
				}
				return sysexec.RunTimeout(systemctlTimeout, resolved, args...)
			}
		}
	}
	lock := opts.Lock
	if lock == nil {
		lock = flock
	}
	if err := ensureSafeParent(root, installLockLogical); err != nil {
		return Report{}, fmt.Errorf("validate install lock path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(rooted(root, installLockLogical)), 0o755); err != nil {
		return Report{}, fmt.Errorf("prepare install lock: %w", err)
	}
	unlockInstall, err := lock(rooted(root, installLockLogical), 0)
	if err != nil {
		if errors.Is(err, ErrLockBusy) {
			return Report{}, &ExitError{Code: 75, Op: "acquire install lock", Err: err}
		}
		return Report{}, fmt.Errorf("acquire install lock: %w", err)
	}
	defer func() {
		if unlockErr := unlockInstall(); unlockErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release install lock: %w", unlockErr))
		}
	}()
	if err := ensureSafeParent(root, runtimeLockLogical); err != nil {
		return Report{}, fmt.Errorf("validate runtime lock path: %w", err)
	}
	unlockRuntime, err := lock(rooted(root, runtimeLockLogical), opts.LockWait)
	if err != nil {
		if errors.Is(err, ErrLockBusy) {
			return Report{}, &ExitError{Code: 75, Op: "wait for runtime lock", Err: err}
		}
		return Report{}, fmt.Errorf("wait for runtime lock: %w", err)
	}
	defer func() {
		if unlockErr := unlockRuntime(); unlockErr != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release runtime lock: %w", unlockErr))
		}
	}()
	if err := rejectInterruptedInstallState(root); err != nil {
		return Report{}, &ExitError{Code: 1, Op: "refuse uninstall during interrupted installation", Err: err}
	}

	if result := run("systemctl", "disable", "--now", timerUnit); systemctlCleanupFailed(result, "disable", timerUnit) {
		report.SystemctlFailureCount++
	}
	if result := run("systemctl", "stop", serviceUnit); systemctlCleanupFailed(result, "stop", serviceUnit) {
		report.SystemctlFailureCount++
	}

	var errs []error
	for _, logical := range []string{
		"/etc/systemd/system/security-update-notify.service",
		"/etc/systemd/system/security-update-notify.timer",
		"/etc/systemd/system/security-update-notify.service.d/credentials.conf",
		"/etc/logrotate.d/security-update-notify",
		"/usr/local/sbin/security-update-notify",
	} {
		if err := removeLogicalFile(root, logical); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", logical, err))
		}
	}
	// Match the shell uninstaller's tolerant rmdir: preserve unrelated drop-ins.
	if err := removeLogicalEmptyDirectory(root, "/etc/systemd/system/security-update-notify.service.d"); err != nil {
		errs = append(errs, fmt.Errorf("remove empty service drop-in directory: %w", err))
	}

	if result := run("systemctl", "daemon-reload"); systemctlCleanupFailed(result, "daemon-reload", "") {
		report.SystemctlFailureCount++
	}

	if opts.PurgeConfig {
		purgeErrs := purge(root, &report)
		errs = append(errs, purgeErrs...)
	}
	return report, errors.Join(errs...)
}

func rejectInterruptedInstallState(root string) error {
	const (
		backupRoot = "/var/backups/security-update-notify"
		journal    = "transaction.json"
		maxJournal = 1 << 20
	)
	for _, candidate := range []struct {
		logical     string
		managedRoot string
	}{
		{
			logical:     "/etc/security-update-notify/credentials/.feishu-app-secret.install-recovery",
			managedRoot: "/etc/security-update-notify",
		},
		{logical: "/etc/credstore.encrypted/.security-update-notify-feishu-app-secret.cred.install-recovery"},
	} {
		logical := candidate.logical
		if candidate.managedRoot != "" {
			info, err := logicalEntryInfo(root, candidate.managedRoot)
			if err != nil {
				return fmt.Errorf("inspect managed recovery root %s: %w", candidate.managedRoot, err)
			}
			// The whole managed tree is removed as one no-follow leaf during
			// purge. A non-directory root cannot contain installer-created
			// recovery state and must not make that safe unlink impossible.
			if info == nil || !info.IsDir() {
				continue
			}
			if err := filetrust.ValidateDirectory(info, os.Geteuid(), 0o022); err != nil {
				return fmt.Errorf("unsafe managed recovery root %s: %w", candidate.managedRoot, err)
			}
		}
		exists, err := trustedLogicalEntryExists(root, logical)
		if err != nil {
			return fmt.Errorf("inspect private install recovery %s: %w", logical, err)
		}
		if exists {
			return fmt.Errorf("private install recovery exists at %s; run install again to recover first", logical)
		}
	}

	directory, err := openRestoreDirectory(root, backupRoot)
	if err != nil {
		return fmt.Errorf("inspect install backup root: %w", err)
	}
	if directory == nil {
		return nil
	}
	defer directory.close()
	info, err := directory.file.Stat()
	if err != nil {
		return fmt.Errorf("inspect install backup root: %w", err)
	}
	if err := filetrust.ValidateDirectory(info, directory.ownerUID, 0o022); err != nil {
		return fmt.Errorf("unsafe install backup root: %w", err)
	}
	names, err := directory.names()
	if err != nil {
		return fmt.Errorf("list install backups: %w", err)
	}
	for _, name := range names {
		entry, err := readRemovalEntry(directory.file, name)
		if err != nil {
			return fmt.Errorf("inspect install backup %s: %w", name, err)
		}
		if !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			continue
		}
		backup, err := openRestoreChildDirectory(directory, name)
		if err != nil {
			return fmt.Errorf("open install backup %s: %w", name, err)
		}
		backupInfo, statErr := backup.file.Stat()
		if statErr != nil {
			_ = backup.close()
			return fmt.Errorf("inspect install backup %s: %w", name, statErr)
		}
		if err := filetrust.ValidateDirectory(backupInfo, backup.ownerUID, 0o022); err != nil {
			_ = backup.close()
			return fmt.Errorf("unsafe install backup %s: %w", name, err)
		}
		snapshot, readErr := backup.readTrustedRegular(journal, maxJournal)
		closeErr := backup.close()
		if readErr != nil {
			return fmt.Errorf("inspect installation transaction in %s: %w", name, readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close install backup %s: %w", name, closeErr)
		}
		if snapshot.exists {
			return fmt.Errorf("installation transaction journal exists in %s; run install again to recover first", name)
		}
	}
	return nil
}

func trustedLogicalEntryExists(root, logical string) (bool, error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer parent.Close()
	info, err := parent.Stat()
	if err != nil {
		return false, err
	}
	if err := filetrust.ValidateDirectory(info, os.Geteuid(), 0o022); err != nil {
		return false, fmt.Errorf("unsafe recovery parent %s: %w", filepath.Dir(logical), err)
	}
	_, err = readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func openRestoreChildDirectory(parent *restoreDirectory, name string) (*restoreDirectory, error) {
	if parent == nil || parent.file == nil {
		return nil, errors.New("restore parent directory is unavailable")
	}
	if err := validRestoreEntry(name); err != nil {
		return nil, err
	}
	fd, err := syscall.Openat(
		int(parent.file.Fd()), name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), parent.host(name))
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create child restore directory handle")
	}
	return &restoreDirectory{
		file: directory, hostPath: parent.host(name), ownerUID: parent.ownerUID,
	}, nil
}

func logicalEntryInfo(root, logical string) (os.FileInfo, error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	info, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return info, err
}

func systemctlCleanupFailed(result sysexec.Result, operation, unit string) bool {
	if result.StdoutTruncated || result.StderrTruncated {
		return true
	}
	if result.Code == 0 && result.Err == nil {
		return false
	}
	if result.Err != nil || result.Stdout != "" {
		return true
	}
	diagnostic := strings.TrimSuffix(result.Stderr, "\n")
	diagnostic = strings.TrimSuffix(diagnostic, "\r")
	switch operation {
	case "disable":
		return result.Code != 1 || diagnostic != "Failed to disable unit: Unit file "+unit+" does not exist."
	case "stop":
		return result.Code != 5 || diagnostic != "Failed to stop "+unit+": Unit "+unit+" not loaded."
	default:
		return true
	}
}

func purge(root string, report *Report) []error {
	var errs []error
	for _, logical := range []string{
		"/etc/security-update-notify",
		"/var/lib/security-update-notify",
		"/var/backups/security-update-notify",
	} {
		if err := removeLogicalTree(root, logical); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", logical, err))
		}
	}

	for _, logical := range []string{
		"/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred",
		"/etc/apt/apt.conf.d/52unattended-upgrades-security-update-notify",
		"/etc/apt/apt.conf.d/52unattended-upgrades-local",
		"/etc/needrestart/conf.d/99-security-update-notify-report-only.conf",
	} {
		if err := removeLogicalFile(root, logical); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", logical, err))
		}
	}

	if err := removeLogicalFile(root, "/var/log/security-update-notify.log"); err != nil {
		errs = append(errs, fmt.Errorf("remove security-update-notify log: %w", err))
	}
	if err := removeLogicalFilesWithPrefix(root, "/var/log", "security-update-notify.log.", nil); err != nil {
		errs = append(errs, fmt.Errorf("remove security-update-notify logs: %w", err))
	}

	aptSource, err := restoreAPT(root)
	if aptSource != "" {
		report.RestoredAPTFrom = logicalPath(root, aptSource)
	}
	if err != nil {
		errs = append(errs, err)
	}

	dnfSource, legacy, err := restoreDNF(root)
	if dnfSource != "" {
		report.RestoredDNFFrom = logicalPath(root, dnfSource)
		report.UsedLegacyDNFBackup = legacy
	}
	if err != nil {
		errs = append(errs, err)
	}

	return errs
}

func flock(path string, wait time.Duration) (func() error, error) {
	release, acquired, err := runlock.AcquireWait(path, wait)
	if err != nil {
		return nil, err
	}
	if !acquired {
		return nil, ErrLockBusy
	}
	return func() error { release(); return nil }, nil
}

func logicalPath(root, path string) string {
	if root == string(filepath.Separator) {
		return path
	}
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return string(filepath.Separator) + filepath.ToSlash(rel)
}

// Package uninstaller removes security-update-notify and, when requested,
// restores package-manager configuration captured before installation.
package uninstaller

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
	"github.com/xxvcc/security-update-notify/internal/commandpath"
	"github.com/xxvcc/security-update-notify/internal/dependencyproof"
	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
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

func restoreAPT(root string) (string, error) {
	return restoreAPTWithRemove(root, nil)
}

func restoreAPTWithRemove(root string, beforeRemove func(string) error) (string, error) {
	directory, err := openRestoreDirectory(root, filepath.Dir(aptPeriodicLogical))
	if err != nil {
		return "", fmt.Errorf("open apt configuration directory: %w", err)
	}
	if directory == nil {
		return "", nil
	}
	defer directory.close()
	names, err := directory.names()
	if err != nil {
		return "", fmt.Errorf("list apt backups: %w", err)
	}
	if artifact := unfinishedRestoreArtifact(names); artifact != "" {
		return "", fmt.Errorf("unfinished apt restore transaction requires manual recovery: %s", directory.host(artifact))
	}
	destination := filepath.Base(aptPeriodicLogical)
	fixed := filepath.Base(aptStableLogical)
	marker := filepath.Base(aptAbsentLogical)
	legacyMarker := filepath.Base(aptLegacyAbsent)
	proof := filepath.Base(aptDependencyProof)
	timestamps := append(
		restoreTimestampNames(names, fixed+".", ""),
		restoreTimestampNames(names, destination+".security-update-notify.", ".bak")...,
	)
	timestampSnapshots, err := directory.readSnapshots(timestamps, restoreConfigLimit)
	if err != nil {
		return "", fmt.Errorf("inspect apt timestamp backups: %w", err)
	}

	fixedSnapshot, err := directory.readRegular(fixed, restoreConfigLimit)
	if err != nil {
		return "", fmt.Errorf("inspect apt fixed backup: %w", err)
	}
	markerSnapshot, err := readAPTMarkerSnapshot(directory, marker)
	if err != nil {
		return "", fmt.Errorf("inspect apt absence marker: %w", err)
	}
	legacyMarkerSnapshot, err := readAPTMarkerSnapshot(directory, legacyMarker)
	if err != nil {
		return "", fmt.Errorf("inspect legacy apt absence marker: %w", err)
	}
	proofSnapshot, err := directory.readRegular(proof, 256)
	if err != nil {
		return "", fmt.Errorf("inspect apt dependency proof: %w", err)
	}

	source := ""
	if fixedSnapshot.exists {
		source = fixed
	}
	markerExists := markerSnapshot.exists || legacyMarkerSnapshot.exists
	preserveDependencyDefault := false
	var configSnapshot regularSnapshot
	if source != "" || markerExists {
		configSnapshot, err = directory.readRegular(destination, restoreConfigLimit)
		if err != nil {
			return "", fmt.Errorf("inspect apt configuration: %w", err)
		}
	}
	if source == "" && markerExists {
		managedHistory := aptBackupsContainOnlyManagedPolicyAt(timestampSnapshots, timestamps)
		if proofSnapshot.exists {
			if !configSnapshot.exists {
				return "", errors.New("inspect apt dependency proof: 20auto-upgrades is missing")
			}
			if !bytes.Equal(proofSnapshot.data, dependencyproof.Contents("apt", configSnapshot.data)) {
				return "", errors.New("inspect apt dependency proof: proof does not match 20auto-upgrades")
			}
			preserveDependencyDefault = true
		} else if !managedHistory || (configSnapshot.exists && !bytes.Equal(configSnapshot.data, []byte(aptconfig.Periodic))) {
			return "", errors.New("inspect apt dependency proof: cannot prove that 20auto-upgrades is a SUN-managed file or retained dependency default")
		}
	}

	var committedConfig *regularSnapshot
	if source != "" {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", fmt.Errorf("restore apt configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		restored, err := directory.restoreFile(source, destination, fixedSnapshot, configSnapshot)
		if err != nil {
			return "", fmt.Errorf("restore apt configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		committedConfig = &restored
	} else if markerExists && preserveDependencyDefault {
		committedConfig = &configSnapshot
	} else if markerExists && configSnapshot.exists {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", fmt.Errorf("restore absent apt configuration: %w", err)
		}
		if err := directory.removeValidated(destination, configSnapshot); err != nil {
			return "", fmt.Errorf("restore absent apt configuration: %w", err)
		}
	}

	if markerExists {
		for _, candidate := range []struct {
			name     string
			snapshot regularSnapshot
		}{{marker, markerSnapshot}, {legacyMarker, legacyMarkerSnapshot}} {
			if candidate.snapshot.exists {
				if err := callRestoreRemoveHook(beforeRemove, directory.host(candidate.name)); err != nil {
					return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w", err)
				}
			}
		}
		if committedConfig != nil {
			if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w",
					directory.recordConflict("apt configuration changed before marker commit", err))
			}
		}
		if proofSnapshot.exists {
			if err := directory.revalidate(proof, proofSnapshot, 256); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w",
					directory.recordConflict("apt dependency proof changed before marker commit", err))
			}
		}
		if markerSnapshot.exists {
			if err := directory.removeValidated(marker, markerSnapshot); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w", err)
			}
		}
		if legacyMarkerSnapshot.exists {
			if err := directory.removeValidated(legacyMarker, legacyMarkerSnapshot); err != nil {
				return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w", err)
			}
		}
		if err := directory.sync(); err != nil {
			return sourcePath(directory, source), fmt.Errorf("commit apt baseline restoration: %w",
				directory.recordConflict("sync apt marker commit", err))
		}
	}
	if committedConfig != nil {
		if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
			return sourcePath(directory, source), fmt.Errorf("validate restored apt configuration before cleanup: %w",
				directory.recordConflict("apt configuration changed before cleanup", err))
		}
	}
	metadata := append(append([]string(nil), timestamps...), fixed)
	cleanupSnapshots := make(map[string]regularSnapshot, len(timestampSnapshots)+2)
	for name, snapshot := range timestampSnapshots {
		cleanupSnapshots[name] = snapshot
	}
	cleanupSnapshots[fixed] = fixedSnapshot
	cleanupSnapshots[proof] = proofSnapshot
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, metadata...); err != nil {
		return sourcePath(directory, source), fmt.Errorf("clean apt backups: %w", err)
	}
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, proof); err != nil {
		return sourcePath(directory, source), fmt.Errorf("clean apt dependency proof: %w", err)
	}
	if err := directory.sync(); err != nil {
		return sourcePath(directory, source), fmt.Errorf("sync apt backup cleanup: %w",
			directory.recordConflict("sync apt backup cleanup", err))
	}
	return sourcePath(directory, source), nil
}

func readAPTMarkerSnapshot(directory *restoreDirectory, name string) (regularSnapshot, error) {
	snapshot, err := directory.readRegular(name, 256)
	if err != nil || !snapshot.exists {
		return snapshot, err
	}
	if string(snapshot.data) != aptAbsentContents {
		return regularSnapshot{}, errors.New("absence marker has invalid contents")
	}
	return snapshot, nil
}

func aptBackupsContainOnlyManagedPolicyAt(snapshots map[string]regularSnapshot, names []string) bool {
	for _, candidate := range names {
		snapshot := snapshots[candidate]
		if !bytes.Equal(snapshot.data, []byte(aptconfig.Periodic)) {
			return false
		}
	}
	return true
}

func sourcePath(directory *restoreDirectory, name string) string {
	if name == "" {
		return ""
	}
	return directory.host(name)
}

func callRestoreRemoveHook(hook func(string) error, path string) error {
	if hook == nil {
		return nil
	}
	return hook(path)
}

func removeRestoreSnapshots(directory *restoreDirectory, hook func(string) error, snapshots map[string]regularSnapshot, names ...string) error {
	for _, name := range names {
		snapshot := snapshots[name]
		if !snapshot.exists {
			continue
		}
		if err := callRestoreRemoveHook(hook, directory.host(name)); err != nil {
			return err
		}
		if err := directory.removeValidated(name, snapshot); err != nil {
			return err
		}
	}
	return nil
}

func restoreDNF(root string) (string, bool, error) {
	return restoreDNFWithRemove(root, nil)
}

func restoreDNFWithRemove(root string, beforeRemove func(string) error) (string, bool, error) {
	directory, err := openRestoreDirectory(root, "/etc/dnf")
	if err != nil {
		return "", false, fmt.Errorf("open dnf configuration directory: %w", err)
	}
	if directory == nil {
		return "", false, nil
	}
	defer directory.close()
	names, err := directory.names()
	if err != nil {
		return "", false, fmt.Errorf("list dnf backups: %w", err)
	}
	if artifact := unfinishedRestoreArtifact(names); artifact != "" {
		return "", false, fmt.Errorf("unfinished dnf restore transaction requires manual recovery: %s", directory.host(artifact))
	}
	destination := dnfAutomaticName
	fixed := dnfStableName
	marker := dnfAbsentName
	proof := dnfDependencyProofName
	projectBackups := restoreTimestampNames(names, fixed+".", "")
	projectSnapshots, err := directory.readSnapshots(projectBackups, restoreConfigLimit)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf timestamp backups: %w", err)
	}

	fixedSnapshot, err := directory.readRegular(fixed, restoreConfigLimit)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf fixed backup: %w", err)
	}
	markerEngine, markerSnapshot, err := readDNFMarkerSnapshot(directory, marker)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf absence marker: %w", err)
	}
	proofSnapshot, err := directory.readRegular(proof, 256)
	if err != nil {
		return "", false, fmt.Errorf("inspect dnf dependency proof: %w", err)
	}

	source := ""
	var sourceSnapshot regularSnapshot
	if fixedSnapshot.exists {
		source = fixed
		sourceSnapshot = fixedSnapshot
	}
	markerExists := markerSnapshot.exists
	if source == "" && !markerExists {
		source = oldestSnapshotName(projectBackups, projectSnapshots)
		if source != "" {
			sourceSnapshot = projectSnapshots[source]
		}
	}
	legacy := false
	if source == "" && !markerExists {
		legacyBackups := restoreNamesWithPrefix(names, "automatic.conf.bak.")
		legacySnapshots, err := directory.readSnapshots(legacyBackups, restoreConfigLimit)
		if err != nil {
			return "", false, fmt.Errorf("inspect legacy dnf backups: %w", err)
		}
		source = newestSnapshotName(legacyBackups, legacySnapshots)
		sourceSnapshot = legacySnapshots[source]
		legacy = source != ""
	}

	preserveDependencyDefault := false
	var configSnapshot regularSnapshot
	if source != "" || markerExists {
		configSnapshot, err = directory.readRegular(destination, restoreConfigLimit)
		if err != nil {
			return "", false, fmt.Errorf("inspect dnf configuration: %w", err)
		}
	}
	// A fixed backup is the authoritative pre-SUN baseline. Dependency proof is
	// only a recovery path for an originally absent configuration when no fixed
	// baseline was durably promoted before an interrupted transaction.
	if markerExists && source == "" {
		if proofSnapshot.exists {
			if markerEngine != "dnf4" {
				return "", false, errors.New("inspect dnf dependency proof: DNF5 absence marker conflicts with DNF4 dependency proof")
			}
			if !configSnapshot.exists {
				return "", false, errors.New("inspect dnf dependency proof: automatic.conf is missing")
			}
			if !bytes.Equal(proofSnapshot.data, dnfconfig.DependencyDefaultProof(configSnapshot.data)) {
				return "", false, errors.New("inspect dnf dependency proof: proof does not match automatic.conf")
			}
			preserveDependencyDefault = true
		} else if markerEngine == "dnf4" && configSnapshot.exists {
			return "", false, errors.New("inspect dnf dependency proof: cannot prove that automatic.conf is a retained DNF4 dependency default")
		}
	}

	var committedConfig *regularSnapshot
	if preserveDependencyDefault {
		source = ""
		legacy = false
		committedConfig = &configSnapshot
	} else if source != "" {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", legacy, fmt.Errorf("restore dnf configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		restored, err := directory.restoreFile(source, destination, sourceSnapshot, configSnapshot)
		if err != nil {
			return "", legacy, fmt.Errorf("restore dnf configuration from %s: %w", logicalPath(root, directory.host(source)), err)
		}
		committedConfig = &restored
	} else if markerExists && configSnapshot.exists {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(destination)); err != nil {
			return "", false, fmt.Errorf("restore absent dnf configuration: %w", err)
		}
		if err := directory.removeValidated(destination, configSnapshot); err != nil {
			return "", false, fmt.Errorf("restore absent dnf configuration: %w", err)
		}
	}

	// Legacy backups may belong to another administrator. Preserve them, as the
	// shell uninstaller does, and remove only project-owned backups.
	if markerExists {
		if err := callRestoreRemoveHook(beforeRemove, directory.host(marker)); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w", err)
		}
		if committedConfig != nil {
			if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
				return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w",
					directory.recordConflict("dnf configuration changed before marker commit", err))
			}
		}
		if proofSnapshot.exists {
			if err := directory.revalidate(proof, proofSnapshot, 256); err != nil {
				return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w",
					directory.recordConflict("dnf dependency proof changed before marker commit", err))
			}
		}
		if err := directory.removeValidated(marker, markerSnapshot); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w", err)
		}
		if err := directory.sync(); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("commit dnf baseline restoration: %w",
				directory.recordConflict("sync dnf marker commit", err))
		}
	}
	if committedConfig != nil {
		if err := directory.revalidate(destination, *committedConfig, restoreConfigLimit); err != nil {
			return sourcePath(directory, source), legacy, fmt.Errorf("validate restored dnf configuration before cleanup: %w",
				directory.recordConflict("dnf configuration changed before cleanup", err))
		}
	}
	metadata := append(append([]string(nil), projectBackups...), fixed)
	cleanupSnapshots := make(map[string]regularSnapshot, len(projectSnapshots)+2)
	for name, snapshot := range projectSnapshots {
		cleanupSnapshots[name] = snapshot
	}
	cleanupSnapshots[fixed] = fixedSnapshot
	cleanupSnapshots[proof] = proofSnapshot
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, metadata...); err != nil {
		return sourcePath(directory, source), legacy, fmt.Errorf("clean dnf backups: %w", err)
	}
	if err := removeRestoreSnapshots(directory, beforeRemove, cleanupSnapshots, proof); err != nil {
		return sourcePath(directory, source), legacy, fmt.Errorf("clean dnf dependency proof: %w", err)
	}
	if err := directory.sync(); err != nil {
		return sourcePath(directory, source), legacy, fmt.Errorf("sync dnf backup cleanup: %w",
			directory.recordConflict("sync dnf backup cleanup", err))
	}
	return sourcePath(directory, source), legacy, nil
}

func readDNFMarkerSnapshot(directory *restoreDirectory, name string) (string, regularSnapshot, error) {
	snapshot, err := directory.readRegular(name, 256)
	if err != nil || !snapshot.exists {
		return "", snapshot, err
	}
	switch string(snapshot.data) {
	case dnf4AbsentContents:
		return "dnf4", snapshot, nil
	case dnf5AbsentContents:
		return "dnf5", snapshot, nil
	default:
		return "", regularSnapshot{}, errors.New("absence marker has invalid contents")
	}
}

func normalizeRoot(root string) (string, error) {
	if root == "" {
		root = string(filepath.Separator)
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("uninstaller RootDir must be absolute: %q", root)
	}
	clean := filepath.Clean(root)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("resolve uninstaller RootDir: %w", err)
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("inspect uninstaller RootDir: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("uninstaller RootDir must be a real directory: %q", root)
	}
	return resolved, nil
}

func rooted(root, logical string) string {
	return filepath.Join(root, strings.TrimPrefix(logical, string(filepath.Separator)))
}

// safePath rejects symlinked ancestors beneath RootDir before non-recursive
// operations. The leaf may be a symlink only when includeLeaf is false, in
// which case unlink removes the link itself rather than following it.
func safePath(root, logical string, includeLeaf bool) (string, error) {
	if !filepath.IsAbs(logical) {
		return "", fmt.Errorf("logical path must be absolute: %q", logical)
	}
	clean := filepath.Clean(logical)
	path := rooted(root, clean)
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes RootDir: %q", logical)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	limit := len(parts)
	if !includeLeaf && limit > 0 {
		limit--
	}
	current := root
	for index := 0; index < limit; index++ {
		if parts[index] == "" || parts[index] == "." {
			continue
		}
		current = filepath.Join(current, parts[index])
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("symlinked path component is forbidden: %s", logical)
		}
		if index < limit-1 && !info.IsDir() {
			return "", fmt.Errorf("non-directory path component: %s", logical)
		}
	}
	return path, nil
}

func ensureSafeParent(root, logical string) error {
	_, err := safePath(root, logical, false)
	return err
}

func removeLogicalFile(root, logical string) error {
	return removeLogicalFileWithHook(root, logical, nil)
}

func removeLogicalFileWithHook(root, logical string, beforeClaim func() error) error {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := cleanupUninstallRemovalArtifacts(parent); err != nil {
		return fmt.Errorf("recover interrupted file removal: %w", err)
	}
	expected, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if expected.IsDir() {
		return fmt.Errorf("refusing to remove directory as a file: %s", logical)
	}
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return err
		}
	}
	return removeValidatedEntryAt(parent, name, expected, removalLeaf)
}

func removeLogicalEmptyDirectory(root, logical string) error {
	return removeLogicalEmptyDirectoryWithHook(root, logical, nil)
}

func removeLogicalEmptyDirectoryWithHook(root, logical string, beforeClaim func() error) error {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := cleanupUninstallRemovalArtifacts(parent); err != nil {
		return fmt.Errorf("recover interrupted directory removal: %w", err)
	}
	expected, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !expected.IsDir() {
		return nil
	}
	empty, err := removalDirectoryEmpty(parent, name)
	if err != nil || !empty {
		return err
	}
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return err
		}
	}
	return removeValidatedEntryAt(parent, name, expected, removalEmptyDirectory)
}

// removeLogicalTree resolves the parent beneath an opened RootDir descriptor
// and recursively removes entries relative to directory descriptors. Unlike a
// safePath check followed by os.RemoveAll, there is no pathname gap in which a
// checked ancestor can be replaced by a symlink to another tree.
func removeLogicalTree(root, logical string) error {
	return removeLogicalTreeWithHook(root, logical, nil)
}

func removeLogicalTreeWithHook(root, logical string, beforeClaim func() error) error {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := cleanupUninstallRemovalArtifacts(parent); err != nil {
		return fmt.Errorf("recover interrupted tree removal: %w", err)
	}
	return removeAllAtWithHook(parent, name, beforeClaim)
}

func openLogicalParent(root, logical string) (*os.File, string, error) {
	if !filepath.IsAbs(logical) {
		return nil, "", fmt.Errorf("logical path must be absolute: %q", logical)
	}
	clean := filepath.Clean(logical)
	if clean == string(filepath.Separator) {
		return nil, "", errors.New("refusing to remove uninstaller RootDir")
	}
	current, err := openRootHandle(root)
	if err != nil {
		return nil, "", err
	}
	walked := ""
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Dir(clean), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		walked += string(filepath.Separator) + component
		physical := component
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil && walked == "/usr/local/sbin" && validLocalSbinAliasAt(current, component) {
			physical = "bin"
			nextFD, openErr = syscall.Openat(
				int(current.Fd()), "bin",
				oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
				0,
			)
		}
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, "", fmt.Errorf("symlinked path component or non-directory component is forbidden: %s", logical)
			}
			return nil, "", openErr
		}
		next := os.NewFile(uintptr(nextFD), filepath.Join(current.Name(), physical))
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, "", errors.New("could not create uninstall directory handle")
		}
		_ = current.Close()
		current = next
	}
	return current, filepath.Base(clean), nil
}

func validLocalSbinAliasAt(parent *os.File, component string) bool {
	componentPointer, err := syscall.BytePtrFromString(component)
	if err != nil {
		return false
	}
	var target [4]byte
	result, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		parent.Fd(), uintptr(unsafe.Pointer(componentPointer)), uintptr(unsafe.Pointer(&target[0])), uintptr(len(target)), 0, 0,
	)
	return errno == 0 && int(result) == len("bin") && string(target[:result]) == "bin"
}

func openRootHandle(root string) (*os.File, error) {
	fd, err := syscall.Open(
		string(filepath.Separator),
		oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), string(filepath.Separator))
	if current == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create uninstaller root handle")
	}
	if root == string(filepath.Separator) {
		return current, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, fmt.Errorf("uninstaller RootDir contains a symlinked or non-directory component: %s", root)
			}
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), filepath.Join(current.Name(), component))
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, errors.New("could not create uninstaller root component handle")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

type removalMode uint8

const (
	removalLeaf removalMode = iota
	removalEmptyDirectory
	removalTree
)

func readRemovalEntry(parent *os.File, name string) (os.FileInfo, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return nil, fmt.Errorf("invalid removal entry: %q", name)
	}
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	entry := os.NewFile(uintptr(fd), name)
	if entry == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create uninstall entry handle")
	}
	info, statErr := entry.Stat()
	closeErr := entry.Close()
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return info, nil
}

func sameRemovalEntry(left, right os.FileInfo) bool {
	if !sameRemovalIdentity(left, right) ||
		left.Size() != right.Size() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	return true
}

func sameRemovalIdentity(left, right os.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK == rightOK && (!leftOK || leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid)
}

func newRemovalPlaceholder(parent *os.File, directory bool) (string, os.FileInfo, error) {
	return newRemovalPlaceholderWithClose(parent, directory, nil)
}

func newRemovalPlaceholderWithClose(parent *os.File, directory bool, closePlaceholder func(*os.File, string) error) (string, os.FileInfo, error) {
	for range restoreTemporaryAttempts {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, err
		}
		name := fmt.Sprintf(".%s.%s", uninstallRemovalPrefix, hex.EncodeToString(random))
		var placeholder *os.File
		if directory {
			err := syscall.Mkdirat(int(parent.Fd()), name, 0o700)
			if errors.Is(err, os.ErrExist) {
				continue
			}
			if err != nil {
				return "", nil, err
			}
			placeholder, err = openRemovalDirectory(parent, name)
			if err != nil {
				return name, nil, fmt.Errorf("open uninstall quarantine retained at %s: %w", removalEntryPath(parent, name), err)
			}
		} else {
			fd, err := syscall.Openat(
				int(parent.Fd()), name,
				syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
				0o600,
			)
			if errors.Is(err, os.ErrExist) {
				continue
			}
			if err != nil {
				return "", nil, err
			}
			placeholder = os.NewFile(uintptr(fd), removalEntryPath(parent, name))
			if placeholder == nil {
				_ = syscall.Close(fd)
				return name, nil, errors.New("could not create uninstall quarantine handle; entry retained at " + removalEntryPath(parent, name))
			}
		}
		info, statErr := placeholder.Stat()
		var closeErr error
		if closePlaceholder == nil {
			closeErr = placeholder.Close()
		} else {
			closeErr = closePlaceholder(placeholder, name)
		}
		initializationErr := errors.Join(statErr, closeErr)
		if initializationErr == nil {
			return name, info, nil
		}
		if info == nil {
			return name, nil, fmt.Errorf("initialize uninstall quarantine retained at %s: %w", removalEntryPath(parent, name), initializationErr)
		}
		if cleanupErr := cleanupRemovalPlaceholder(parent, name, info); cleanupErr != nil {
			return name, info, errors.Join(
				fmt.Errorf("initialize uninstall quarantine retained at %s: %w", removalEntryPath(parent, name), initializationErr),
				cleanupErr,
			)
		}
		return name, info, initializationErr
	}
	return "", nil, errors.New("could not create uninstall quarantine entry")
}

func cleanupUninstallRemovalArtifacts(parent *os.File) error {
	directory, err := openRemovalDirectory(parent, ".")
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	var errs []error
	for _, entry := range entries {
		if !isRestoreTemporaryName(entry.Name(), uninstallRemovalPrefix) {
			continue
		}
		expected, err := readRemovalEntry(parent, entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil {
			err = removeValidatedEntryAt(parent, entry.Name(), expected, removalTree)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("remove interrupted quarantine %s: %w", removalEntryPath(parent, entry.Name()), err))
		}
	}
	return errors.Join(errs...)
}

func cleanupRemovalPlaceholder(parent *os.File, name string, expected os.FileInfo) error {
	current, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !sameRemovalEntry(current, expected) {
		return errors.Join(errors.New("uninstall quarantine placeholder changed; retained at "+removalEntryPath(parent, name)), err)
	}
	if expected.IsDir() {
		return unlinkRemovalDirectory(parent, name, expected)
	}
	if err := syscall.Unlinkat(int(parent.Fd()), name); err != nil {
		return fmt.Errorf("remove uninstall quarantine placeholder retained at %s: %w", removalEntryPath(parent, name), err)
	}
	return nil
}

func restoreUnexpectedClaim(parent *os.File, quarantine, name string, cause error) error {
	restoreErr := renameRestoreEntry(int(parent.Fd()), quarantine, name, restoreRenameNoReplace)
	if restoreErr == nil {
		return errors.Join(errors.New("entry changed before removal; concurrent entry restored"), cause)
	}
	return errors.Join(
		errors.New("entry changed before removal; concurrent entry retained at "+removalEntryPath(parent, quarantine)),
		cause, restoreErr,
	)
}

func removeValidatedEntryAt(parent *os.File, name string, expected os.FileInfo, mode removalMode) (returnErr error) {
	return removeValidatedEntryAtWithHook(parent, name, expected, mode, nil)
}

func removeValidatedEntryAtWithHook(parent *os.File, name string, expected os.FileInfo, mode removalMode, beforeDelete func(string) error) (returnErr error) {
	var claimedDirectory *os.File
	if expected.IsDir() {
		var err error
		claimedDirectory, err = openRemovalDirectory(parent, name)
		if err != nil {
			return errors.Join(errors.New("entry changed before removal: validated directory changed before claim"), err)
		}
		info, err := claimedDirectory.Stat()
		if err != nil || !sameRemovalEntry(info, expected) {
			_ = claimedDirectory.Close()
			return errors.Join(errors.New("entry changed before removal: validated directory changed before claim"), err)
		}
		defer func() {
			returnErr = errors.Join(returnErr, claimedDirectory.Close())
		}()
	}
	quarantine, placeholder, err := newRemovalPlaceholder(parent, expected.IsDir())
	if err != nil {
		return err
	}
	if err := syscall.Renameat(int(parent.Fd()), name, int(parent.Fd()), quarantine); err != nil {
		cleanupErr := cleanupRemovalPlaceholder(parent, quarantine, placeholder)
		if errors.Is(err, os.ErrNotExist) {
			return cleanupErr
		}
		return errors.Join(fmt.Errorf("claim validated entry; quarantine retained at %s: %w", removalEntryPath(parent, quarantine), err), cleanupErr)
	}
	claimed, readErr := readRemovalEntry(parent, quarantine)
	if readErr != nil || !sameRemovalEntry(claimed, expected) {
		return restoreUnexpectedClaim(parent, quarantine, name, readErr)
	}
	if beforeDelete != nil {
		if err := beforeDelete(quarantine); err != nil {
			return fmt.Errorf("remove claimed entry retained at %s: %w", removalEntryPath(parent, quarantine), err)
		}
	}

	switch mode {
	case removalLeaf:
		if claimed.IsDir() {
			return restoreUnexpectedClaim(parent, quarantine, name, errors.New("validated leaf became a directory"))
		}
		if err := syscall.Unlinkat(int(parent.Fd()), quarantine); err != nil {
			return fmt.Errorf("remove claimed entry retained at %s: %w", removalEntryPath(parent, quarantine), err)
		}
		return nil
	case removalEmptyDirectory:
		if !claimed.IsDir() || claimedDirectory == nil {
			return restoreUnexpectedClaim(parent, quarantine, name, errors.New("validated directory changed type"))
		}
		empty, err := removalDirectoryEmptyOpened(claimedDirectory)
		if err != nil || !empty {
			if err == nil {
				err = errors.New("validated empty directory gained an entry")
			}
			return restoreUnexpectedClaim(parent, quarantine, name, err)
		}
		return unlinkRemovalDirectory(parent, quarantine, expected)
	case removalTree:
		if !claimed.IsDir() {
			if err := syscall.Unlinkat(int(parent.Fd()), quarantine); err != nil {
				return fmt.Errorf("remove claimed entry retained at %s: %w", removalEntryPath(parent, quarantine), err)
			}
			return nil
		}
		if claimedDirectory == nil {
			return restoreUnexpectedClaim(parent, quarantine, name, errors.New("validated directory handle is unavailable"))
		}
		if err := removeClaimedTree(claimedDirectory); err != nil {
			return fmt.Errorf("remove quarantined tree retained at %s: %w", removalEntryPath(parent, quarantine), err)
		}
		return unlinkRemovalDirectory(parent, quarantine, expected)
	default:
		return errors.New("invalid uninstall removal mode; claimed entry retained at " + removalEntryPath(parent, quarantine))
	}
}

func openRemovalDirectory(parent *os.File, name string) (*os.File, error) {
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), removalEntryPath(parent, name))
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create recursive uninstall directory handle")
	}
	return directory, nil
}

func removalDirectoryEmpty(parent *os.File, name string) (bool, error) {
	directory, err := openRemovalDirectory(parent, name)
	if err != nil {
		return false, err
	}
	empty, readErr := removalDirectoryEmptyOpened(directory)
	closeErr := directory.Close()
	return empty, errors.Join(readErr, closeErr)
}

func removalDirectoryEmptyOpened(directory *os.File) (bool, error) {
	entries, err := directory.ReadDir(1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return len(entries) == 0, nil
}

func removeClaimedTree(directory *os.File) error {
	entries, readErr := directory.ReadDir(-1)
	if readErr == nil {
		for _, entry := range entries {
			if err := removeAllAt(directory, entry.Name()); err != nil {
				readErr = err
				break
			}
		}
	}
	return readErr
}

func unlinkRemovalDirectory(parent *os.File, name string, expected os.FileInfo) error {
	current, err := readRemovalEntry(parent, name)
	if err != nil || !sameRemovalIdentity(current, expected) {
		return errors.Join(errors.New("claimed directory changed before removal; retained at "+removalEntryPath(parent, name)), err)
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_UNLINKAT,
		parent.Fd(), uintptr(unsafe.Pointer(namePointer)), atRemoveDir, 0, 0, 0,
	)
	if errno != 0 && !errors.Is(errno, os.ErrNotExist) {
		return fmt.Errorf("remove claimed directory retained at %s: %w", removalEntryPath(parent, name), errno)
	}
	return nil
}

func removalEntryPath(parent *os.File, name string) string {
	if parent == nil || parent.Name() == "" {
		return name
	}
	return filepath.Join(parent.Name(), name)
}

func removeAllAt(parent *os.File, name string) error {
	return removeAllAtWithHook(parent, name, nil)
}

func removeAllAtWithHook(parent *os.File, name string, beforeClaim func() error) error {
	expected, err := readRemovalEntry(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return err
		}
	}
	return removeValidatedEntryAt(parent, name, expected, removalTree)
}

func removeLogicalFilesWithPrefix(root, directoryLogical, prefix string, beforeClaim func(string) error) error {
	parent, name, err := openLogicalParent(root, directoryLogical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	directory, err := openRemovalDirectory(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := cleanupUninstallRemovalArtifacts(directory); err != nil {
		_ = directory.Close()
		return fmt.Errorf("recover interrupted prefixed-file removal: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr != nil {
		_ = directory.Close()
		return readErr
	}
	var errs []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		expected, err := readRemovalEntry(directory, entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && expected.IsDir() {
			err = fmt.Errorf("refusing to remove directory as a file: %s", filepath.Join(directoryLogical, entry.Name()))
		}
		if err == nil && beforeClaim != nil {
			err = beforeClaim(entry.Name())
		}
		if err == nil {
			err = removeValidatedEntryAt(directory, entry.Name(), expected, removalLeaf)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errors.Join(errs...), directory.Close())
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

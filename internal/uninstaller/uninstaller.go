// Package uninstaller removes security-update-notify and, when requested,
// restores package-manager configuration captured before installation.
package uninstaller

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	runlock "github.com/xxvcc/security-update-notify/internal/lock"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

const (
	timerUnit          = "security-update-notify.timer"
	serviceUnit        = "security-update-notify.service"
	installLockLogical = "/run/security-update-notify.install.lock"
	runtimeLockLogical = "/run/security-update-notify.lock"
	systemctlTimeout   = 30 * time.Second
	atRemoveDir        = 0x200
	oPath              = 0x200000
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
func Uninstall(opts Options) (Report, error) {
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
				return sysexec.RunTimeout(systemctlTimeout, name, args...)
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
	defer unlockInstall()
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
	defer unlockRuntime()

	var report Report
	if result := run("systemctl", "disable", "--now", timerUnit); result.Code != 0 || result.Err != nil {
		report.SystemctlFailureCount++
	}
	if result := run("systemctl", "stop", serviceUnit); result.Code != 0 || result.Err != nil {
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
	if path, pathErr := safePath(root, "/etc/systemd/system/security-update-notify.service.d", false); pathErr == nil {
		_ = os.Remove(path)
	} else {
		errs = append(errs, pathErr)
	}

	if result := run("systemctl", "daemon-reload"); result.Code != 0 || result.Err != nil {
		report.SystemctlFailureCount++
	}

	if opts.PurgeConfig {
		purgeErrs := purge(root, &report)
		errs = append(errs, purgeErrs...)
	}
	return report, errors.Join(errs...)
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
	logDir, pathErr := safePath(root, "/var/log", true)
	var rotatedLogs []string
	var err error
	if pathErr == nil {
		rotatedLogs, err = filesWithPrefix(logDir, "security-update-notify.log.")
	} else {
		err = pathErr
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("list security-update-notify logs: %w", err))
	} else if err := removeFiles(rotatedLogs...); err != nil {
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
	fixed, err := safePath(root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak", true)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("validate apt fixed backup: %w", err)
	}
	if fixed == "" {
		fixed = rooted(root, "/etc/apt/apt.conf.d/20auto-upgrades.security-update-notify.bak")
	}
	destination, err := safePath(root, "/etc/apt/apt.conf.d/20auto-upgrades", false)
	if err != nil {
		return "", fmt.Errorf("validate apt destination: %w", err)
	}
	if _, err := safePath(root, "/etc/apt/apt.conf.d", true); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("validate apt directory: %w", err)
	}
	timestamps, err := filesWithPrefix(filepath.Dir(fixed), filepath.Base(fixed)+".")
	if err != nil {
		return "", fmt.Errorf("list apt timestamp backups: %w", err)
	}

	var source string
	if exists, err := regularFileExists(fixed); err != nil {
		return "", fmt.Errorf("inspect apt fixed backup: %w", err)
	} else if exists {
		source = fixed
	}

	if source != "" {
		if err := restoreFile(source, destination); err != nil {
			return "", fmt.Errorf("restore apt configuration from %s: %w", logicalPath(root, source), err)
		}
	}
	if err := removeFiles(append([]string{fixed}, timestamps...)...); err != nil {
		return source, fmt.Errorf("clean apt backups: %w", err)
	}
	return source, nil
}

func restoreDNF(root string) (string, bool, error) {
	dnfDir, err := safePath(root, "/etc/dnf", true)
	if errors.Is(err, os.ErrNotExist) {
		dnfDir = rooted(root, "/etc/dnf")
	} else if err != nil {
		return "", false, fmt.Errorf("validate dnf directory: %w", err)
	}
	destination := filepath.Join(dnfDir, "automatic.conf")
	projectBackups, err := filesWithPrefix(dnfDir, "automatic.conf.security-update-notify.bak.")
	if err != nil {
		return "", false, fmt.Errorf("list dnf backups: %w", err)
	}

	source, err := newestRegular(projectBackups)
	if err != nil {
		return "", false, fmt.Errorf("select dnf backup: %w", err)
	}
	legacy := false
	if source == "" {
		legacyBackups, listErr := filesWithPrefix(dnfDir, "automatic.conf.bak.")
		if listErr != nil {
			return "", false, fmt.Errorf("list legacy dnf backups: %w", listErr)
		}
		source, err = newestRegular(legacyBackups)
		if err != nil {
			return "", false, fmt.Errorf("select legacy dnf backup: %w", err)
		}
		legacy = source != ""
	}

	if source != "" {
		if err := restoreFile(source, destination); err != nil {
			return "", legacy, fmt.Errorf("restore dnf configuration from %s: %w", logicalPath(root, source), err)
		}
	}
	// Legacy backups may belong to another administrator. Preserve them, as the
	// shell uninstaller does, and remove only project-owned backups.
	if err := removeFiles(projectBackups...); err != nil {
		return source, legacy, fmt.Errorf("clean dnf backups: %w", err)
	}
	return source, legacy, nil
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
	path, err := safePath(root, logical, false)
	if err != nil {
		return err
	}
	return removeFile(path)
}

// removeLogicalTree resolves the parent beneath an opened RootDir descriptor
// and recursively removes entries relative to directory descriptors. Unlike a
// safePath check followed by os.RemoveAll, there is no pathname gap in which a
// checked ancestor can be replaced by a symlink to another tree.
func removeLogicalTree(root, logical string) error {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	return removeAllAt(parent, name)
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
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Dir(clean), string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
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
				return nil, "", fmt.Errorf("symlinked path component or non-directory component is forbidden: %s", logical)
			}
			return nil, "", openErr
		}
		next := os.NewFile(uintptr(nextFD), component)
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
		next := os.NewFile(uintptr(nextFD), component)
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

func removeAllAt(parent *os.File, name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("invalid recursive removal entry: %q", name)
	}
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
			err = syscall.Unlinkat(int(parent.Fd()), name)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = syscall.Close(fd)
		return errors.New("could not create recursive uninstall directory handle")
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr == nil {
		for _, entry := range entries {
			if err := removeAllAt(directory, entry.Name()); err != nil {
				readErr = err
				break
			}
		}
	}
	closeErr := directory.Close()
	if readErr != nil {
		return readErr
	}
	if closeErr != nil {
		return closeErr
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
		return errno
	}
	return nil
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

func regularFileExists(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("backup is not a regular file: %s", path)
	}
	return true, nil
}

func newestRegular(paths []string) (string, error) {
	type candidate struct {
		path  string
		mtime time.Time
	}
	var newest candidate
	found := false
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return "", err
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("backup is not a regular file: %s", path)
		}
		current := candidate{path: path, mtime: info.ModTime()}
		if !found || current.mtime.After(newest.mtime) || current.mtime.Equal(newest.mtime) && current.path > newest.path {
			newest = current
			found = true
		}
	}
	if !found {
		return "", nil
	}
	return newest.path, nil
}

func restoreFile(source, destination string) (retErr error) {
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !sourceInfo.Mode().IsRegular() {
		return fmt.Errorf("backup is not a regular file")
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	openedInfo, err := in.Stat()
	if err != nil {
		return err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(sourceInfo, openedInfo) {
		return fmt.Errorf("backup changed while opening")
	}

	tmp, err := os.CreateTemp(filepath.Dir(destination), ".security-update-notify-restore-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		if retErr != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		_ = tmp.Close()
		return err
	}
	if stat, ok := sourceInfo.Sys().(*syscall.Stat_t); ok {
		if err := tmp.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	// chown can clear set-ID bits, so apply the source mode afterwards.
	if err := tmp.Chmod(sourceInfo.Mode()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := copyXattrs(source, tmpPath); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chtimes(tmpPath, sourceInfo.ModTime(), sourceInfo.ModTime()); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, destination); err != nil {
		return err
	}
	return syncDir(filepath.Dir(destination))
}

func copyXattrs(source, target string) error {
	size, err := syscall.Listxattr(source, nil)
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("list backup xattrs: %w", err)
	}
	if size == 0 {
		return nil
	}
	if size > 1<<20 {
		return fmt.Errorf("backup xattr name list exceeds 1 MiB")
	}
	names := make([]byte, size)
	n, err := syscall.Listxattr(source, names)
	if err != nil {
		return fmt.Errorf("read backup xattr names: %w", err)
	}
	for _, nameBytes := range strings.Split(string(names[:n]), "\x00") {
		if nameBytes == "" {
			continue
		}
		valueSize, err := syscall.Getxattr(source, nameBytes, nil)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read backup xattr %s: %w", nameBytes, err)
		}
		if valueSize > 1<<20 {
			return fmt.Errorf("backup xattr %s exceeds 1 MiB", nameBytes)
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			n, err = syscall.Getxattr(source, nameBytes, value)
			if err != nil {
				return fmt.Errorf("read backup xattr %s: %w", nameBytes, err)
			}
			value = value[:n]
		}
		if err := syscall.Setxattr(target, nameBytes, value, 0); err != nil {
			return fmt.Errorf("restore backup xattr %s: %w", nameBytes, err)
		}
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func removeFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// os.Remove would also remove an empty directory, unlike rm -f. Refuse that
	// scope expansion while still allowing a symlink (including one to a dir).
	if info.IsDir() {
		return fmt.Errorf("refusing to remove directory as a file: %s", path)
	}
	// unlink(2) cannot remove a directory, including if the path is swapped
	// between Lstat and this call.
	err = syscall.Unlink(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func filesWithPrefix(dir, prefix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, nil
}

func removeFiles(paths ...string) error {
	var errs []error
	for _, path := range paths {
		if err := removeFile(path); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

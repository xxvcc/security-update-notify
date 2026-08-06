// Package lock 用 flock 实现运行时的单实例互斥，复刻 `exec 9>LOCK_FILE; flock -n 9 || exit 0`：
// 非阻塞抢锁，抢不到（已有实例在跑）时返回 acquired=false，调用方据此静默退出 0。
//
// Package lock provides the runtime's single-instance mutex via flock, reproducing
// `exec 9>LOCK_FILE; flock -n 9 || exit 0`: a non-blocking acquire that returns acquired=false when
// another instance holds it, so the caller exits 0 silently.
package lock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const oPath = 0x200000

// Acquire 非阻塞地对 path 加独占 flock。成功返回 release（释放并关闭 fd）与 acquired=true；已被占用
// 返回 acquired=false（release 为 nil，err 为 nil）；其它错误经 err 返回。
func Acquire(path string) (release func(), acquired bool, err error) {
	return AcquireWait(path, 0)
}

// AcquireWait waits up to timeout for the lock. A zero timeout performs one non-blocking attempt.
// The caller decides whether a timeout is a quiet no-op or an explicit failure.
func AcquireWait(path string, timeout time.Duration) (release func(), acquired bool, err error) {
	f, parent, name, err := openLockFile(path)
	if err != nil {
		return nil, false, err
	}
	closeHandles := func() {
		_ = parent.Close()
		_ = f.Close()
	}
	uid := os.Geteuid()
	if _, err := validateLockFile(f, uid); err != nil {
		closeHandles()
		return nil, false, err
	}
	if err := f.Chmod(0o600); err != nil {
		closeHandles()
		return nil, false, err
	}
	// Revalidate after the only metadata mutation. This catches a hard link
	// added between the first fstat and fchmod instead of returning a lock whose
	// permissions were also changed through another name.
	if _, err := validateLockFile(f, uid); err != nil {
		closeHandles()
		return nil, false, err
	}
	deadline := time.Now().Add(timeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			closeHandles()
			return nil, false, err
		}
		remaining := time.Until(deadline)
		if timeout <= 0 || remaining <= 0 {
			closeHandles()
			return nil, false, nil
		}
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		time.Sleep(remaining)
	}
	// A waiter may have opened the old inode before another process replaced the
	// pathname. Bind the acquired flock back to the still-current directory
	// entry before reporting success.
	if err := validateLockPath(parent, name, f, uid); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeHandles()
		return nil, false, err
	}
	if err := parent.Close(); err != nil {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
		return nil, false, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true, nil
}

// AcquireInherited validates and adopts an already-open descriptor for path.
// It is used by installer child checks while the parent keeps the same open
// file description locked. The returned release closes only the child's
// descriptor: issuing LOCK_UN here would also release the parent's flock.
func AcquireInherited(path string, descriptor int) (release func(), err error) {
	if descriptor < 3 {
		return nil, fmt.Errorf("invalid inherited runtime lock descriptor: %d", descriptor)
	}
	inherited := os.NewFile(uintptr(descriptor), path)
	if inherited == nil {
		return nil, errors.New("could not create inherited runtime lock handle")
	}
	fail := func(err error) (func(), error) {
		_ = inherited.Close()
		return nil, err
	}

	uid := os.Geteuid()
	info, err := validateLockFile(inherited, uid)
	if err != nil {
		return fail(fmt.Errorf("validate inherited runtime lock: %w", err))
	}
	if info.Mode().Perm() != 0o600 {
		return fail(fmt.Errorf("inherited runtime lock has permissions %#o, want 0600", info.Mode().Perm()))
	}

	current, parent, name, err := openLockFile(path)
	if err != nil {
		return fail(fmt.Errorf("open canonical runtime lock: %w", err))
	}
	_ = current.Close()
	defer parent.Close()
	if err := validateLockPath(parent, name, inherited, uid); err != nil {
		return fail(fmt.Errorf("validate inherited runtime lock path: %w", err))
	}
	if err := syscall.Flock(descriptor, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fail(fmt.Errorf("validate inherited runtime lock ownership: %w", err))
	}
	if err := validateLockPath(parent, name, inherited, uid); err != nil {
		return fail(fmt.Errorf("revalidate inherited runtime lock path: %w", err))
	}
	return func() { _ = inherited.Close() }, nil
}

// openLockFile resolves every parent component through directory descriptors
// with O_NOFOLLOW, then opens the leaf relative to the final descriptor. A
// concurrent ancestor rename cannot redirect the open through a symlink.
func openLockFile(path string) (*os.File, *os.File, string, error) {
	clean := filepath.Clean(path)
	name := filepath.Base(clean)
	if clean == string(filepath.Separator) || name == "." || name == ".." {
		return nil, nil, "", fmt.Errorf("invalid runtime lock path: %q", path)
	}

	start := "."
	directory := filepath.Dir(clean)
	if filepath.IsAbs(clean) {
		start = string(filepath.Separator)
		directory = strings.TrimPrefix(directory, string(filepath.Separator))
	}
	fd, err := syscall.Open(start, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, "", err
	}
	parent := os.NewFile(uintptr(fd), start)
	if parent == nil {
		_ = syscall.Close(fd)
		return nil, nil, "", errors.New("could not create runtime lock directory handle")
	}
	for _, component := range strings.Split(directory, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		nextFD, openErr := syscall.Openat(
			int(parent.Fd()), component,
			oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			_ = parent.Close()
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, nil, "", fmt.Errorf("runtime lock path contains a symlinked or non-directory component: %s", path)
			}
			return nil, nil, "", openErr
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = parent.Close()
			return nil, nil, "", errors.New("could not create runtime lock directory handle")
		}
		_ = parent.Close()
		parent = next
	}

	lockFD, err := syscall.Openat(
		int(parent.Fd()), name,
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		_ = parent.Close()
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, "", fmt.Errorf("runtime lock path must not be a symlink: %s", path)
		}
		return nil, nil, "", err
	}
	file := os.NewFile(uintptr(lockFD), path)
	if file == nil {
		_ = syscall.Close(lockFD)
		_ = parent.Close()
		return nil, nil, "", errors.New("could not create runtime lock handle")
	}
	return file, parent, name, nil
}

func validateLockFile(file *os.File, uid int) (os.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || uid < 0 || int64(stat.Uid) != int64(uid) || stat.Nlink != 1 {
		return nil, fmt.Errorf("runtime lock must be a regular file owned by uid %d with exactly one link", uid)
	}
	return info, nil
}

func validateLockPath(parent *os.File, name string, locked *os.File, uid int) error {
	lockedInfo, err := validateLockFile(locked, uid)
	if err != nil {
		return err
	}
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return fmt.Errorf("runtime lock path changed while acquiring: %w", err)
	}
	current := os.NewFile(uintptr(fd), name)
	if current == nil {
		_ = syscall.Close(fd)
		return errors.New("could not create runtime lock validation handle")
	}
	defer current.Close()
	currentInfo, err := validateLockFile(current, uid)
	if err != nil {
		return err
	}
	if !os.SameFile(lockedInfo, currentInfo) {
		return errors.New("runtime lock path changed while acquiring")
	}
	return nil
}

// Package statefile persists small runtime facts used by multi-day patch-health checks.
// Files are written atomically with mode 0600 inside the effective-user-owned state directory.
package statefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

const maxStateFileBytes = 4 << 10

type Store struct {
	Dir                string
	afterDirectoryOpen func()
	fileSync           func(*os.File) error
	directorySync      func(*os.File) error
}

func (s Store) path(name string) (string, error) {
	if s.Dir == "" {
		return "", fmt.Errorf("state directory is required")
	}
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsAny(name, `/\\`) {
		return "", fmt.Errorf("invalid state file name %q", name)
	}
	return filepath.Join(s.Dir, name), nil
}

func (s Store) ReadString(name string) (string, error) {
	p, err := s.path(name)
	if err != nil {
		return "", err
	}
	directory, exists, err := s.openDirectory(false)
	if err != nil {
		return "", err
	}
	if !exists {
		return "", nil
	}
	defer directory.Close()
	fd, err := syscall.Openat(int(directory.Fd()), filepath.Base(p), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if err := filetrust.ValidateRegular(info, os.Geteuid(), 0o022, false); err != nil || info.Size() > maxStateFileBytes {
		return "", fmt.Errorf("state file must be a protected regular file no larger than %d bytes", maxStateFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStateFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(b) > maxStateFileBytes {
		return "", fmt.Errorf("state file exceeds %d bytes", maxStateFileBytes)
	}
	return strings.TrimRight(string(b), "\n"), nil
}

func (s Store) ReadInt(name string) (int64, error) {
	v, err := s.ReadString(name)
	if err != nil || v == "" {
		return 0, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse state timestamp: %w", err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("state timestamp must be positive")
	}
	return n, nil
}

func (s Store) WriteString(name, value string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if len(value)+1 > maxStateFileBytes {
		return fmt.Errorf("state value exceeds %d bytes", maxStateFileBytes)
	}
	directory, _, err := s.openDirectory(true)
	if err != nil {
		return err
	}
	defer directory.Close()
	tmp, tmpName, err := createTempAt(directory, ".patch-state.*")
	if err != nil {
		return err
	}
	clean := func() {
		_ = tmp.Close()
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
	}
	if _, err := tmp.WriteString(value + "\n"); err != nil {
		clean()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		clean()
		return err
	}
	if err := s.syncFile(tmp); err != nil {
		clean()
		return fmt.Errorf("sync state temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), tmpName, int(directory.Fd()), filepath.Base(p)); err != nil {
		_ = syscall.Unlinkat(int(directory.Fd()), tmpName)
		return err
	}
	if err := s.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func (s Store) WriteInt(name string, value int64) error {
	return s.WriteString(name, strconv.FormatInt(value, 10))
}

func (s Store) Remove(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	directory, exists, err := s.openDirectory(false)
	if err != nil || !exists {
		return err
	}
	defer directory.Close()
	err = syscall.Unlinkat(int(directory.Fd()), filepath.Base(p))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.syncDirectory(directory); err != nil {
		return fmt.Errorf("sync state directory after remove: %w", err)
	}
	return nil
}

func (s Store) syncFile(file *os.File) error {
	if s.fileSync != nil {
		return s.fileSync(file)
	}
	return file.Sync()
}

func (s Store) syncDirectory(directory *os.File) error {
	if s.directorySync != nil {
		return s.directorySync(directory)
	}
	return directory.Sync()
}

func (s Store) openDirectory(create bool) (*os.File, bool, error) {
	var directory *os.File
	var exists bool
	var err error
	if create {
		directory, err = filetrust.OpenOrCreateDirectory(s.Dir, os.Geteuid())
		exists = err == nil
	} else {
		directory, exists, err = filetrust.OpenExistingDirectory(s.Dir, os.Geteuid())
	}
	if err == nil && exists && s.afterDirectoryOpen != nil {
		s.afterDirectoryOpen()
	}
	return directory, exists, err
}

func createTempAt(directory *os.File, pattern string) (*os.File, string, error) {
	procPath := filepath.Join("/proc/self/fd", strconv.Itoa(int(directory.Fd())))
	temporary, err := os.CreateTemp(procPath, pattern)
	if err != nil {
		return nil, "", err
	}
	return temporary, filepath.Base(temporary.Name()), nil
}

// Track returns the first time an active condition was observed. When mutate is false it is read-only;
// a missing timestamp is treated as newly observed. Clock rollback resets a future timestamp.
func (s Store) Track(name string, active bool, now int64, mutate bool) (int64, error) {
	if !active {
		if mutate {
			return 0, s.Remove(name)
		}
		return 0, nil
	}
	first, err := s.ReadInt(name)
	if err != nil {
		return 0, err
	}
	if first > 0 && first <= now {
		return first, nil
	}
	if mutate {
		if err := s.WriteInt(name, now); err != nil {
			return 0, err
		}
	}
	return now, nil
}

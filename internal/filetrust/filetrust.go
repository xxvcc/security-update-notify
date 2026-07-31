// Package filetrust centralizes metadata checks for runtime-owned files and directories.
package filetrust

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// ValidateDirectory requires a real directory owned by euid and rejects the requested permission bits.
func ValidateDirectory(info fs.FileInfo, euid int, forbiddenPerm fs.FileMode) error {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("must be a real directory")
	}
	if err := validateOwner(info, euid); err != nil {
		return err
	}
	if info.Mode().Perm()&forbiddenPerm != 0 {
		return fmt.Errorf("has forbidden permissions %#o", info.Mode().Perm()&forbiddenPerm)
	}
	return nil
}

// ValidateRegular requires a regular file owned by euid, rejects the requested permission bits,
// and optionally requires a single hard link.
func ValidateRegular(info fs.FileInfo, euid int, forbiddenPerm fs.FileMode, singleLink bool) error {
	if info == nil || !info.Mode().IsRegular() {
		return fmt.Errorf("must be a regular file")
	}
	stat, err := ownerStat(info, euid)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&forbiddenPerm != 0 {
		return fmt.Errorf("has forbidden permissions %#o", info.Mode().Perm()&forbiddenPerm)
	}
	if singleLink && stat.Nlink != 1 {
		return fmt.Errorf("must have exactly one hard link")
	}
	return nil
}

// ExistingDirectory validates path when present. A missing path is reported as (false, nil).
func ExistingDirectory(path string, euid int) (bool, error) {
	directory, exists, err := OpenExistingDirectory(path, euid)
	if directory != nil {
		_ = directory.Close()
	}
	return exists, err
}

// EnsureDirectory creates a missing directory with mode 0750, then validates the final path.
// Existing directories are never chmodded before validation.
func EnsureDirectory(path string, euid int) error {
	directory, err := OpenOrCreateDirectory(path, euid)
	if directory != nil {
		_ = directory.Close()
	}
	return err
}

// OpenExistingDirectory opens and validates the final directory object without
// following a symlink. A missing path is reported as (nil, false, nil).
func OpenExistingDirectory(path string, euid int) (*os.File, bool, error) {
	return openDirectory(path, euid, false)
}

// OpenOrCreateDirectory creates a missing directory with mode 0750, then opens
// and validates the final directory object. Callers can safely use *at syscalls
// relative to the returned descriptor even if the pathname is later replaced.
func OpenOrCreateDirectory(path string, euid int) (*os.File, error) {
	directory, exists, err := openDirectory(path, euid, true)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("directory was not created: %s", path)
	}
	return directory, nil
}

func openDirectory(path string, euid int, create bool) (*os.File, bool, error) {
	if path == "" {
		return nil, false, fmt.Errorf("directory path is required")
	}
	open := func() (int, error) {
		return syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	}
	fd, err := open()
	if errors.Is(err, os.ErrNotExist) && create {
		if err := os.MkdirAll(path, 0o750); err != nil {
			return nil, false, err
		}
		fd, err = open()
	}
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, false, fmt.Errorf("could not create directory handle")
	}
	info, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, false, err
	}
	if err := ValidateDirectory(info, euid, 0o022); err != nil {
		_ = directory.Close()
		return nil, false, fmt.Errorf("unsafe directory %s: %w", path, err)
	}
	return directory, true, nil
}

func validateOwner(info fs.FileInfo, euid int) error {
	_, err := ownerStat(info, euid)
	return err
}

func ownerStat(info fs.FileInfo, euid int) (*syscall.Stat_t, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return nil, fmt.Errorf("cannot verify owner")
	}
	if euid < 0 || uint64(stat.Uid) != uint64(euid) {
		return nil, fmt.Errorf("owner uid %d does not match effective uid %d", stat.Uid, euid)
	}
	return stat, nil
}

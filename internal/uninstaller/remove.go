package uninstaller

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"unsafe"
)

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

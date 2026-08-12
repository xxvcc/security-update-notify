package uninstaller

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/filetrust"

	"unsafe"
)

type removalMode uint8

type removalRecoveryPolicy uint8

type removalIdentity struct {
	device, inode, nlink uint64
	mode, uid, gid       uint32
	size, mtimeSec, nsec int64
}

type removalHooks struct {
	afterPendingClaim      func(string) error
	afterPendingValidation func(string) error
	afterOwnedPromotion    func(string) error
	syncOwned              func(*os.File) error
	beforeDelete           func(string) error
	validate               func(os.FileInfo) error
}

const (
	removalLeaf removalMode = iota
	removalEmptyDirectory
	removalTree
)

const (
	trustedParentRemovalRecovery removalRecoveryPolicy = iota + 1
	sharedParentRemovalRecovery
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
	if leftOK != rightOK {
		return false
	}
	if !leftOK {
		return true
	}
	if leftStat.Uid != rightStat.Uid || leftStat.Gid != rightStat.Gid {
		return false
	}
	return left.IsDir() || leftStat.Nlink == rightStat.Nlink
}

func removalIdentityFromInfo(info os.FileInfo) (removalIdentity, bool) {
	if info == nil {
		return removalIdentity{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return removalIdentity{}, false
	}
	identity := removalIdentity{
		device: uint64(stat.Dev),
		inode:  stat.Ino,
		mode:   stat.Mode,
		uid:    stat.Uid,
		gid:    stat.Gid,
	}
	if !info.IsDir() {
		identity.nlink = uint64(stat.Nlink)
		identity.size = stat.Size
		identity.mtimeSec = int64(stat.Mtim.Sec)
		identity.nsec = int64(stat.Mtim.Nsec)
	}
	return identity, true
}

func (identity removalIdentity) matches(info os.FileInfo) bool {
	current, ok := removalIdentityFromInfo(info)
	return ok && current == identity
}

func newRemovalPlaceholder(parent *os.File, directory bool) (string, os.FileInfo, error) {
	return newRemovalPlaceholderWithClose(parent, directory, uninstallRemovalPendingPrefix, nil)
}

func newRemovalPlaceholderWithClose(parent *os.File, directory bool, prefix string, closePlaceholder func(*os.File, string) error) (string, os.FileInfo, error) {
	for range restoreTemporaryAttempts {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, err
		}
		name := fmt.Sprintf(".%s.%s", prefix, hex.EncodeToString(random))
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

func cleanupUninstallRemovalArtifacts(parent *os.File, policy removalRecoveryPolicy) error {
	if policy != trustedParentRemovalRecovery && policy != sharedParentRemovalRecovery {
		return errors.New("invalid uninstall removal recovery policy")
	}
	if policy == trustedParentRemovalRecovery {
		info, err := parent.Stat()
		if err != nil {
			return fmt.Errorf("inspect trusted uninstall recovery parent %s: %w", parent.Name(), err)
		}
		if err := filetrust.ValidateDirectory(info, os.Geteuid(), 0o022); err != nil {
			return fmt.Errorf("unsafe trusted uninstall recovery parent %s: %w", parent.Name(), err)
		}
	}
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
		if isRestoreTemporaryName(entry.Name(), uninstallRemovalPendingPrefix) {
			errs = append(errs, errors.New("unverified uninstall quarantine retained at "+removalEntryPath(parent, entry.Name())))
			continue
		}
		if isRestoreTemporaryName(entry.Name(), uninstallRemovalPrefix) {
			errs = append(errs, errors.New("legacy uninstall quarantine has unverified ownership; retained at "+removalEntryPath(parent, entry.Name())))
			continue
		}
		identity, mode, owned := parseOwnedRemovalName(entry.Name())
		if !owned {
			if isOwnedRemovalCandidate(entry.Name()) {
				errs = append(errs, errors.New(
					"owned uninstall quarantine has an unsupported durable identity; retained at "+
						removalEntryPath(parent, entry.Name()),
				))
			}
			continue
		}
		if policy == sharedParentRemovalRecovery {
			errs = append(errs, fmt.Errorf(
				"owned uninstall quarantine mode %d is forbidden by shared-parent recovery policy; retained at %s",
				mode, removalEntryPath(parent, entry.Name()),
			))
			continue
		}
		expected, err := readRemovalEntry(parent, entry.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err == nil && !identity.matches(expected) {
			err = errors.New("owned uninstall quarantine does not match its durable identity; retained at " + removalEntryPath(parent, entry.Name()))
		}
		if err == nil {
			err = deleteOwnedRemovalEntry(parent, entry.Name(), expected, mode, nil, removalHooks{})
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
	return removeValidatedEntryAtWithHooks(parent, name, expected, mode, removalHooks{beforeDelete: beforeDelete})
}

func removeValidatedEntryAtWithHooks(parent *os.File, name string, expected os.FileInfo, mode removalMode, hooks removalHooks) (returnErr error) {
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
	pending, placeholder, err := newRemovalPlaceholder(parent, expected.IsDir())
	if err != nil {
		return err
	}
	if err := syscall.Renameat(int(parent.Fd()), name, int(parent.Fd()), pending); err != nil {
		cleanupErr := cleanupRemovalPlaceholder(parent, pending, placeholder)
		if errors.Is(err, os.ErrNotExist) {
			return cleanupErr
		}
		return errors.Join(fmt.Errorf("claim validated entry; pending quarantine retained at %s: %w", removalEntryPath(parent, pending), err), cleanupErr)
	}
	if hooks.afterPendingClaim != nil {
		if err := hooks.afterPendingClaim(pending); err != nil {
			return fmt.Errorf("validate pending uninstall quarantine retained at %s: %w", removalEntryPath(parent, pending), err)
		}
	}
	claimed, readErr := readRemovalEntry(parent, pending)
	if readErr != nil {
		return restoreUnexpectedClaim(parent, pending, name, readErr)
	}
	if hooks.validate != nil {
		if err := hooks.validate(claimed); err != nil {
			return restoreUnexpectedClaim(parent, pending, name, err)
		}
	}
	if !sameRemovalEntry(claimed, expected) {
		return restoreUnexpectedClaim(parent, pending, name, nil)
	}
	if hooks.afterPendingValidation != nil {
		if err := hooks.afterPendingValidation(pending); err != nil {
			return fmt.Errorf("publish pending uninstall quarantine retained at %s: %w", removalEntryPath(parent, pending), err)
		}
	}
	owned, err := ownedRemovalName(pending, expected, mode)
	if err != nil {
		return fmt.Errorf("publish verified uninstall quarantine retained at %s: %w", removalEntryPath(parent, pending), err)
	}
	if err := renameRestoreEntry(int(parent.Fd()), pending, owned, restoreRenameNoReplace); err != nil {
		return fmt.Errorf("publish verified uninstall quarantine retained at %s: %w", removalEntryPath(parent, pending), err)
	}
	if hooks.afterOwnedPromotion != nil {
		if err := hooks.afterOwnedPromotion(owned); err != nil {
			return fmt.Errorf("verify promoted uninstall quarantine retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	}
	current, readErr := readRemovalEntry(parent, owned)
	if readErr != nil {
		return errors.Join(errors.New("owned uninstall quarantine changed before removal; retained at "+removalEntryPath(parent, owned)), readErr)
	}
	if hooks.validate != nil {
		if err := hooks.validate(current); err != nil {
			return fmt.Errorf("owned uninstall quarantine failed removal policy; retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	}
	if !sameRemovalEntry(current, expected) {
		return errors.New("owned uninstall quarantine changed before removal; retained at " + removalEntryPath(parent, owned))
	}
	return deleteOwnedRemovalEntry(parent, owned, current, mode, claimedDirectory, hooks)
}

func deleteOwnedRemovalEntry(parent *os.File, owned string, expected os.FileInfo, mode removalMode, claimedDirectory *os.File, hooks removalHooks) (returnErr error) {
	identity, encodedMode, validName := parseOwnedRemovalName(owned)
	if !validName || encodedMode != mode || !identity.matches(expected) {
		return errors.New("owned uninstall quarantine does not match its durable identity; retained at " + removalEntryPath(parent, owned))
	}
	if expected.IsDir() && claimedDirectory == nil {
		var err error
		claimedDirectory, err = openRemovalDirectory(parent, owned)
		if err != nil {
			return fmt.Errorf("open owned uninstall quarantine retained at %s: %w", removalEntryPath(parent, owned), err)
		}
		defer func() {
			returnErr = errors.Join(returnErr, claimedDirectory.Close())
		}()
		info, err := claimedDirectory.Stat()
		if err != nil || !sameRemovalEntry(info, expected) {
			return errors.Join(errors.New("owned uninstall quarantine changed before removal; retained at "+removalEntryPath(parent, owned)), err)
		}
	}
	current, readErr := readRemovalEntry(parent, owned)
	if readErr != nil {
		return errors.Join(errors.New("owned uninstall quarantine changed before removal; retained at "+removalEntryPath(parent, owned)), readErr)
	}
	if hooks.validate != nil {
		if err := hooks.validate(current); err != nil {
			return fmt.Errorf("owned uninstall quarantine failed removal policy; retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	}
	if !sameRemovalEntry(current, expected) || !identity.matches(current) {
		return errors.New("owned uninstall quarantine changed before removal; retained at " + removalEntryPath(parent, owned))
	}
	syncOwned := hooks.syncOwned
	if syncOwned == nil {
		syncOwned = syncLogicalRemovalParent
	}
	if err := syncOwned(parent); err != nil {
		return fmt.Errorf("persist owned uninstall quarantine retained at %s: %w", removalEntryPath(parent, owned), err)
	}
	current, readErr = readRemovalEntry(parent, owned)
	if readErr != nil {
		return errors.Join(errors.New("owned uninstall quarantine changed after persistence; retained at "+removalEntryPath(parent, owned)), readErr)
	}
	if hooks.validate != nil {
		if err := hooks.validate(current); err != nil {
			return fmt.Errorf("owned uninstall quarantine failed removal policy after persistence; retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	}
	if !sameRemovalEntry(current, expected) || !identity.matches(current) {
		return errors.New("owned uninstall quarantine changed after persistence; retained at " + removalEntryPath(parent, owned))
	}
	if hooks.beforeDelete != nil {
		if err := hooks.beforeDelete(owned); err != nil {
			return fmt.Errorf("remove claimed entry retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	}
	current, readErr = readRemovalEntry(parent, owned)
	if readErr != nil {
		return errors.Join(errors.New("owned uninstall quarantine changed before deletion; retained at "+removalEntryPath(parent, owned)), readErr)
	}
	if hooks.validate != nil {
		if err := hooks.validate(current); err != nil {
			return fmt.Errorf("owned uninstall quarantine failed removal policy before deletion; retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	}
	if !sameRemovalEntry(current, expected) || !identity.matches(current) {
		return errors.New("owned uninstall quarantine changed before deletion; retained at " + removalEntryPath(parent, owned))
	}

	var removeErr error
	switch mode {
	case removalLeaf:
		if current.IsDir() {
			return errors.New("owned uninstall quarantine changed type; retained at " + removalEntryPath(parent, owned))
		}
		if err := syscall.Unlinkat(int(parent.Fd()), owned); err != nil {
			removeErr = fmt.Errorf("remove claimed entry retained at %s: %w", removalEntryPath(parent, owned), err)
		}
	case removalEmptyDirectory:
		if !current.IsDir() || claimedDirectory == nil {
			return errors.New("owned uninstall quarantine changed type; retained at " + removalEntryPath(parent, owned))
		}
		empty, err := removalDirectoryEmptyOpened(claimedDirectory)
		if err != nil || !empty {
			if err == nil {
				err = errors.New("validated empty directory gained an entry")
			}
			return errors.Join(errors.New("owned uninstall quarantine changed before removal; retained at "+removalEntryPath(parent, owned)), err)
		}
		removeErr = unlinkRemovalDirectory(parent, owned, expected)
	case removalTree:
		if !current.IsDir() {
			if err := syscall.Unlinkat(int(parent.Fd()), owned); err != nil {
				removeErr = fmt.Errorf("remove claimed entry retained at %s: %w", removalEntryPath(parent, owned), err)
			}
		} else if claimedDirectory == nil {
			return errors.New("validated directory handle is unavailable; claimed entry retained at " + removalEntryPath(parent, owned))
		} else if err := removeClaimedTree(claimedDirectory); err != nil {
			removeErr = fmt.Errorf("remove quarantined tree retained at %s: %w", removalEntryPath(parent, owned), err)
		} else {
			removeErr = unlinkRemovalDirectory(parent, owned, expected)
		}
	default:
		return errors.New("invalid uninstall removal mode; claimed entry retained at " + removalEntryPath(parent, owned))
	}
	return errors.Join(removeErr, syncOwned(parent))
}

func ownedRemovalName(pending string, expected os.FileInfo, mode removalMode) (string, error) {
	suffix, found := strings.CutPrefix(pending, "."+uninstallRemovalPendingPrefix+".")
	if !found || !isRestoreTemporaryName("."+uninstallRemovalOwnedPrefix+"."+suffix, uninstallRemovalOwnedPrefix) {
		return "", fmt.Errorf("invalid pending uninstall quarantine name: %q", pending)
	}
	identity, ok := removalIdentityFromInfo(expected)
	if !ok {
		return "", errors.New("uninstall quarantine identity is unavailable")
	}
	if mode > removalTree {
		return "", errors.New("invalid uninstall quarantine removal mode")
	}
	return fmt.Sprintf(".%s.%s.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x",
		uninstallRemovalOwnedPrefix, suffix, mode,
		identity.device, identity.inode, identity.mode, identity.uid, identity.gid,
		identity.nlink, uint64(identity.size), uint64(identity.mtimeSec), uint64(identity.nsec),
	), nil
}

func isOwnedRemovalCandidate(name string) bool {
	rest, found := strings.CutPrefix(name, "."+uninstallRemovalOwnedPrefix+".")
	if !found {
		return false
	}
	suffix, _, found := strings.Cut(rest, ".")
	return found && isRestoreTemporaryName("."+uninstallRemovalOwnedPrefix+"."+suffix, uninstallRemovalOwnedPrefix)
}

func parseOwnedRemovalName(name string) (removalIdentity, removalMode, bool) {
	rest, found := strings.CutPrefix(name, "."+uninstallRemovalOwnedPrefix+".")
	if !found {
		return removalIdentity{}, 0, false
	}
	fields := strings.Split(rest, ".")
	if len(fields) != 11 || !isRestoreTemporaryName("."+uninstallRemovalOwnedPrefix+"."+fields[0], uninstallRemovalOwnedPrefix) {
		return removalIdentity{}, 0, false
	}
	values := make([]uint64, 10)
	for index, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 16, 64)
		if err != nil || strconv.FormatUint(value, 16) != field {
			return removalIdentity{}, 0, false
		}
		values[index] = value
	}
	if values[0] > uint64(removalTree) || values[3] > uint64(^uint32(0)) || values[4] > uint64(^uint32(0)) || values[5] > uint64(^uint32(0)) {
		return removalIdentity{}, 0, false
	}
	return removalIdentity{
		device: values[1], inode: values[2], mode: uint32(values[3]),
		uid: uint32(values[4]), gid: uint32(values[5]), nlink: values[6], size: int64(values[7]),
		mtimeSec: int64(values[8]), nsec: int64(values[9]),
	}, removalMode(values[0]), true
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
	return removeClaimedTreeWithSync(directory, nil, syncLogicalRemovalParent)
}

func removeClaimedTreeWithSync(directory *os.File, beforeChild func(string) error, syncDirectory func(*os.File) error) (returnErr error) {
	defer func() {
		returnErr = errors.Join(returnErr, syncDirectory(directory))
	}()
	entries, readErr := directory.ReadDir(-1)
	if readErr == nil {
		for _, entry := range entries {
			var beforeClaim func() error
			if beforeChild != nil {
				beforeClaim = func() error { return beforeChild(entry.Name()) }
			}
			if err := removeAllAtWithHook(directory, entry.Name(), beforeClaim); err != nil {
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
	return removeAllAtWithHooks(parent, name, beforeClaim, removalHooks{})
}

func removeAllAtWithHooks(parent *os.File, name string, beforeClaim func() error, hooks removalHooks) error {
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
	return removeValidatedEntryAtWithHooks(parent, name, expected, removalTree, hooks)
}

func removeLogicalFilesWithPrefix(root, directoryLogical, prefix string, beforeClaim func(string) error) error {
	return removeLogicalFilesWithPrefixWithSync(root, directoryLogical, prefix, beforeClaim, syncLogicalRemovalParent)
}

func removeLogicalFilesWithPrefixWithSync(root, directoryLogical, prefix string, beforeClaim func(string) error, syncParent func(*os.File) error) (returnErr error) {
	parent, name, err := openLogicalParent(root, directoryLogical)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	directory, err := openRemovalDirectory(parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return parent.Close()
	}
	if err != nil {
		return errors.Join(err, parent.Close())
	}
	defer func() {
		returnErr = errors.Join(returnErr, syncParent(directory), directory.Close(), parent.Close())
	}()
	if err := cleanupUninstallRemovalArtifacts(directory, sharedParentRemovalRecovery); err != nil {
		return fmt.Errorf("recover interrupted prefixed-file removal: %w", err)
	}
	entries, readErr := directory.ReadDir(-1)
	if readErr != nil {
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
			err = removeValidatedEntryAtWithHooks(directory, entry.Name(), expected, removalLeaf, removalHooks{syncOwned: syncParent})
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

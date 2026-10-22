package installer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"io/fs"
	"os"

	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const removalOwnedPrefix = ".security-update-notify-remove-owned."

// Remove has rm -f semantics: it may unlink a file or symlink, but it never
// broadens scope to removing a directory, including under a replacement race.
func (f *RootFS) Remove(logicalPath string) error {
	return f.remove(logicalPath, nil)
}

func (f *RootFS) remove(logicalPath string, beforeClaim func() error) (returnErr error) {
	directory, name, err := f.openParent(logicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, f.syncRemovalDirectory(directory), directory.Close())
	}()
	if err := cleanupRemovalArtifactsAt(directory); err != nil {
		return fmt.Errorf("recover interrupted removal: %w", err)
	}
	expected, err := readRemovalEntry(directory, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if expected.IsDir() {
		return fmt.Errorf("refusing to remove directory as a file: %s", logicalPath)
	}
	return removeValidatedEntryAt(directory, name, expected, false, beforeClaim)
}

func (f *RootFS) RemoveAll(logicalPath string) error {
	return f.removeAll(logicalPath, nil)
}

func (f *RootFS) removeAll(logicalPath string, beforeClaim func() error) (returnErr error) {
	directory, name, err := f.openParent(logicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, f.syncRemovalDirectory(directory), directory.Close())
	}()
	if err := cleanupRemovalArtifactsAt(directory); err != nil {
		return fmt.Errorf("recover interrupted recursive removal: %w", err)
	}
	expected, err := readRemovalEntry(directory, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return removeValidatedEntryAt(directory, name, expected, true, beforeClaim)
}

func (f *RootFS) syncRemovalDirectory(directory *os.File) error {
	if f.beforeRemovalDirectorySync != nil {
		if err := f.beforeRemovalDirectorySync(directory); err != nil {
			return err
		}
	}
	return directory.Sync()
}

func removeAllAt(parent *os.File, name string) error {
	expected, err := readRemovalEntry(parent, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return removeValidatedEntryAt(parent, name, expected, true, nil)
}

func readRemovalEntry(parent *os.File, name string) (fs.FileInfo, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
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
		return nil, errors.New("could not create removal entry handle")
	}
	info, statErr := entry.Stat()
	closeErr := entry.Close()
	if statErr != nil || closeErr != nil {
		return nil, errors.Join(statErr, closeErr)
	}
	return info, nil
}

func sameRemovalEntry(left, right fs.FileInfo) bool {
	return sameRemovalIdentity(left, right) && left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func sameRemovalIdentity(left, right fs.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Mode() != right.Mode() {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK == rightOK && (!leftOK || leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid)
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
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create recursive directory handle")
	}
	return directory, nil
}

func newRemovalPlaceholder(parent *os.File, directory bool) (string, fs.FileInfo, error) {
	for range temporaryAttempts {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return "", nil, err
		}
		name := removalPrefix + hex.EncodeToString(random)
		if directory {
			err := syscall.Mkdirat(int(parent.Fd()), name, 0o700)
			if errors.Is(err, fs.ErrExist) {
				continue
			}
			if err != nil {
				return "", nil, err
			}
			info, statErr := readRemovalEntry(parent, name)
			return name, info, statErr
		}
		fd, err := syscall.Openat(
			int(parent.Fd()), name,
			syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0o600,
		)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		placeholder := os.NewFile(uintptr(fd), name)
		if placeholder == nil {
			_ = syscall.Close(fd)
			return "", nil, errors.New("could not create removal quarantine handle")
		}
		info, statErr := placeholder.Stat()
		closeErr := placeholder.Close()
		if statErr != nil || closeErr != nil {
			return name, info, errors.Join(statErr, closeErr)
		}
		return name, info, nil
	}
	return "", nil, errors.New("could not create removal quarantine entry")
}

func isRemovalArtifactName(name string) bool {
	if strings.HasPrefix(name, removalOwnedPrefix) {
		return true
	}
	suffix, found := strings.CutPrefix(name, removalPrefix)
	if !found || len(suffix) != 32 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
}

// The old random-only name is a pending claim, including on older installs:
// a crash may have happened before the claimed inode was checked. Only a name
// published after that check carries the identity needed to resume deletion.
func ownedRemovalName(pending string, info fs.FileInfo) (string, error) {
	suffix, found := strings.CutPrefix(pending, removalPrefix)
	if !found || !isRemovalArtifactName(pending) {
		return "", errors.New("invalid pending removal name")
	}
	digest, err := removalIdentityDigest(info)
	if err != nil {
		return "", err
	}
	return removalOwnedPrefix + suffix + "." + digest, nil
}

func removalIdentityDigest(info fs.FileInfo) (string, error) {
	if info == nil {
		return "", errors.New("removal identity is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return "", errors.New("removal identity is unavailable")
	}
	identity := fmt.Sprintf("%x:%x:%x:%x:%x", stat.Dev, stat.Ino, stat.Mode, stat.Uid, stat.Gid)
	// Recursive deletion changes directory size, timestamps and link count.
	// Leaf entries must retain all of those facts except rename-sensitive ctime.
	if !info.IsDir() {
		identity += fmt.Sprintf(":%x:%x:%x:%x", stat.Nlink, stat.Size, stat.Mtim.Sec, stat.Mtim.Nsec)
	}
	digest := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(digest[:]), nil
}

func ownedRemovalMatches(name string, info fs.FileInfo) bool {
	suffix, found := strings.CutPrefix(name, removalOwnedPrefix)
	if !found {
		return false
	}
	random, digest, found := strings.Cut(suffix, ".")
	if !found || !isRemovalArtifactName(removalPrefix+random) || len(digest) != sha256.Size*2 {
		return false
	}
	expected, err := removalIdentityDigest(info)
	return err == nil && digest == expected
}

func cleanupRemovalArtifactsAt(parent *os.File) error {
	fd, err := syscall.Openat(
		int(parent.Fd()), ".",
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), parent.Name())
	if directory == nil {
		_ = syscall.Close(fd)
		return errors.New("could not create removal recovery directory handle")
	}
	entries, readErr := directory.ReadDir(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	var errs []error
	for _, entry := range entries {
		if !isRemovalArtifactName(entry.Name()) {
			continue
		}
		if !strings.HasPrefix(entry.Name(), removalOwnedPrefix) {
			errs = append(errs, errors.New("unverified or legacy removal quarantine requires manual recovery; retained at "+entry.Name()))
			continue
		}
		expected, err := readRemovalEntry(parent, entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil && !ownedRemovalMatches(entry.Name(), expected) {
			err = errors.New("owned removal quarantine does not match its durable identity; retained at " + entry.Name())
		}
		if err == nil {
			err = removeOwnedEntryAt(parent, entry.Name(), expected, nil)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("remove interrupted quarantine %s: %w", entry.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func cleanupRemovalPlaceholder(parent *os.File, name string, expected fs.FileInfo) error {
	current, err := readRemovalEntry(parent, name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !sameRemovalEntry(current, expected) {
		return errors.Join(errors.New("removal quarantine placeholder changed; retained at "+name), err)
	}
	if expected.IsDir() {
		return unlinkRemovalDirectory(parent, name, expected)
	}
	return syscall.Unlinkat(int(parent.Fd()), name)
}

func restoreUnexpectedRemovalClaim(parent *os.File, quarantine, name string, cause error) error {
	restoreErr := renameEntryNoReplace(int(parent.Fd()), quarantine, name)
	if restoreErr == nil {
		return errors.Join(errors.New("entry changed before removal; concurrent entry restored"), cause)
	}
	return errors.Join(
		errors.New("entry changed before removal; concurrent entry retained at "+quarantine),
		cause, restoreErr,
	)
}

func removeValidatedEntryAt(parent *os.File, name string, expected fs.FileInfo, recursive bool, beforeClaim func() error) (returnErr error) {
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
	if beforeClaim != nil {
		if err := beforeClaim(); err != nil {
			return err
		}
	}
	quarantine, placeholder, err := newRemovalPlaceholder(parent, expected.IsDir())
	if err != nil {
		return err
	}
	if err := syscall.Renameat(int(parent.Fd()), name, int(parent.Fd()), quarantine); err != nil {
		cleanupErr := cleanupRemovalPlaceholder(parent, quarantine, placeholder)
		if errors.Is(err, fs.ErrNotExist) {
			return cleanupErr
		}
		return errors.Join(fmt.Errorf("claim validated entry; quarantine retained at %s: %w", quarantine, err), cleanupErr)
	}
	claimed, readErr := readRemovalEntry(parent, quarantine)
	if readErr != nil || !sameRemovalEntry(claimed, expected) {
		return restoreUnexpectedRemovalClaim(parent, quarantine, name, readErr)
	}
	if claimed.IsDir() && !recursive {
		return restoreUnexpectedRemovalClaim(parent, quarantine, name, errors.New("validated leaf became a directory"))
	}
	if claimed.IsDir() && claimedDirectory == nil {
		return restoreUnexpectedRemovalClaim(parent, quarantine, name, errors.New("validated directory handle is unavailable"))
	}
	owned, err := ownedRemovalName(quarantine, claimed)
	if err != nil {
		return fmt.Errorf("record removal ownership; pending entry retained at %s: %w", quarantine, err)
	}
	// Both names include the freshly reserved 128-bit random suffix. A plain
	// rename keeps this promotion atomic on filesystems without renameat2 flags.
	if err := syscall.Renameat(int(parent.Fd()), quarantine, int(parent.Fd()), owned); err != nil {
		return fmt.Errorf("publish removal ownership; pending entry retained at %s: %w", quarantine, err)
	}
	return removeOwnedEntryAt(parent, owned, claimed, claimedDirectory)
}

func removeOwnedEntryAt(parent *os.File, owned string, expected fs.FileInfo, claimedDirectory *os.File) (returnErr error) {
	current, err := readRemovalEntry(parent, owned)
	if err != nil || !ownedRemovalMatches(owned, current) || !sameRemovalEntry(current, expected) {
		return errors.Join(errors.New("owned removal quarantine changed; retained at "+owned), err)
	}
	// Persist the ownership decision before deleting any bytes. After a crash,
	// recovery must never reinterpret an unverified claim as an owned one.
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("persist owned removal quarantine retained at %s: %w", owned, err)
	}
	current, err = readRemovalEntry(parent, owned)
	if err != nil || !ownedRemovalMatches(owned, current) || !sameRemovalEntry(current, expected) {
		return errors.Join(errors.New("owned removal quarantine changed after persistence; retained at "+owned), err)
	}
	if !current.IsDir() {
		if err := syscall.Unlinkat(int(parent.Fd()), owned); err != nil {
			return fmt.Errorf("remove claimed entry retained at %s: %w", owned, err)
		}
		return nil
	}
	if claimedDirectory == nil {
		claimedDirectory, err = openRemovalDirectory(parent, owned)
		if err != nil {
			return err
		}
		defer func() { returnErr = errors.Join(returnErr, claimedDirectory.Close()) }()
	}
	info, err := claimedDirectory.Stat()
	if err != nil || !sameRemovalIdentity(info, current) {
		return errors.Join(errors.New("owned removal directory changed; retained at "+owned), err)
	}
	// A partially deleted tree can itself contain a pending child claim. Do not
	// erase that unresolved conflict merely because its parent is owned.
	if err := cleanupRemovalArtifactsAt(claimedDirectory); err != nil {
		return err
	}
	entries, err := claimedDirectory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := removeAllAt(claimedDirectory, entry.Name()); err != nil {
			return fmt.Errorf("remove quarantined tree retained at %s: %w", owned, err)
		}
	}
	if err := claimedDirectory.Sync(); err != nil {
		return fmt.Errorf("sync removed tree contents retained at %s: %w", owned, err)
	}
	return unlinkRemovalDirectory(parent, owned, expected)
}

func unlinkRemovalDirectory(parent *os.File, name string, expected fs.FileInfo) error {
	current, err := readRemovalEntry(parent, name)
	if err != nil || !sameRemovalIdentity(current, expected) {
		return errors.Join(errors.New("claimed directory changed before removal; retained at "+name), err)
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_UNLINKAT,
		parent.Fd(), uintptr(unsafe.Pointer(namePointer)), atRemoveDir, 0, 0, 0,
	)
	if errno != 0 && !errors.Is(errno, fs.ErrNotExist) {
		return fmt.Errorf("remove claimed directory retained at %s: %w", name, errno)
	}
	return nil
}

func renameEntryNoReplace(directory int, oldName, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	systemCall := renameat2SystemCall()
	if systemCall == 0 {
		return syscall.ENOSYS
	}
	_, _, errno := syscall.Syscall6(
		systemCall,
		uintptr(directory), uintptr(unsafe.Pointer(oldPointer)),
		uintptr(directory), uintptr(unsafe.Pointer(newPointer)), 1, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func renameat2SystemCall() uintptr {
	switch runtime.GOARCH {
	case "amd64":
		return 316
	case "386":
		return 353
	case "arm64":
		return 276
	case "ppc64le":
		return 357
	case "s390x":
		return 347
	default:
		return 0
	}
}

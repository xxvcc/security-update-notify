package uninstaller

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"unsafe"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

const (
	restoreConfigLimit       = 4 << 20
	restoreXattrNameLimit    = 1 << 20
	restoreXattrValueLimit   = 1 << 20
	restoreXattrTotalLimit   = 16 << 20
	restoreTemporaryAttempts = 1000
	restoreFilePrefix        = "security-update-notify-restore"
	restorePurgePrefix       = "security-update-notify-purge"
	restoreConflictPrefix    = "security-update-notify-conflict"
)

type restoreDirectory struct {
	file                  *os.File
	hostPath              string
	ownerUID              int
	afterExchange         func()
	beforeTemporaryCommit func(string) error
	beforeRemove          func(string) error
	syncDirectory         func() error
}

type regularSnapshot struct {
	exists          bool
	data            []byte
	info            fs.FileInfo
	xattrs          map[string][]byte
	xattrsSupported bool
}

func openRestoreDirectory(root, logical string) (*restoreDirectory, error) {
	parent, name, err := openLogicalParent(root, logical)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
		return nil, fmt.Errorf("symlinked path component or non-directory component is forbidden: %s", logical)
	}
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), logical)
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create restore directory handle")
	}
	return &restoreDirectory{file: directory, hostPath: rooted(root, logical), ownerUID: os.Geteuid()}, nil
}

func (d *restoreDirectory) close() error {
	if d == nil || d.file == nil {
		return nil
	}
	return d.file.Close()
}

func (d *restoreDirectory) host(name string) string {
	return filepath.Join(d.hostPath, name)
}

func validRestoreEntry(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
		return fmt.Errorf("invalid restore directory entry: %q", name)
	}
	return nil
}

func (d *restoreDirectory) names() ([]string, error) {
	duplicateFD, err := syscall.Dup(int(d.file.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(duplicateFD)
	duplicate := os.NewFile(uintptr(duplicateFD), d.file.Name())
	if duplicate == nil {
		_ = syscall.Close(duplicateFD)
		return nil, errors.New("could not duplicate restore directory handle")
	}
	entries, readErr := duplicate.ReadDir(-1)
	closeErr := duplicate.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func restoreNamesWithPrefix(names []string, prefix string) []string {
	result := make([]string, 0)
	for _, name := range names {
		if strings.HasPrefix(name, prefix) {
			result = append(result, name)
		}
	}
	return result
}

func restoreTimestampNames(names []string, prefix, suffix string) []string {
	result := make([]string, 0)
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		stamp := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		if len(stamp) != len("20060102150405") {
			continue
		}
		valid := true
		for _, character := range stamp {
			if character < '0' || character > '9' {
				valid = false
				break
			}
		}
		if valid {
			result = append(result, name)
		}
	}
	return result
}

func unfinishedRestoreArtifact(names []string) string {
	for _, name := range names {
		if isRestoreTemporaryName(name, restoreFilePrefix) || isRestoreTemporaryName(name, restorePurgePrefix) ||
			isRestoreTemporaryName(name, restoreConflictPrefix) {
			return name
		}
	}
	return ""
}

func isRestoreTemporaryName(name, prefix string) bool {
	suffix, found := strings.CutPrefix(name, "."+prefix+".")
	if !found || len(suffix) != 32 {
		return false
	}
	for _, character := range suffix {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func (d *restoreDirectory) readSnapshots(names []string, maxBytes int64) (map[string]regularSnapshot, error) {
	snapshots := make(map[string]regularSnapshot, len(names))
	for _, name := range names {
		snapshot, err := d.readTrustedRegular(name, maxBytes)
		if err != nil {
			return nil, err
		}
		if !snapshot.exists {
			return nil, errors.New("file disappeared while recording restore transaction")
		}
		snapshots[name] = snapshot
	}
	return snapshots, nil
}

func oldestSnapshotName(names []string, snapshots map[string]regularSnapshot) string {
	oldest := ""
	for _, name := range names {
		if !snapshots[name].exists {
			continue
		}
		if oldest == "" || name < oldest {
			oldest = name
		}
	}
	return oldest
}

func newestSnapshotName(names []string, snapshots map[string]regularSnapshot) string {
	newest := ""
	for _, name := range names {
		snapshot := snapshots[name]
		if !snapshot.exists {
			continue
		}
		if newest == "" || snapshot.info.ModTime().After(snapshots[newest].info.ModTime()) ||
			snapshot.info.ModTime().Equal(snapshots[newest].info.ModTime()) && name > newest {
			newest = name
		}
	}
	return newest
}

func (d *restoreDirectory) readRegular(name string, maxBytes int64) (regularSnapshot, error) {
	if err := validRestoreEntry(name); err != nil {
		return regularSnapshot{}, err
	}
	fd, err := syscall.Openat(
		int(d.file.Fd()), name,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if errors.Is(err, os.ErrNotExist) {
		return regularSnapshot{}, nil
	}
	if errors.Is(err, syscall.ELOOP) {
		return regularSnapshot{}, fmt.Errorf("symlinked restore entry is forbidden: %s", d.host(name))
	}
	if err != nil {
		return regularSnapshot{}, err
	}
	opened := os.NewFile(uintptr(fd), d.host(name))
	if opened == nil {
		_ = syscall.Close(fd)
		return regularSnapshot{}, errors.New("could not create restore file handle")
	}
	defer opened.Close()
	info, err := opened.Stat()
	if err != nil {
		return regularSnapshot{}, err
	}
	if !info.Mode().IsRegular() || maxBytes < 0 || info.Size() < 0 || info.Size() > maxBytes {
		return regularSnapshot{}, fmt.Errorf("file is not a regular file no larger than %d bytes: %s", maxBytes, d.host(name))
	}
	data, err := io.ReadAll(io.LimitReader(opened, maxBytes+1))
	if err != nil {
		return regularSnapshot{}, err
	}
	if int64(len(data)) > maxBytes {
		return regularSnapshot{}, fmt.Errorf("file exceeds %d bytes: %s", maxBytes, d.host(name))
	}
	xattrs, xattrsSupported, err := readRestoreXattrs(opened)
	if err != nil {
		return regularSnapshot{}, err
	}
	finalInfo, err := opened.Stat()
	if err != nil {
		return regularSnapshot{}, err
	}
	finalXattrs, finalXattrsSupported, err := readRestoreXattrs(opened)
	if err != nil {
		return regularSnapshot{}, err
	}
	if !sameRestoreFileState(info, finalInfo) || xattrsSupported != finalXattrsSupported || !sameRestoreXattrs(xattrs, finalXattrs) {
		return regularSnapshot{}, errors.New("regular file changed while reading")
	}
	return regularSnapshot{
		exists:          true,
		data:            data,
		info:            info,
		xattrs:          xattrs,
		xattrsSupported: xattrsSupported,
	}, nil
}

// readTrustedRegular is for baselines, provenance records, and current
// privileged configuration that can influence a restore decision. Temporary
// transaction files use readRegular and are instead bound to their opened fd.
func (d *restoreDirectory) readTrustedRegular(name string, maxBytes int64) (regularSnapshot, error) {
	snapshot, err := d.readRegular(name, maxBytes)
	if err != nil || !snapshot.exists {
		return snapshot, err
	}
	if err := filetrust.ValidateRegular(snapshot.info, d.ownerUID, 0o022, true); err != nil {
		return regularSnapshot{}, fmt.Errorf("unsafe restore decision file %s: %w", d.host(name), err)
	}
	return snapshot, nil
}

func sameRestoreFileInfo(left, right fs.FileInfo) bool {
	if left == nil || right == nil || !os.SameFile(left, right) || left.Size() != right.Size() ||
		left.Mode() != right.Mode() || !left.ModTime().Equal(right.ModTime()) {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Uid == rightStat.Uid && leftStat.Gid == rightStat.Gid &&
		leftStat.Nlink == rightStat.Nlink
}

func sameRestoreFileState(left, right fs.FileInfo) bool {
	if !sameRestoreFileInfo(left, right) {
		return false
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	return leftOK && rightOK && leftStat.Ctim == rightStat.Ctim
}

func sameRestoreXattrs(left, right map[string][]byte) bool {
	if len(left) != len(right) {
		return false
	}
	for name, value := range left {
		rightValue, exists := right[name]
		if !exists || !bytes.Equal(value, rightValue) {
			return false
		}
	}
	return true
}

func sameRegularSnapshot(left, right regularSnapshot) bool {
	if left.exists != right.exists {
		return false
	}
	if !left.exists {
		return true
	}
	return sameRestoreFileState(left.info, right.info) && bytes.Equal(left.data, right.data) &&
		left.xattrsSupported == right.xattrsSupported && sameRestoreXattrs(left.xattrs, right.xattrs)
}

// A successful rename can advance ctime even though the same inode and all
// rollback-relevant contents and metadata were moved. Post-rename verification
// deliberately omits only ctime; pre-commit revalidation remains strict.
func sameRenamedRegularSnapshot(left, right regularSnapshot) bool {
	if left.exists != right.exists {
		return false
	}
	if !left.exists {
		return true
	}
	return sameRestoreFileInfo(left.info, right.info) && bytes.Equal(left.data, right.data) &&
		left.xattrsSupported == right.xattrsSupported && sameRestoreXattrs(left.xattrs, right.xattrs)
}

func sameRestoredMetadataAndContents(restored, source regularSnapshot) bool {
	if !restored.exists || !source.exists || restored.info == nil || source.info == nil ||
		!restored.info.Mode().IsRegular() || restored.info.Mode() != source.info.Mode() ||
		!restored.info.ModTime().Equal(source.info.ModTime()) || !bytes.Equal(restored.data, source.data) ||
		restored.xattrsSupported != source.xattrsSupported || !sameRestoreXattrs(restored.xattrs, source.xattrs) {
		return false
	}
	restoredStat, restoredOK := restored.info.Sys().(*syscall.Stat_t)
	sourceStat, sourceOK := source.info.Sys().(*syscall.Stat_t)
	return restoredOK && sourceOK && restoredStat.Uid == sourceStat.Uid && restoredStat.Gid == sourceStat.Gid &&
		restoredStat.Nlink == 1
}

func (d *restoreDirectory) revalidate(name string, expected regularSnapshot, maxBytes int64) error {
	current, err := d.readRegular(name, maxBytes)
	if err != nil {
		return err
	}
	if !sameRegularSnapshot(current, expected) {
		return errors.New("validated file changed before commit")
	}
	return nil
}

func (d *restoreDirectory) remove(name string) error {
	if err := validRestoreEntry(name); err != nil {
		return err
	}
	if d.beforeRemove != nil {
		if err := d.beforeRemove(name); err != nil {
			return err
		}
	}
	err := syscall.Unlinkat(int(d.file.Fd()), name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (d *restoreDirectory) cleanupUncommittedPlaceholder(name string, cause error) error {
	cleanupErr := d.remove(name)
	if cleanupErr != nil {
		cleanupErr = fmt.Errorf("remove uncommitted restore placeholder retained at %s: %w", d.host(name), cleanupErr)
	}
	return errors.Join(cause, cleanupErr)
}

func (d *restoreDirectory) removeOwnedTemporary(name string, opened *os.File) error {
	expected, err := opened.Stat()
	if err != nil {
		return err
	}
	current, err := d.readRegular(name, restoreConfigLimit)
	if err == nil && !current.exists {
		return nil
	}
	if err != nil || !os.SameFile(expected, current.info) {
		return errors.Join(errors.New("temporary restore entry changed; retained at "+d.host(name)), err)
	}
	if err := d.remove(name); err != nil {
		return fmt.Errorf("remove temporary restore entry retained at %s: %w", d.host(name), err)
	}
	return nil
}

func (d *restoreDirectory) sync() error {
	if d.syncDirectory != nil {
		return d.syncDirectory()
	}
	return d.file.Sync()
}

func (d *restoreDirectory) newTemporary(prefix string) (*os.File, string, error) {
	for range restoreTemporaryAttempts {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			return nil, "", err
		}
		name := fmt.Sprintf(".%s.%s", prefix, hex.EncodeToString(random))
		fd, err := syscall.Openat(
			int(d.file.Fd()), name,
			syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0o600,
		)
		if err == nil {
			file := os.NewFile(uintptr(fd), d.host(name))
			if file == nil {
				_ = syscall.Close(fd)
				_ = d.remove(name)
				return nil, "", errors.New("could not create temporary restore file handle")
			}
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not create temporary restore file")
}

func (d *restoreDirectory) recordConflict(reason string, causes ...error) error {
	marker, markerName, err := d.newTemporary(restoreConflictPrefix)
	if err != nil {
		return errors.Join(errors.New(reason), errors.Join(causes...), fmt.Errorf("record restore conflict: %w", err))
	}
	closeErr := marker.Close()
	syncErr := d.sync()
	return errors.Join(
		errors.New(reason+"; recovery marker retained at "+d.host(markerName)),
		errors.Join(causes...), closeErr, syncErr,
	)
}

func (d *restoreDirectory) restoreFile(source, destination string, sourceSnapshot, destinationSnapshot regularSnapshot) (snapshot regularSnapshot, retErr error) {
	if !sourceSnapshot.exists {
		return regularSnapshot{}, os.ErrNotExist
	}
	if err := filetrust.ValidateRegular(sourceSnapshot.info, d.ownerUID, 0o022, true); err != nil {
		return regularSnapshot{}, fmt.Errorf("unsafe backup source %s: %w", d.host(source), err)
	}
	if err := d.revalidate(source, sourceSnapshot, restoreConfigLimit); err != nil {
		return regularSnapshot{}, d.recordConflict("backup changed before restore", err)
	}
	temporary, temporaryName, err := d.newTemporary(restoreFilePrefix)
	if err != nil {
		return regularSnapshot{}, err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			retErr = errors.Join(retErr, d.removeOwnedTemporary(temporaryName, temporary))
		}
		retErr = errors.Join(retErr, temporary.Close())
	}()
	written, err := temporary.Write(sourceSnapshot.data)
	if err != nil {
		return regularSnapshot{}, err
	}
	if written != len(sourceSnapshot.data) || int64(written) != sourceSnapshot.info.Size() {
		return regularSnapshot{}, errors.New("short write while restoring backup")
	}
	if err := preserveRestoreMetadata(sourceSnapshot, temporary); err != nil {
		return regularSnapshot{}, err
	}
	if err := temporary.Sync(); err != nil {
		return regularSnapshot{}, err
	}
	if d.beforeTemporaryCommit != nil {
		if err := d.beforeTemporaryCommit(temporaryName); err != nil {
			return regularSnapshot{}, err
		}
	}
	committedInfo, err := temporary.Stat()
	if err != nil {
		return regularSnapshot{}, err
	}
	if !committedInfo.Mode().IsRegular() || committedInfo.Size() != int64(len(sourceSnapshot.data)) {
		return regularSnapshot{}, errors.New("temporary restore file changed before commit")
	}
	committedSnapshot, err := d.readRegular(temporaryName, restoreConfigLimit)
	if err != nil {
		return regularSnapshot{}, err
	}
	if !committedSnapshot.exists || !sameRestoreFileState(committedInfo, committedSnapshot.info) ||
		!sameRestoredMetadataAndContents(committedSnapshot, sourceSnapshot) {
		return regularSnapshot{}, errors.New("temporary restore file changed before commit")
	}
	publishedSnapshot, retainTemporary, err := d.publishTemporary(temporaryName, destination, committedSnapshot, destinationSnapshot)
	removeTemporary = !retainTemporary
	if err != nil {
		return regularSnapshot{}, err
	}
	removeTemporary = false
	return publishedSnapshot, nil
}

func (d *restoreDirectory) publishTemporary(temporary, destination string, committed, expectedDestination regularSnapshot) (regularSnapshot, bool, error) {
	if err := d.revalidate(temporary, committed, restoreConfigLimit); err != nil {
		return regularSnapshot{}, true, d.recordConflict("temporary restore file changed before publish", err)
	}
	if err := d.revalidate(destination, expectedDestination, restoreConfigLimit); err != nil {
		return regularSnapshot{}, true, d.recordConflict("destination changed before restore", err)
	}
	if !expectedDestination.exists {
		if err := renameRestoreEntry(int(d.file.Fd()), temporary, destination, restoreRenameNoReplace); err != nil {
			return regularSnapshot{}, true, d.recordConflict("publish restored file without overwrite failed", err)
		}
		published, err := d.readRegular(destination, restoreConfigLimit)
		if err != nil || !sameRenamedRegularSnapshot(published, committed) {
			return regularSnapshot{}, true, d.recordConflict("published restore file changed before verification", err)
		}
		if err := d.sync(); err != nil {
			return regularSnapshot{}, true, d.recordConflict("sync published restore file", err)
		}
		return published, false, nil
	}

	if err := renameRestoreEntry(int(d.file.Fd()), temporary, destination, restoreRenameExchange); err != nil {
		return regularSnapshot{}, true, d.recordConflict("exchange restored file with destination failed", err)
	}
	if d.afterExchange != nil {
		d.afterExchange()
	}
	published, publishErr := d.readRegular(destination, restoreConfigLimit)
	displaced, displacedErr := d.readRegular(temporary, restoreConfigLimit)
	if publishErr != nil || displacedErr != nil || !sameRenamedRegularSnapshot(published, committed) ||
		!sameRenamedRegularSnapshot(displaced, expectedDestination) {
		return regularSnapshot{}, true, d.recordConflict(
			"restore exchange changed concurrently; entries retained at "+d.host(destination)+" and "+d.host(temporary),
			publishErr, displacedErr,
		)
	}
	if err := d.sync(); err != nil {
		return regularSnapshot{}, true, d.recordConflict(
			"sync restore exchange; entries retained at "+d.host(destination)+" and "+d.host(temporary),
			err,
		)
	}
	if err := d.removeValidated(temporary, expectedDestination); err != nil {
		return regularSnapshot{}, true, fmt.Errorf("remove displaced destination: %w", err)
	}
	if err := d.sync(); err != nil {
		return regularSnapshot{}, true, d.recordConflict("sync completed restore exchange", err)
	}
	return published, false, nil
}

// removeValidated first moves the current directory entry to a private name.
// The move and subsequent inode/content check bind deletion to the exact file
// that was validated, while a concurrent replacement remains at destination.
func (d *restoreDirectory) removeValidated(name string, expected regularSnapshot) error {
	placeholder, quarantine, err := d.newTemporary(restorePurgePrefix)
	if err != nil {
		return err
	}
	if err := placeholder.Close(); err != nil {
		return d.cleanupUncommittedPlaceholder(quarantine, err)
	}
	if err := syscall.Renameat(int(d.file.Fd()), name, int(d.file.Fd()), quarantine); err != nil {
		return errors.Join(
			fmt.Errorf("claim validated file; conflict marker retained at %s: %w", d.host(quarantine), err),
			d.sync(),
		)
	}
	moved, readErr := d.readRegular(quarantine, restoreConfigLimit)
	if readErr == nil && sameRenamedRegularSnapshot(moved, expected) {
		if err := d.remove(quarantine); err != nil {
			return fmt.Errorf("remove validated file retained at %s: %w", d.host(quarantine), err)
		}
		if err := d.sync(); err != nil {
			return d.recordConflict("sync validated file removal", err)
		}
		return nil
	}

	// Put an unexpected entry back without overwriting a newer concurrent write,
	// and retain the private hard link so a later purge cannot reinterpret it.
	linkErr := linkRestoreEntry(int(d.file.Fd()), quarantine, name)
	if linkErr == nil {
		return errors.Join(
			errors.New("validated file changed before removal; unexpected entry retained at "+d.host(quarantine)),
			readErr, d.sync(),
		)
	}
	return errors.Join(
		errors.New("validated file changed before removal; unexpected entry retained at "+d.host(quarantine)),
		readErr, linkErr, d.sync(),
	)
}

func linkRestoreEntry(directory int, oldName, newName string) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_LINKAT,
		uintptr(directory), uintptr(unsafe.Pointer(oldPointer)),
		uintptr(directory), uintptr(unsafe.Pointer(newPointer)), 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

const (
	restoreRenameNoReplace = 1
	restoreRenameExchange  = 2
)

func renameRestoreEntry(directory int, oldName, newName string, flags uintptr) error {
	oldPointer, err := syscall.BytePtrFromString(oldName)
	if err != nil {
		return err
	}
	newPointer, err := syscall.BytePtrFromString(newName)
	if err != nil {
		return err
	}
	systemCall := restoreRenameat2SystemCall()
	if systemCall == 0 {
		return syscall.ENOSYS
	}
	_, _, errno := syscall.Syscall6(
		systemCall,
		uintptr(directory), uintptr(unsafe.Pointer(oldPointer)),
		uintptr(directory), uintptr(unsafe.Pointer(newPointer)), flags, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func restoreRenameat2SystemCall() uintptr {
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

func preserveRestoreMetadata(source regularSnapshot, target *os.File) error {
	if stat, ok := source.info.Sys().(*syscall.Stat_t); ok {
		if err := target.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
			return fmt.Errorf("preserve file ownership: %w", err)
		}
	}
	mode := source.info.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
	if err := target.Chmod(mode); err != nil {
		return fmt.Errorf("preserve file mode: %w", err)
	}
	if err := applyRestoreXattrs(source.xattrs, source.xattrsSupported, target); err != nil {
		return err
	}
	stamp := syscall.NsecToTimespec(source.info.ModTime().UnixNano())
	times := [2]syscall.Timespec{stamp, stamp}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_UTIMENSAT,
		target.Fd(), 0, uintptr(unsafe.Pointer(&times[0])), 0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("preserve file mtime: %w", errno)
	}
	return nil
}

func applyRestoreXattrs(xattrs map[string][]byte, supported bool, target *os.File) error {
	if !supported {
		return nil
	}
	targetAttrs, targetSupported, err := readRestoreXattrs(target)
	if err != nil {
		return err
	}
	if !targetSupported {
		if len(xattrs) == 0 {
			return nil
		}
		return errors.New("destination filesystem does not support source xattrs")
	}
	for name := range targetAttrs {
		if _, keep := xattrs[name]; keep {
			continue
		}
		if err := restoreFRemoveXattr(target, name); err != nil && !errors.Is(err, syscall.ENODATA) {
			return fmt.Errorf("remove inherited xattr %s: %w", name, err)
		}
	}
	for name, value := range xattrs {
		if err := restoreFSetXattr(target, name, value); err != nil {
			return fmt.Errorf("preserve xattr %s: %w", name, err)
		}
	}
	return nil
}

func readRestoreXattrs(file *os.File) (map[string][]byte, bool, error) {
	size, err := restoreFListXattr(file, nil)
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("list file xattrs: %w", err)
	}
	if size == 0 {
		return map[string][]byte{}, true, nil
	}
	if size < 0 || size > restoreXattrNameLimit {
		return nil, false, errors.New("xattr name list exceeds 1 MiB")
	}
	names := make([]byte, size)
	n, err := restoreFListXattr(file, names)
	if err != nil {
		return nil, false, fmt.Errorf("read file xattr names: %w", err)
	}
	result := make(map[string][]byte)
	total := 0
	for _, name := range strings.Split(string(names[:n]), "\x00") {
		if name == "" {
			continue
		}
		valueSize, err := restoreFGetXattr(file, name, nil)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("read xattr %s size: %w", name, err)
		}
		if valueSize < 0 || valueSize > restoreXattrValueLimit || total+valueSize > restoreXattrTotalLimit {
			return nil, false, errors.New("xattr data exceeds safety limit")
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			n, err = restoreFGetXattr(file, name, value)
			if err != nil {
				return nil, false, fmt.Errorf("read xattr %s: %w", name, err)
			}
			value = value[:n]
		}
		result[name] = value
		total += len(value)
	}
	return result, true, nil
}

func restoreFListXattr(file *os.File, destination []byte) (int, error) {
	result, _, errno := syscall.Syscall(
		syscall.SYS_FLISTXATTR,
		file.Fd(), restoreByteSlicePointer(destination), uintptr(len(destination)),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}

func restoreFGetXattr(file *os.File, name string, destination []byte) (int, error) {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	result, _, errno := syscall.Syscall6(
		syscall.SYS_FGETXATTR,
		file.Fd(), uintptr(unsafe.Pointer(namePointer)),
		restoreByteSlicePointer(destination), uintptr(len(destination)), 0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}

func restoreFSetXattr(file *os.File, name string, value []byte) error {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		file.Fd(), uintptr(unsafe.Pointer(namePointer)),
		restoreByteSlicePointer(value), uintptr(len(value)), 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func restoreFRemoveXattr(file *os.File, name string) error {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_FREMOVEXATTR,
		file.Fd(), uintptr(unsafe.Pointer(namePointer)), 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func restoreByteSlicePointer(value []byte) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&value[0]))
}

package installer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	"syscall"
	"unsafe"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

func (f *RootFS) WriteFileAtomic(logicalPath string, data []byte, perm fs.FileMode) (returnErr error) {
	directory, file, temporary, destination, err := f.newAtomicFile(logicalPath)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			returnErr = errors.Join(returnErr, cleanupAtomicFile(directory, file, temporary))
		}
		returnErr = errors.Join(returnErr, file.Close(), directory.Close())
	}()
	if err := file.Chmod(perm.Perm()); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := f.publishAtomicFile(directory, file, temporary, destination); err != nil {
		return err
	}
	committed = true
	return directory.Sync()
}

// CopyRegularFileAtomic copies contents and rollback-relevant metadata from a
// source inode trusted by the current process: current-euid ownership, no
// group/other write bits, and exactly one hard link.
func (f *RootFS) CopyRegularFileAtomic(source, destination string, maxBytes int64) error {
	return f.CopyTrustedRegularFileAtomic(source, destination, maxBytes, uint32(os.Geteuid()))
}

// CopyTrustedRegularFileAtomic additionally requires the opened source inode
// to be owned by ownerUID, non-writable by group/other, and singly linked. This
// keeps an untrusted source owner from modifying the temporary inode after its
// metadata has been preserved but before it is atomically published.
func (f *RootFS) CopyTrustedRegularFileAtomic(source, destination string, maxBytes int64, ownerUID uint32) error {
	return f.copyRegularFileAtomicValidated(source, destination, maxBytes, func(info fs.FileInfo) error {
		if err := filetrust.ValidateRegular(info, int(ownerUID), 0o022, true); err != nil {
			return fmt.Errorf("unsafe source file: %w", err)
		}
		return nil
	}, nil)
}

// ValidateTrustedRegularFile performs every source-side operation required by
// CopyTrustedRegularFileAtomic: it reads the complete contents and xattrs and
// verifies that both the opened inode and its path remain stable throughout.
// Recovery uses this before changing any managed host path so a corrupt later
// snapshot cannot be discovered only after earlier paths were restored.
func (f *RootFS) ValidateTrustedRegularFile(source string, maxBytes int64, ownerUID uint32) error {
	return f.validateTrustedRegularFile(source, maxBytes, ownerUID, nil)
}

func (f *RootFS) validateTrustedRegularFile(source string, maxBytes int64, ownerUID uint32, checkpoint func(copyRegularFileCheckpoint)) error {
	if maxBytes < 0 {
		return errors.New("invalid negative file limit")
	}
	file, err := f.OpenFileNoFollow(source, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	state, err := regularFileStateFromInfo(info)
	if err != nil {
		return err
	}
	if err := filetrust.ValidateRegular(info, int(ownerUID), 0o022, true); err != nil {
		return fmt.Errorf("unsafe source file: %w", err)
	}
	if state.size < 0 || state.size > maxBytes {
		return fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	written, err := io.Copy(io.Discard, io.LimitReader(file, limitWithOverflowByte(maxBytes)))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	if written != state.size {
		return errors.New("source file changed while validating copy")
	}
	if checkpoint != nil {
		checkpoint(copyRegularFileContentsCopied)
	}
	if err := f.revalidateRegularFileState(source, file, state); err != nil {
		return err
	}
	if _, _, err := readFileXattrs(file); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(copyRegularFileXattrsCaptured)
	}
	if err := f.revalidateRegularFileState(source, file, state); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(copyRegularFileReadyToPublish)
	}
	return f.revalidateRegularFileState(source, file, state)
}

// The checkpoint is nil in production and lets tests deterministically modify
// the source at consistency boundaries.
func (f *RootFS) copyRegularFileAtomic(source, destination string, maxBytes int64, checkpoint func(copyRegularFileCheckpoint)) (returnErr error) {
	return f.copyRegularFileAtomicValidated(source, destination, maxBytes, nil, checkpoint)
}

func (f *RootFS) copyRegularFileAtomicValidated(source, destination string, maxBytes int64, validateSource func(fs.FileInfo) error, checkpoint func(copyRegularFileCheckpoint)) (returnErr error) {
	if maxBytes < 0 {
		return errors.New("invalid negative file limit")
	}
	sourceFile, err := f.OpenFileNoFollow(source, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer sourceFile.Close()
	sourceInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}
	sourceState, err := regularFileStateFromInfo(sourceInfo)
	if err != nil {
		return err
	}
	if !sourceInfo.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if validateSource != nil {
		if err := validateSource(sourceInfo); err != nil {
			return err
		}
	}
	if sourceState.size < 0 || sourceState.size > maxBytes {
		return fmt.Errorf("file exceeds %d bytes", maxBytes)
	}

	directory, targetFile, temporary, targetName, err := f.newAtomicFile(destination)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			returnErr = errors.Join(returnErr, cleanupAtomicFile(directory, targetFile, temporary))
		}
		returnErr = errors.Join(returnErr, targetFile.Close(), directory.Close())
	}()

	written, err := io.Copy(targetFile, io.LimitReader(sourceFile, limitWithOverflowByte(maxBytes)))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	if checkpoint != nil {
		checkpoint(copyRegularFileContentsCopied)
	}
	if written != sourceState.size {
		return errors.New("source file changed while copying")
	}
	if err := f.revalidateRegularFileState(source, sourceFile, sourceState); err != nil {
		return err
	}
	sourceXattrs, sourceXattrsSupported, err := readFileXattrs(sourceFile)
	if err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(copyRegularFileXattrsCaptured)
	}
	if err := f.revalidateRegularFileState(source, sourceFile, sourceState); err != nil {
		return err
	}
	if err := preserveRegularMetadata(sourceInfo, sourceXattrs, sourceXattrsSupported, targetFile); err != nil {
		return err
	}
	if err := targetFile.Sync(); err != nil {
		return err
	}
	if checkpoint != nil {
		checkpoint(copyRegularFileReadyToPublish)
	}
	if err := f.revalidateRegularFileState(source, sourceFile, sourceState); err != nil {
		return err
	}
	if err := f.publishAtomicFile(directory, targetFile, temporary, targetName); err != nil {
		return err
	}
	committed = true
	return directory.Sync()
}

func limitWithOverflowByte(maxBytes int64) int64 {
	if maxBytes == int64(^uint64(0)>>1) {
		return maxBytes
	}
	return maxBytes + 1
}

func regularFileStateFromInfo(info fs.FileInfo) (regularFileState, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return regularFileState{}, errors.New("source file identity metadata is unavailable")
	}
	return regularFileState{
		device:    uint64(stat.Dev),
		inode:     uint64(stat.Ino),
		mode:      uint32(stat.Mode),
		linkCount: uint64(stat.Nlink),
		uid:       uint32(stat.Uid),
		gid:       uint32(stat.Gid),
		size:      stat.Size,
		mtime:     stat.Mtim,
		ctime:     stat.Ctim,
	}, nil
}

func (f *RootFS) revalidateRegularFileState(source string, file *os.File, expected regularFileState) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	current, err := regularFileStateFromInfo(info)
	if err != nil {
		return err
	}
	if current != expected {
		return errors.New("source file changed while copying")
	}
	pathInfo, err := f.Lstat(source)
	if err != nil {
		return fmt.Errorf("reinspect source path while copying: %w", err)
	}
	pathState, err := regularFileStateFromInfo(pathInfo)
	if err != nil {
		return err
	}
	if pathState != expected {
		return errors.New("source path changed while copying")
	}
	return nil
}

func (f *RootFS) newAtomicFile(logicalPath string) (*os.File, *os.File, string, string, error) {
	directory, destination, err := f.openParent(logicalPath)
	if err != nil {
		return nil, nil, "", "", err
	}
	for range temporaryAttempts {
		random := make([]byte, 16)
		if _, err := rand.Read(random); err != nil {
			_ = directory.Close()
			return nil, nil, "", "", err
		}
		temporary := ".security-update-notify." + hex.EncodeToString(random)
		fd, openErr := syscall.Openat(
			int(directory.Fd()), temporary,
			syscall.O_CREAT|syscall.O_EXCL|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0o600,
		)
		if openErr == nil {
			file := os.NewFile(uintptr(fd), logicalPath)
			if file == nil {
				_ = syscall.Close(fd)
				_ = syscall.Unlinkat(int(directory.Fd()), temporary)
				_ = directory.Close()
				return nil, nil, "", "", errors.New("could not create atomic file handle")
			}
			return directory, file, temporary, destination, nil
		}
		if !errors.Is(openErr, fs.ErrExist) {
			_ = directory.Close()
			return nil, nil, "", "", openErr
		}
	}
	_ = directory.Close()
	return nil, nil, "", "", errors.New("could not create atomic temporary file")
}

func (f *RootFS) publishAtomicFile(directory, file *os.File, temporary, destination string) error {
	if f.beforeAtomicPublish != nil {
		if err := f.beforeAtomicPublish(directory, temporary); err != nil {
			return err
		}
	}
	owned, err := atomicEntryMatchesFile(directory, temporary, file)
	if err != nil || !owned {
		return errors.Join(
			errors.New("atomic temporary file changed before publish: "+temporary),
			err,
		)
	}
	return syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), destination)
}

func atomicEntryMatchesFile(directory *os.File, name string, file *os.File) (bool, error) {
	expected, err := file.Stat()
	if err != nil {
		return false, err
	}
	fd, err := syscall.Openat(
		int(directory.Fd()), name,
		oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return false, err
	}
	entry := os.NewFile(uintptr(fd), name)
	if entry == nil {
		_ = syscall.Close(fd)
		return false, errors.New("could not create atomic entry handle")
	}
	current, statErr := entry.Stat()
	closeErr := entry.Close()
	if statErr != nil || closeErr != nil {
		return false, errors.Join(statErr, closeErr)
	}
	if !expected.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(expected, current) {
		return false, nil
	}
	expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
	currentStat, currentOK := current.Sys().(*syscall.Stat_t)
	if !expectedOK || !currentOK || expectedStat.Nlink != 1 || currentStat.Nlink != 1 {
		return false, nil
	}
	return true, nil
}

func cleanupAtomicFile(directory, file *os.File, name string) error {
	owned, err := atomicEntryMatchesFile(directory, name, file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || !owned {
		return errors.Join(errors.New("atomic temporary entry changed; retained at "+name), err)
	}
	if err := syscall.Unlinkat(int(directory.Fd()), name); err != nil {
		return fmt.Errorf("remove atomic temporary retained at %s: %w", name, err)
	}
	return nil
}

func preserveRegularMetadata(sourceInfo fs.FileInfo, sourceXattrs map[string][]byte, sourceXattrsSupported bool, target *os.File) error {
	targetInfo, err := target.Stat()
	if err != nil {
		return err
	}
	sourceStat, sourceOK := sourceInfo.Sys().(*syscall.Stat_t)
	targetStat, targetOK := targetInfo.Sys().(*syscall.Stat_t)
	if sourceOK && (!targetOK || sourceStat.Uid != targetStat.Uid || sourceStat.Gid != targetStat.Gid) {
		if err := target.Chown(int(sourceStat.Uid), int(sourceStat.Gid)); err != nil {
			return fmt.Errorf("preserve file ownership: %w", err)
		}
	}
	mode := sourceInfo.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)
	if err := target.Chmod(mode); err != nil {
		return fmt.Errorf("preserve file mode: %w", err)
	}
	if err := applyFileXattrs(target, sourceXattrs, sourceXattrsSupported); err != nil {
		return err
	}
	stamp := syscall.NsecToTimespec(sourceInfo.ModTime().UnixNano())
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

func applyFileXattrs(target *os.File, xattrs map[string][]byte, supported bool) error {
	if !supported {
		return nil
	}
	targetAttrs, targetSupported, err := readFileXattrs(target)
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
		if err := fremovexattr(target, name); err != nil && !errors.Is(err, syscall.ENODATA) {
			return fmt.Errorf("remove inherited xattr %s: %w", name, err)
		}
	}
	for name, value := range xattrs {
		if err := fsetxattr(target, name, value); err != nil {
			return fmt.Errorf("preserve xattr %s: %w", name, err)
		}
	}
	return nil
}

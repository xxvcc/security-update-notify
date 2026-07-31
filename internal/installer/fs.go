package installer

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

const (
	maxXattrNameBytes  = 1 << 20
	maxXattrValueBytes = 1 << 20
	maxXattrTotalBytes = 16 << 20
	atRemoveDir        = 0x200
	oPath              = 0x200000
	maxSymlinkDepth    = 40
	temporaryAttempts  = 1000
	removalPrefix      = ".security-update-notify-remove."
)

// RootFS applies logical absolute paths below Root. Root "/" addresses the
// real host; a temporary Root gives integration tests a private filesystem.
// Every operation walks from an open root directory descriptor with
// O_NOFOLLOW, so a concurrent symlink replacement cannot redirect it outside
// the selected root. The one accepted ancestor alias is Fedora's package-owned
// /usr/local/sbin -> bin layout; the walker validates that exact link text and
// opens /usr/local/bin directly from the already-open /usr/local descriptor.
type RootFS struct {
	Root string
	root *os.File

	// Tests use this hook to replace an atomic temporary entry at the last
	// consistency boundary. Production instances leave it nil.
	beforeAtomicPublish func(directory *os.File, temporary string) error
}

type regularFileState struct {
	device    uint64
	inode     uint64
	mode      uint32
	linkCount uint64
	uid       uint32
	gid       uint32
	size      int64
	mtime     syscall.Timespec
	ctime     syscall.Timespec
}

type copyRegularFileCheckpoint uint8

const (
	copyRegularFileContentsCopied copyRegularFileCheckpoint = iota
	copyRegularFileXattrsCaptured
	copyRegularFileReadyToPublish
)

func NewRootFS(root string) (*RootFS, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, fmt.Errorf("filesystem root must be absolute")
	}
	clean := filepath.Clean(root)
	if err := rejectSymlinkedRoot(clean); err != nil {
		return nil, err
	}
	opened, err := openHostRoot(clean)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root: %w", err)
	}
	return &RootFS{Root: clean, root: opened}, nil
}

func rejectSymlinkedRoot(root string) error {
	if root == string(filepath.Separator) {
		return nil
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(root, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect filesystem root component: %w", err)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("filesystem root contains a symlinked component: %s", current)
		}
		if !info.IsDir() {
			return fmt.Errorf("filesystem root component is not a directory: %s", current)
		}
	}
	return nil
}

func openHostRoot(root string) (*os.File, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	current := os.NewFile(uintptr(fd), "/")
	if current == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create filesystem root handle")
	}
	if root == "/" {
		return current, nil
	}
	for _, component := range strings.Split(strings.TrimPrefix(root, "/"), "/") {
		if component == "" {
			continue
		}
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil {
			_ = current.Close()
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, errors.New("could not create filesystem component handle")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func cleanLogicalPath(logicalPath string) (string, error) {
	if !path.IsAbs(logicalPath) {
		return "", fmt.Errorf("logical path must be absolute: %q", logicalPath)
	}
	return path.Clean(logicalPath), nil
}

func (f *RootFS) duplicateRoot() (*os.File, error) {
	fd, err := syscall.Dup(int(f.root.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	duplicate := os.NewFile(uintptr(fd), f.Root)
	if duplicate == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not duplicate filesystem root handle")
	}
	return duplicate, nil
}

func (f *RootFS) openDir(logicalPath string, create bool, perm fs.FileMode) (*os.File, error) {
	clean, err := cleanLogicalPath(logicalPath)
	if err != nil {
		return nil, err
	}
	current, err := f.duplicateRoot()
	if err != nil {
		return nil, err
	}
	if clean == "/" {
		return current, nil
	}
	walked := ""
	for _, component := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		walked += "/" + component
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if openErr != nil && walked == "/usr/local/sbin" && validLocalSbinAliasAt(current, component) {
			// Never follow the link itself. Opening its fixed sibling target from
			// the held parent descriptor keeps replacement races contained.
			nextFD, openErr = syscall.Openat(
				int(current.Fd()), "bin",
				syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
				0,
			)
		}
		if errors.Is(openErr, fs.ErrNotExist) && create {
			if mkdirErr := syscall.Mkdirat(int(current.Fd()), component, uint32(perm.Perm())); mkdirErr != nil && !errors.Is(mkdirErr, fs.ErrExist) {
				_ = current.Close()
				return nil, mkdirErr
			}
			nextFD, openErr = syscall.Openat(
				int(current.Fd()), component,
				syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
				0,
			)
		}
		if openErr != nil {
			_ = current.Close()
			if errors.Is(openErr, syscall.ELOOP) || errors.Is(openErr, syscall.ENOTDIR) {
				return nil, fmt.Errorf("symlinked path component or non-directory component is forbidden: %s", logicalPath)
			}
			return nil, openErr
		}
		next := os.NewFile(uintptr(nextFD), component)
		if next == nil {
			_ = syscall.Close(nextFD)
			_ = current.Close()
			return nil, errors.New("could not create directory handle")
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func validLocalSbinAliasAt(parent *os.File, component string) bool {
	var target [4]byte
	n, err := readlinkat(int(parent.Fd()), component, target[:])
	return err == nil && n == len("bin") && string(target[:n]) == "bin"
}

func (f *RootFS) openParent(logicalPath string) (*os.File, string, error) {
	clean, err := cleanLogicalPath(logicalPath)
	if err != nil {
		return nil, "", err
	}
	if clean == "/" {
		return nil, "", errors.New("filesystem root has no removable leaf")
	}
	directory, err := f.openDir(path.Dir(clean), false, 0)
	if err != nil {
		return nil, "", err
	}
	return directory, path.Base(clean), nil
}

func (f *RootFS) Lstat(logicalPath string) (fs.FileInfo, error) {
	clean, err := cleanLogicalPath(logicalPath)
	if err != nil {
		return nil, err
	}
	if clean == "/" {
		return f.root.Stat()
	}
	directory, name, err := f.openParent(clean)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := syscall.Openat(
		int(directory.Fd()), name,
		oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), clean)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create lstat file handle")
	}
	defer file.Close()
	return file.Stat()
}

// ReadFile is deliberately no-follow at every component. Files with a
// legitimate leaf symlink, such as /etc/os-release, use ReadFileFollow.
func (f *RootFS) ReadFile(logicalPath string) ([]byte, error) {
	data, _, err := f.ReadRegularFile(logicalPath, int64(^uint64(0)>>1)-1)
	return data, err
}

// ReadFileFollow follows only leaf symlinks. Each target is normalized as a
// logical path below Root and every ancestor is still opened with O_NOFOLLOW.
func (f *RootFS) ReadFileFollow(logicalPath string, maxBytes int64) ([]byte, fs.FileInfo, error) {
	current, err := cleanLogicalPath(logicalPath)
	if err != nil {
		return nil, nil, err
	}
	seen := make(map[string]bool)
	for depth := 0; depth < maxSymlinkDepth; depth++ {
		if seen[current] {
			return nil, nil, errors.New("symbolic link cycle")
		}
		seen[current] = true
		file, openErr := f.OpenFileNoFollow(current, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if openErr == nil {
			defer file.Close()
			return readOpenedRegularFile(file, maxBytes)
		}
		target, linkErr := f.Readlink(current)
		if linkErr != nil {
			return nil, nil, openErr
		}
		if path.IsAbs(target) {
			current = path.Clean(target)
		} else {
			current = path.Clean(path.Join(path.Dir(current), target))
		}
		if !path.IsAbs(current) {
			current = "/" + current
		}
	}
	return nil, nil, errors.New("too many symbolic links")
}

// ReadRegularFile opens with O_NOFOLLOW and validates the already-open file,
// closing the usual lstat/open race for credential and managed-file reads.
func (f *RootFS) ReadRegularFile(logicalPath string, maxBytes int64) ([]byte, fs.FileInfo, error) {
	file, err := f.OpenFileNoFollow(logicalPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	return readOpenedRegularFile(file, maxBytes)
}

func readOpenedRegularFile(file *os.File, maxBytes int64) ([]byte, fs.FileInfo, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, info, errors.New("not a regular file")
	}
	if maxBytes < 0 || info.Size() < 0 || info.Size() > maxBytes {
		return nil, info, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, limitWithOverflowByte(maxBytes)))
	if err != nil {
		return nil, info, err
	}
	if int64(len(data)) > maxBytes {
		return nil, info, fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	return data, info, nil
}

func (f *RootFS) OpenFileNoFollow(logicalPath string, flag int, perm fs.FileMode) (*os.File, error) {
	clean, err := cleanLogicalPath(logicalPath)
	if err != nil {
		return nil, err
	}
	if clean == "/" {
		if flag&(os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_RDWR) != 0 {
			return nil, errors.New("refusing to modify filesystem root")
		}
		return f.duplicateRoot()
	}
	directory, name, err := f.openParent(clean)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	fd, err := syscall.Openat(
		int(directory.Fd()), name,
		flag|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		uint32(perm.Perm()),
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), clean)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("could not create file handle")
	}
	return file, nil
}

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

func readFileXattrs(file *os.File) (map[string][]byte, bool, error) {
	size, err := flistxattr(file, nil)
	if errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("list file xattrs: %w", err)
	}
	if size == 0 {
		return map[string][]byte{}, true, nil
	}
	if size < 0 || size > maxXattrNameBytes {
		return nil, false, errors.New("xattr name list exceeds 1 MiB")
	}
	names := make([]byte, size)
	n, err := flistxattr(file, names)
	if err != nil {
		return nil, false, fmt.Errorf("read file xattr names: %w", err)
	}
	result := make(map[string][]byte)
	total := 0
	for _, name := range strings.Split(string(names[:n]), "\x00") {
		if name == "" {
			continue
		}
		valueSize, err := fgetxattr(file, name, nil)
		if errors.Is(err, syscall.ENODATA) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("read xattr %s size: %w", name, err)
		}
		if valueSize < 0 || valueSize > maxXattrValueBytes || total+valueSize > maxXattrTotalBytes {
			return nil, false, errors.New("xattr data exceeds safety limit")
		}
		value := make([]byte, valueSize)
		if valueSize > 0 {
			n, err = fgetxattr(file, name, value)
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

func flistxattr(file *os.File, destination []byte) (int, error) {
	result, _, errno := syscall.Syscall(
		syscall.SYS_FLISTXATTR,
		file.Fd(), byteSlicePointer(destination), uintptr(len(destination)),
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}

func fgetxattr(file *os.File, name string, destination []byte) (int, error) {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	result, _, errno := syscall.Syscall6(
		syscall.SYS_FGETXATTR,
		file.Fd(), uintptr(unsafe.Pointer(namePointer)), byteSlicePointer(destination), uintptr(len(destination)), 0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}

func fsetxattr(file *os.File, name string, value []byte) error {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(
		syscall.SYS_FSETXATTR,
		file.Fd(), uintptr(unsafe.Pointer(namePointer)), byteSlicePointer(value), uintptr(len(value)), 0, 0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func fremovexattr(file *os.File, name string) error {
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

func byteSlicePointer(value []byte) uintptr {
	if len(value) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&value[0]))
}

func (f *RootFS) Mkdir(logicalPath string, perm fs.FileMode) error {
	directory, name, err := f.openParent(logicalPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	return syscall.Mkdirat(int(directory.Fd()), name, uint32(perm.Perm()))
}

func (f *RootFS) MkdirAll(logicalPath string, perm fs.FileMode) error {
	directory, err := f.openDir(logicalPath, true, perm)
	if err != nil {
		return err
	}
	return directory.Close()
}

func (f *RootFS) ReadDir(logicalPath string) ([]fs.DirEntry, error) {
	directory, err := f.openDir(logicalPath, false, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	return directory.ReadDir(-1)
}

func (f *RootFS) Readlink(logicalPath string) (string, error) {
	return f.readlink(logicalPath, nil)
}

func (f *RootFS) readlink(logicalPath string, beforeRead func() error) (string, error) {
	directory, name, err := f.openParent(logicalPath)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	fd, err := syscall.Openat(
		int(directory.Fd()), name,
		oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		return "", err
	}
	link := os.NewFile(uintptr(fd), logicalPath)
	if link == nil {
		_ = syscall.Close(fd)
		return "", errors.New("could not create symbolic link handle")
	}
	defer link.Close()
	info, err := link.Stat()
	if err != nil {
		return "", err
	}
	if info.Mode()&fs.ModeSymlink == 0 {
		return "", errors.New("not a symbolic link")
	}
	if beforeRead != nil {
		if err := beforeRead(); err != nil {
			return "", err
		}
	}
	size := 256
	for size <= maxXattrNameBytes {
		buffer := make([]byte, size)
		n, readErr := readlinkat(int(link.Fd()), "", buffer)
		if readErr != nil {
			return "", readErr
		}
		if n < len(buffer) {
			return string(buffer[:n]), nil
		}
		size *= 2
	}
	return "", errors.New("symbolic link target exceeds 1 MiB")
}

func readlinkat(directory int, name string, destination []byte) (int, error) {
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, err
	}
	result, _, errno := syscall.Syscall6(
		syscall.SYS_READLINKAT,
		uintptr(directory), uintptr(unsafe.Pointer(namePointer)), byteSlicePointer(destination), uintptr(len(destination)), 0, 0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(result), nil
}

func (f *RootFS) Symlink(target, logicalPath string) error {
	directory, name, err := f.openParent(logicalPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	targetPointer, err := syscall.BytePtrFromString(target)
	if err != nil {
		return err
	}
	namePointer, err := syscall.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall(
		syscall.SYS_SYMLINKAT,
		uintptr(unsafe.Pointer(targetPointer)), directory.Fd(), uintptr(unsafe.Pointer(namePointer)),
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func (f *RootFS) Chmod(logicalPath string, perm fs.FileMode) error {
	file, err := f.OpenFileNoFollow(logicalPath, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Chmod(perm)
}

// Remove has rm -f semantics: it may unlink a file or symlink, but it never
// broadens scope to removing a directory, including under a replacement race.
func (f *RootFS) Remove(logicalPath string) error {
	return f.remove(logicalPath, nil)
}

func (f *RootFS) remove(logicalPath string, beforeClaim func() error) error {
	directory, name, err := f.openParent(logicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
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

func (f *RootFS) removeAll(logicalPath string, beforeClaim func() error) error {
	directory, name, err := f.openParent(logicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
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
	suffix, found := strings.CutPrefix(name, removalPrefix)
	if !found || len(suffix) != 32 {
		return false
	}
	_, err := hex.DecodeString(suffix)
	return err == nil
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
		expected, err := readRemovalEntry(parent, entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			err = removeValidatedEntryAt(parent, entry.Name(), expected, true, nil)
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
	if !claimed.IsDir() {
		if err := syscall.Unlinkat(int(parent.Fd()), quarantine); err != nil {
			return fmt.Errorf("remove claimed entry retained at %s: %w", quarantine, err)
		}
		return nil
	}
	if !recursive {
		return restoreUnexpectedRemovalClaim(parent, quarantine, name, errors.New("validated leaf became a directory"))
	}
	if claimedDirectory == nil {
		return restoreUnexpectedRemovalClaim(parent, quarantine, name, errors.New("validated directory handle is unavailable"))
	}
	entries, err := claimedDirectory.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := removeAllAt(claimedDirectory, entry.Name()); err != nil {
			return fmt.Errorf("remove quarantined tree retained at %s: %w", quarantine, err)
		}
	}
	return unlinkRemovalDirectory(parent, quarantine, expected)
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

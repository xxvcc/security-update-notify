package installer

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const (
	maxXattrNameBytes  = 1 << 20
	maxXattrValueBytes = 1 << 20
	maxXattrTotalBytes = 16 << 20
	atRemoveDir        = 0x200
	oPath              = 0x200000
	maxSymlinkDepth    = 40
)

// RootFS applies logical absolute paths below Root. Root "/" addresses the
// real host; a temporary Root gives integration tests a private filesystem.
// Every operation walks from an open root directory descriptor with
// O_NOFOLLOW, so a concurrent symlink replacement cannot redirect it outside
// the selected root.
type RootFS struct {
	Root string
	root *os.File
}

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
	for _, component := range strings.Split(strings.TrimPrefix(clean, "/"), "/") {
		nextFD, openErr := syscall.Openat(
			int(current.Fd()), component,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
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
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
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

func (f *RootFS) WriteFileAtomic(logicalPath string, data []byte, perm fs.FileMode) error {
	directory, file, temporary, destination, err := f.newAtomicFile(logicalPath)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = syscall.Unlinkat(int(directory.Fd()), temporary)
		}
		_ = directory.Close()
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
	if err := file.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), destination); err != nil {
		return err
	}
	committed = true
	return directory.Sync()
}

// CopyRegularFileAtomic copies contents and the rollback-relevant metadata that
// cp -a preserved in the shell installer: owner, mode, mtime, and xattrs (ACLs
// are represented by system.posix_acl_* xattrs on Linux).
func (f *RootFS) CopyRegularFileAtomic(source, destination string, maxBytes int64) error {
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
	if !sourceInfo.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if sourceInfo.Size() < 0 || sourceInfo.Size() > maxBytes {
		return fmt.Errorf("file exceeds %d bytes", maxBytes)
	}

	directory, targetFile, temporary, targetName, err := f.newAtomicFile(destination)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = targetFile.Close()
		if !committed {
			_ = syscall.Unlinkat(int(directory.Fd()), temporary)
		}
		_ = directory.Close()
	}()

	written, err := io.Copy(targetFile, io.LimitReader(sourceFile, maxBytes+1))
	if err != nil {
		return err
	}
	if written > maxBytes {
		return fmt.Errorf("file exceeds %d bytes", maxBytes)
	}
	finalSourceInfo, err := sourceFile.Stat()
	if err != nil {
		return err
	}
	if written != sourceInfo.Size() || finalSourceInfo.Size() != sourceInfo.Size() {
		return errors.New("source file changed while copying")
	}
	if err := preserveRegularMetadata(sourceFile, sourceInfo, targetFile); err != nil {
		return err
	}
	if err := targetFile.Sync(); err != nil {
		return err
	}
	if err := targetFile.Close(); err != nil {
		return err
	}
	if err := syscall.Renameat(int(directory.Fd()), temporary, int(directory.Fd()), targetName); err != nil {
		return err
	}
	committed = true
	return directory.Sync()
}

func (f *RootFS) newAtomicFile(logicalPath string) (*os.File, *os.File, string, string, error) {
	directory, destination, err := f.openParent(logicalPath)
	if err != nil {
		return nil, nil, "", "", err
	}
	for sequence := 0; sequence < 1000; sequence++ {
		temporary := fmt.Sprintf(".security-update-notify.%d.%d", os.Getpid(), sequence)
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

func preserveRegularMetadata(source *os.File, sourceInfo fs.FileInfo, target *os.File) error {
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
	if err := copyFileXattrs(source, target); err != nil {
		return err
	}
	stamp := syscall.NsecToTimeval(sourceInfo.ModTime().UnixNano())
	if err := syscall.Futimes(int(target.Fd()), []syscall.Timeval{stamp, stamp}); err != nil {
		return fmt.Errorf("preserve file mtime: %w", err)
	}
	return nil
}

func copyFileXattrs(source, target *os.File) error {
	xattrs, supported, err := readFileXattrs(source)
	if err != nil {
		return err
	}
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
	directory, name, err := f.openParent(logicalPath)
	if err != nil {
		return "", err
	}
	defer directory.Close()
	size := 256
	for size <= maxXattrNameBytes {
		buffer := make([]byte, size)
		n, readErr := readlinkat(int(directory.Fd()), name, buffer)
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
	directory, name, err := f.openParent(logicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	err = syscall.Unlinkat(int(directory.Fd()), name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func (f *RootFS) RemoveAll(logicalPath string) error {
	directory, name, err := f.openParent(logicalPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer directory.Close()
	return removeAllAt(directory, name)
}

func removeAllAt(parent *os.File, name string) error {
	fd, err := syscall.Openat(
		int(parent.Fd()), name,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
			err = syscall.Unlinkat(int(parent.Fd()), name)
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		return err
	}
	directory := os.NewFile(uintptr(fd), name)
	if directory == nil {
		_ = syscall.Close(fd)
		return errors.New("could not create recursive directory handle")
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
	_, _, errno := syscall.Syscall6(
		syscall.SYS_UNLINKAT,
		parent.Fd(), uintptr(unsafe.Pointer(syscall.StringBytePtr(name))), atRemoveDir, 0, 0, 0,
	)
	if errno != 0 && !errors.Is(errno, fs.ErrNotExist) {
		return errno
	}
	return nil
}

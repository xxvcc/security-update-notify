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

package installer

import (
	"errors"

	"io/fs"
	"os"

	"syscall"
	"unsafe"
)

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

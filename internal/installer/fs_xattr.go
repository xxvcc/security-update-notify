package installer

import (
	"errors"
	"fmt"

	"os"

	"strings"
	"syscall"
	"unsafe"
)

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

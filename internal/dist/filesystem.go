package dist

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func openRealDirectory(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), path)
	if directory == nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("create directory handle")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		_ = directory.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("not a directory")
	}
	return directory, nil
}

func createPrivateTempFileAt(directory *os.File, prefix string) (*os.File, string, error) {
	if directory == nil || prefix == "" || filepath.Base(prefix) != prefix {
		return nil, "", fmt.Errorf("invalid temporary-file request")
	}
	for attempt := 0; attempt < 100; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:])
		fd, err := syscall.Openat(
			int(directory.Fd()), name,
			syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
			0o600,
		)
		if err == syscall.EEXIST {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = syscall.Close(fd)
			_ = syscall.Unlinkat(int(directory.Fd()), name)
			return nil, "", fmt.Errorf("create temporary-file handle")
		}
		return file, name, nil
	}
	return nil, "", fmt.Errorf("could not allocate a unique temporary filename")
}

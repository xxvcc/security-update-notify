package filetrust

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const temporaryDirectoryAttempts = 100

// MkdirTemp creates a mode-0700 directory without consulting TMPDIR. Every component of base must
// be a real directory owned by root or trustedUID. Group/other-writable components are accepted only
// with the sticky bit, so an untrusted user cannot replace a checked descendant. Creation is bound
// to the opened base descriptor with mkdirat instead of resolving the pathname again.
func MkdirTemp(base, prefix string, trustedUID int) (string, error) {
	if trustedUID < 0 {
		return "", errors.New("trusted uid must not be negative")
	}
	if prefix == "" || prefix == "." || prefix == ".." || filepath.Base(prefix) != prefix {
		return "", errors.New("temporary directory prefix must be a single path component")
	}
	baseDirectory, err := openTrustedDirectoryPath(base, trustedUID)
	if err != nil {
		return "", err
	}
	defer baseDirectory.Close()

	for attempt := 0; attempt < temporaryDirectoryAttempts; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", fmt.Errorf("generate temporary directory name: %w", err)
		}
		name := prefix + hex.EncodeToString(random[:])
		if err := syscall.Mkdirat(int(baseDirectory.Fd()), name, 0o700); err != nil {
			if errors.Is(err, syscall.EEXIST) {
				continue
			}
			return "", fmt.Errorf("create temporary directory: %w", err)
		}
		return filepath.Join(base, name), nil
	}
	return "", errors.New("could not allocate a unique temporary directory")
}

func openTrustedDirectoryPath(path string, trustedUID int) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("trusted directory path must be clean and absolute: %q", path)
	}
	openDirectory := func(directory *os.File, name, displayPath string) (*os.File, error) {
		fd := -1
		var err error
		if directory == nil {
			fd, err = syscall.Open(displayPath, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		} else {
			fd, err = syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		}
		if err != nil {
			return nil, err
		}
		opened := os.NewFile(uintptr(fd), displayPath)
		if opened == nil {
			_ = syscall.Close(fd)
			return nil, errors.New("create trusted directory handle")
		}
		if err := validateTemporaryDirectory(opened, trustedUID); err != nil {
			_ = opened.Close()
			return nil, fmt.Errorf("unsafe temporary directory path %s: %w", displayPath, err)
		}
		return opened, nil
	}

	current, err := openDirectory(nil, "", string(filepath.Separator))
	if err != nil {
		return nil, fmt.Errorf("open trusted directory root: %w", err)
	}
	if path == string(filepath.Separator) {
		return current, nil
	}
	displayPath := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		displayPath = filepath.Join(displayPath, component)
		next, err := openDirectory(current, component, displayPath)
		_ = current.Close()
		if err != nil {
			return nil, err
		}
		current = next
	}
	return current, nil
}

func validateTemporaryDirectory(directory *os.File, trustedUID int) error {
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("must be a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return errors.New("cannot verify owner")
	}
	if stat.Uid != 0 && uint64(stat.Uid) != uint64(trustedUID) {
		return fmt.Errorf("owner uid %d is neither root nor trusted uid %d", stat.Uid, trustedUID)
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("group/other-writable directory lacks sticky bit")
	}
	return nil
}

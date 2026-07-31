package releasepkg

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

const maxReleaseSignatureBytes int64 = 1 << 20

type regularFileState struct {
	info   os.FileInfo
	digest [sha256.Size]byte
}

func openBoundedRegular(path string, maxSize int64, singleLink bool) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, nil, fmt.Errorf("must be a bounded regular file: %w", err)
		}
		return nil, nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, fmt.Errorf("create regular-file handle")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || maxSize < 0 || maxSize > 0 && info.Size() > maxSize {
		_ = file.Close()
		return nil, nil, fmt.Errorf("must be a bounded regular file")
	}
	if singleLink {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat == nil || stat.Nlink != 1 {
			_ = file.Close()
			return nil, nil, fmt.Errorf("regular file must have exactly one hard link")
		}
	}
	return file, info, nil
}

func readOpenedRegular(file *os.File, info os.FileInfo, maxSize int64) ([]byte, error) {
	if file == nil || info == nil || info.Size() < 0 || info.Size() > maxSize {
		return nil, fmt.Errorf("invalid opened regular file")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	content, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) != info.Size() {
		return nil, fmt.Errorf("regular file changed size while being read")
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !sameRegularMetadata(info, after) {
		return nil, fmt.Errorf("regular file changed while being read")
	}
	return content, nil
}

func readBoundedRegularPath(path string, maxSize int64, singleLink bool) ([]byte, error) {
	file, info, err := openBoundedRegular(path, maxSize, singleLink)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := readOpenedRegular(file, info, maxSize)
	if err != nil {
		return nil, err
	}
	if err := validateOpenedRegularPath(path, info); err != nil {
		return nil, err
	}
	return content, nil
}

func captureRegularFileState(path string, maxSize int64) (regularFileState, error) {
	file, info, err := openBoundedRegular(path, maxSize, true)
	if err != nil {
		return regularFileState{}, err
	}
	defer file.Close()
	h := sha256.New()
	if _, err := io.CopyN(h, file, info.Size()); err != nil {
		return regularFileState{}, err
	}
	var extra [1]byte
	if count, err := file.Read(extra[:]); count != 0 || !errors.Is(err, io.EOF) {
		return regularFileState{}, fmt.Errorf("regular file changed size while being hashed")
	}
	after, err := file.Stat()
	if err != nil || !sameRegularMetadata(info, after) {
		return regularFileState{}, fmt.Errorf("regular file changed while being hashed")
	}
	current, err := os.Lstat(path)
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(info, current) || !sameRegularMetadata(info, current) {
		return regularFileState{}, fmt.Errorf("regular file path changed while being hashed")
	}
	state := regularFileState{info: info}
	copy(state.digest[:], h.Sum(nil))
	return state, nil
}

func verifyRegularFileState(path string, expected regularFileState, maxSize int64) error {
	current, err := captureRegularFileState(path, maxSize)
	if err != nil {
		return err
	}
	if expected.info == nil || !os.SameFile(expected.info, current.info) ||
		!sameRegularMetadata(expected.info, current.info) || expected.digest != current.digest {
		return fmt.Errorf("regular file changed after validation")
	}
	return nil
}

func validateOpenedRegularPath(path string, opened os.FileInfo) error {
	current, err := os.Lstat(path)
	if err != nil || opened == nil || !current.Mode().IsRegular() ||
		!os.SameFile(opened, current) || !sameRegularMetadata(opened, current) {
		return fmt.Errorf("regular file path changed while open")
	}
	return nil
}

func sameRegularMetadata(left, right fs.FileInfo) bool {
	return left != nil && right != nil && left.Mode() == right.Mode() &&
		left.Size() == right.Size() && left.ModTime().Equal(right.ModTime())
}

func writeExclusiveRegular(path string, content []byte, mode fs.FileMode) error {
	fd, err := syscall.Open(
		path,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		uint32(mode.Perm()),
	)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return fmt.Errorf("create output-file handle")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	ok = true
	return nil
}

package releasepkg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const releaseCommitLockPoll = 25 * time.Millisecond

func withReleaseCommitLock(ctx context.Context, distDir string, commit func(*os.File) error) error {
	directory, err := openPackageDirectory(distDir)
	if err != nil {
		return fmt.Errorf("open release output directory for locking: %w", err)
	}
	defer directory.Close()
	directoryInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect release output directory for locking: %w", err)
	}
	if !directoryInfo.IsDir() {
		return errors.New("release output path is not a directory")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ticker := time.NewTicker(releaseCommitLockPoll)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("wait for release commit lock: %w", err)
		}
		err := syscall.Flock(int(directory.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			defer syscall.Flock(int(directory.Fd()), syscall.LOCK_UN)
			current, err := os.Stat(distDir)
			if err != nil {
				return fmt.Errorf("revalidate release output directory: %w", err)
			}
			if !current.IsDir() || !os.SameFile(directoryInfo, current) {
				return errors.New("release output directory changed while waiting for the commit lock")
			}
			commitErr := commit(directory)
			current, pathErr := os.Stat(distDir)
			if pathErr != nil || !current.IsDir() || !os.SameFile(directoryInfo, current) {
				pathErr = errors.New("release output directory changed during artifact commit")
			}
			return errors.Join(commitErr, pathErr)
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("acquire release commit lock: %w", err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for release commit lock: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

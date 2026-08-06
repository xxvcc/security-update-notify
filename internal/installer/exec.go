package installer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/commandpath"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

const maxCommandOutput = 8 << 20

type cappedBuffer struct {
	b         bytes.Buffer
	max       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := b.max - b.b.Len(); remaining > 0 {
		if len(p) > remaining {
			_, _ = b.b.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.b.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

type ExecRunner struct {
	Resolve func(string) (string, error)
}

func (r ExecRunner) resolve(name string) (string, error) {
	if r.Resolve != nil {
		return r.Resolve(name)
	}
	return commandpath.Resolve(name)
}

func (r ExecRunner) LookPath(name string) bool {
	_, err := r.resolve(name)
	return err == nil
}

func (r ExecRunner) Run(parent context.Context, command Command) CommandResult {
	ctx := parent
	cancel := func() {}
	if command.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, command.Timeout)
	}
	defer cancel()

	resolved, err := r.resolve(command.Name)
	if err != nil {
		return CommandResult{Code: -1, Err: err}
	}
	cmd := sysexec.CommandContext(ctx, resolved, command.Args...)
	cmd.Env = commandEnv(command.Env)
	cmd.Stdin = bytes.NewReader(command.Stdin)
	cmd.ExtraFiles = command.ExtraFiles
	out := &cappedBuffer{max: maxCommandOutput}
	errOut := &cappedBuffer{max: maxCommandOutput}
	cmd.Stdout, cmd.Stderr = out, errOut
	err = cmd.Run()
	result := CommandResult{
		Stdout:          out.b.Bytes(),
		Stderr:          errOut.b.Bytes(),
		StdoutTruncated: out.truncated,
		StderrTruncated: errOut.truncated,
	}
	if err == nil {
		return result
	}
	if ctx.Err() != nil {
		result.Code, result.Err = -1, ctx.Err()
		return result
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.Code = exitErr.ExitCode()
		return result
	}
	result.Code, result.Err = -1, err
	return result
}

func commandEnv(overrides map[string]string) []string {
	return commandpath.SanitizedEnvironment(commandpath.EffectivePATH(), overrides)
}

type FileLocker struct {
	FS       FileSystem
	OwnerUID uint32
}

func (l FileLocker) Acquire(ctx context.Context, path string, wait time.Duration) (*HeldLock, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := l.FS.OpenFileNoFollow(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := validateInstallerLockFile(file, l.OwnerUID); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateInstallerLockFile(file, l.OwnerUID); err != nil {
		_ = file.Close()
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if err := validateInstallerLockPath(l.FS, path, file, l.OwnerUID); err != nil {
				_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				_ = file.Close()
				return nil, err
			}
			return &HeldLock{File: file, unlock: func() error {
				unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				closeErr := file.Close()
				if unlockErr != nil {
					return unlockErr
				}
				return closeErr
			}}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		if wait <= 0 || !time.Now().Before(deadline) {
			_ = file.Close()
			return nil, ErrLockBusy
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func validateInstallerLockFile(file *os.File, ownerUID uint32) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Uid != ownerUID || stat.Nlink != 1 {
		return errors.New("lock file must be regular, owned by the configured root uid, and have exactly one link")
	}
	return nil
}

func validateInstallerLockPath(filesystem FileSystem, path string, locked *os.File, ownerUID uint32) error {
	lockedInfo, err := locked.Stat()
	if err != nil {
		return err
	}
	currentInfo, err := filesystem.Lstat(path)
	if err != nil {
		return errors.Join(errors.New("lock path changed while acquiring"), err)
	}
	currentStat, ok := currentInfo.Sys().(*syscall.Stat_t)
	if !currentInfo.Mode().IsRegular() || !ok || currentStat.Uid != ownerUID || currentStat.Nlink != 1 ||
		!os.SameFile(lockedInfo, currentInfo) {
		return errors.New("lock path changed while acquiring")
	}
	return nil
}

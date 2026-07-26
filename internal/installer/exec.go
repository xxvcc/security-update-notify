package installer

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

const maxCommandOutput = 8 << 20

type cappedBuffer struct {
	b   bytes.Buffer
	max int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if remaining := b.max - b.b.Len(); remaining > 0 {
		if len(p) > remaining {
			_, _ = b.b.Write(p[:remaining])
		} else {
			_, _ = b.b.Write(p)
		}
	}
	return len(p), nil
}

type ExecRunner struct{}

func (ExecRunner) LookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (ExecRunner) Run(parent context.Context, command Command) CommandResult {
	ctx := parent
	cancel := func() {}
	if command.Timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, command.Timeout)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	cmd.Env = commandEnv(command.Env)
	cmd.Stdin = bytes.NewReader(command.Stdin)
	out := &cappedBuffer{max: maxCommandOutput}
	errOut := &cappedBuffer{max: maxCommandOutput}
	cmd.Stdout, cmd.Stderr = out, errOut
	err := cmd.Run()
	result := CommandResult{Stdout: out.b.Bytes(), Stderr: errOut.b.Bytes()}
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
	remove := make(map[string]bool, len(overrides)+1)
	remove["LC_ALL"] = true
	for key := range overrides {
		remove[key] = true
	}
	env := make([]string, 0, len(os.Environ())+len(overrides)+1)
	for _, value := range os.Environ() {
		key, _, _ := strings.Cut(value, "=")
		if !remove[key] {
			env = append(env, value)
		}
	}
	env = append(env, "LC_ALL=C")
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		env = append(env, key+"="+overrides[key])
	}
	return env
}

type FileLocker struct {
	FS FileSystem
}

func (l FileLocker) Acquire(ctx context.Context, path string, wait time.Duration) (UnlockFunc, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := l.FS.OpenFileNoFollow(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("lock path is not a regular file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && (stat.Uid != 0 || stat.Nlink != 1) {
		_ = file.Close()
		return nil, errors.New("lock file must be root-owned and have exactly one link")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() error {
				unlockErr := syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
				closeErr := file.Close()
				if unlockErr != nil {
					return unlockErr
				}
				return closeErr
			}, nil
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

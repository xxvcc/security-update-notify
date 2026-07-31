// Package sysexec 是全 Go 运行时唯一的外部命令边界。它复刻运行时 `set +e` 的语义：子命令的非零
// 退出码作为数据返回、绝不致命；并对每个子进程强制 LC_ALL=C，使 needrestart/needs-restarting 的文案
// 匹配、排序、字段解析在任何系统语言下都确定（与运行时 `export LC_ALL=C` 一致，也是去重 hash 稳定的前提）。
//
// Package sysexec is the single external-command boundary of the all-Go runtime. It reproduces the
// runtime's `set +e` semantics: a child's non-zero exit is returned as data, never fatal; and it forces
// LC_ALL=C on every child so needrestart/needs-restarting message matching, sorting and field parsing are
// deterministic under any system language (matching the runtime's `export LC_ALL=C`, a prerequisite for a
// stable dedup hash).
package sysexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/commandpath"
)

// Result 是一次命令执行的结果。Code 是退出码（命令无法启动时为 -1，Err 非空）。
type Result struct {
	Stdout          string
	Stderr          string
	StdoutTruncated bool
	StderrTruncated bool
	Code            int
	Err             error // 命令无法启动或 context 取消/超时时非空；普通非零退出不算 Err
}

// maxCapturedBytes 限制单个流（stdout/stderr）缓冲的字节数，防止被攻破的包源/needrestart 返回
// 超大输出把 root 进程撑到 OOM。真实输出仅数十 KB；后续 firstNLines 等截断在此之上再收窄。
const (
	maxCapturedBytes = 8 << 20 // 8 MiB per stream
	commandWaitDelay = 250 * time.Millisecond
	signalGraceDelay = 250 * time.Millisecond
)

var (
	activeProcessGroups  sync.Map
	signalForwardingOnce sync.Once
	terminating          atomic.Bool
	terminationBarrier   = make(chan struct{})
	terminationCleanupMu sync.Mutex
	terminationCleanups  = make(map[uint64]func())
	terminationCleanupID atomic.Uint64
	commandPathMu        sync.RWMutex
	testCommandPath      string
	testCommandPathSet   bool
)

// capBuffer 是带上限的写入缓冲：达到上限后丢弃多余字节，但始终向子进程声明"已全部写入"，
// 避免因短写让子进程收到写错误（镜像运行时 `set +e` 的宽松语义）。
type capBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if rem := c.max - c.buf.Len(); rem > 0 {
		if len(p) > rem {
			c.buf.Write(p[:rem])
			c.truncated = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.truncated = true
	}
	return len(p), nil
}

// forcedEnv 在当前环境基础上强制 LC_ALL=C 和受信 PATH。测试搜索路径只影响测试二进制，
// 且保留系统目录供夹具脚本调用基础工具；生产进程始终使用 commandpath.TrustedPATH。
func forcedEnv() []string {
	path := commandpath.EffectivePATH()
	var overrides map[string]string
	if testPath, ok := commandPathOverride(); ok && testPath != "" {
		path = testPath + string(os.PathListSeparator) + path
		overrides = make(map[string]string)
		for _, item := range os.Environ() {
			key, value, found := strings.Cut(item, "=")
			if found && strings.HasPrefix(key, "SUN_") {
				overrides[key] = value
			}
		}
	}
	return commandpath.SanitizedEnvironment(path, overrides)
}

// Run 执行命令并捕获 stdout/stderr/退出码。非零退出不作为错误返回（镜像 `set +e`）。
func Run(name string, args ...string) Result {
	return RunContext(context.Background(), name, args...)
}

// RunTimeout bounds commands used by the daily watchdog. A timed-out command returns Code=-1 and Err set.
func RunTimeout(timeout time.Duration, name string, args ...string) Result {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return RunContext(ctx, name, args...)
}

// RunContext 是带 context 的 Run（用于超时/取消）。
func RunContext(ctx context.Context, name string, args ...string) Result {
	cmd := CommandContext(ctx, name, args...)
	stdout := &capBuffer{max: maxCapturedBytes}
	stderr := &capBuffer{max: maxCapturedBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	res := Result{
		Stdout:          stdout.buf.String(),
		Stderr:          stderr.buf.String(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
	}
	if err == nil {
		res.Code = 0
		return res
	}
	if contextErr := ctx.Err(); contextErr != nil {
		res.Code = -1
		res.Err = contextErr
		return res
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		res.Code = ee.ExitCode() // 非零退出：作为数据，不视为致命错误
		return res
	}
	// 命令无法启动（未找到 / 权限等）。
	res.Code = -1
	res.Err = err
	return res
}

// CommandContext creates a Linux command in its own process group. Context cancellation kills the
// complete group, and WaitDelay bounds the pipe wait even if a descendant deliberately escapes it.
// Cmd wraps exec.Cmd so active process groups can be removed from the signal-forwarding registry
// exactly when Wait completes. Callers configure the embedded exec.Cmd fields as usual.
type Cmd struct {
	*exec.Cmd
	processGroup int
}

func (c *Cmd) Start() error {
	if err := c.Cmd.Start(); err != nil {
		return err
	}
	c.processGroup = c.Process.Pid
	activeProcessGroups.Store(c.processGroup, struct{}{})
	if terminating.Load() {
		_ = syscall.Kill(-c.processGroup, syscall.SIGKILL)
	}
	return nil
}

func (c *Cmd) Wait() error {
	err := c.Cmd.Wait()
	if c.processGroup > 0 {
		activeProcessGroups.Delete(c.processGroup)
		c.processGroup = 0
	}
	if terminating.Load() {
		// Keep the main goroutine alive until the signal-forwarding goroutine
		// re-raises the original signal with the default disposition.
		<-terminationBarrier
	}
	return err
}

func (c *Cmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

func CommandContext(ctx context.Context, name string, args ...string) *Cmd {
	resolved, resolveErr := resolveCommand(name)
	if resolveErr != nil {
		// Build a non-runnable command without asking os/exec to search caller PATH.
		resolved = "/__security_update_notify_command_unavailable__"
	}
	cmd := exec.CommandContext(ctx, resolved, args...)
	cmd.Args[0] = name
	cmd.Env = forcedEnv()
	if resolveErr != nil {
		cmd.Err = resolveErr
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.WaitDelay = commandWaitDelay
	return &Cmd{Cmd: cmd}
}

// InstallSignalForwarding makes SIGHUP/SIGINT/SIGTERM reach every active child process group before the
// signal is re-raised in the parent. The short grace period preserves normal command cleanup; a
// second signal or the grace deadline force-kills any remaining descendants. It is process-global
// and idempotent, so command entrypoints should call it once during startup.
func InstallSignalForwarding() {
	signalForwardingOnce.Do(func() {
		signals := make(chan os.Signal, 2)
		signal.Notify(signals, syscall.SIGHUP, os.Interrupt, syscall.SIGTERM)
		go func() {
			first := <-signals
			sig, ok := first.(syscall.Signal)
			if !ok {
				sig = syscall.SIGTERM
			}
			terminating.Store(true)
			runTerminationCleanups()
			signalActiveProcessGroups(sig)

			timer := time.NewTimer(signalGraceDelay)
			select {
			case <-timer.C:
			case <-signals:
				if !timer.Stop() {
					<-timer.C
				}
			}
			signalActiveProcessGroups(syscall.SIGKILL)
			signal.Stop(signals)
			signal.Reset(syscall.SIGHUP, os.Interrupt, syscall.SIGTERM)
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				os.Exit(128 + int(sig))
			}
		}()
	})
}

// RegisterTerminationCleanup registers a short, non-blocking cleanup that must
// run before InstallSignalForwarding re-raises a termination signal. This is
// intended for process-local state, such as restoring terminal attributes,
// whose normal defer cannot run after signal re-raising. The returned function
// unregisters the cleanup and synchronizes with an invocation already in
// progress.
func RegisterTerminationCleanup(cleanup func()) func() {
	if cleanup == nil {
		return func() {}
	}
	id := terminationCleanupID.Add(1)
	terminationCleanupMu.Lock()
	if terminating.Load() {
		terminationCleanupMu.Unlock()
		callTerminationCleanup(cleanup)
		return func() {}
	}
	terminationCleanups[id] = cleanup
	terminationCleanupMu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			terminationCleanupMu.Lock()
			delete(terminationCleanups, id)
			terminationCleanupMu.Unlock()
		})
	}
}

func runTerminationCleanups() {
	// Holding the lock while callbacks run makes unregister a synchronization
	// point: once it returns, a callback cannot touch a resource that its owner
	// is about to release or reuse.
	terminationCleanupMu.Lock()
	defer terminationCleanupMu.Unlock()
	for id, cleanup := range terminationCleanups {
		callTerminationCleanup(cleanup)
		delete(terminationCleanups, id)
	}
}

func callTerminationCleanup(cleanup func()) {
	defer func() { _ = recover() }()
	cleanup()
}

func signalActiveProcessGroups(sig syscall.Signal) {
	activeProcessGroups.Range(func(key, _ any) bool {
		processGroup, ok := key.(int)
		if ok && processGroup > 0 {
			_ = syscall.Kill(-processGroup, sig)
		}
		return true
	})
}

// Look reports whether a command exists on the fixed privileged PATH.
func Look(name string) bool {
	_, err := resolveCommand(name)
	return err == nil
}

func resolveCommand(name string) (string, error) {
	if filepath.IsAbs(name) || strings.ContainsRune(name, filepath.Separator) {
		return commandpath.Resolve(name)
	}
	if path, ok := commandPathOverride(); ok {
		for _, directory := range filepath.SplitList(path) {
			if directory == "" || !filepath.IsAbs(directory) {
				continue
			}
			candidate := filepath.Join(directory, name)
			if resolved, err := commandpath.Resolve(candidate); err == nil {
				return resolved, nil
			}
		}
		return "", fmt.Errorf("command is unavailable on injected test PATH: %s", name)
	}
	return commandpath.Resolve(name)
}

func commandPathOverride() (string, bool) {
	commandPathMu.RLock()
	defer commandPathMu.RUnlock()
	return testCommandPath, testCommandPathSet
}

// SetCommandPathForTest replaces command lookup for deterministic tests. Production code must not
// call this hook; normal command execution always resolves through commandpath.TrustedPATH.
func SetCommandPathForTest(path string) func() {
	commandPathMu.Lock()
	previousPath, previousSet := testCommandPath, testCommandPathSet
	testCommandPath, testCommandPathSet = path, true
	commandPathMu.Unlock()
	return func() {
		commandPathMu.Lock()
		testCommandPath, testCommandPathSet = previousPath, previousSet
		commandPathMu.Unlock()
	}
}

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
	"os"
	"os/exec"
)

// Result 是一次命令执行的结果。Code 是退出码（命令无法启动时为 -1，Err 非空）。
type Result struct {
	Stdout string
	Stderr string
	Code   int
	Err    error // 仅在命令无法启动（如未找到）时非空；非零退出不算 Err
}

// forcedEnv 在当前环境基础上强制 LC_ALL=C（去掉已有的 LC_ALL/LANG 影响，追加权威值）。
func forcedEnv() []string {
	env := os.Environ()
	out := env[:0]
	for _, kv := range env {
		if len(kv) >= 7 && kv[:7] == "LC_ALL=" {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "LC_ALL=C")
}

// Run 执行命令并捕获 stdout/stderr/退出码。非零退出不作为错误返回（镜像 `set +e`）。
func Run(name string, args ...string) Result {
	return RunContext(context.Background(), name, args...)
}

// RunContext 是带 context 的 Run（用于超时/取消）。
func RunContext(ctx context.Context, name string, args ...string) Result {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = forcedEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		res.Code = 0
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

// Look 报告命令是否在 PATH 中（复刻 `command -v`）。
func Look(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

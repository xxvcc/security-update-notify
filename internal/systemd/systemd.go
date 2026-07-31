// Package systemd 用 internal/sysexec 封装看门狗与 doctor 需要的 systemctl 查询（is-enabled、
// show -p PROP --value）。刻意 shell 到 systemctl 而非走 D-Bus（保持零第三方依赖，与运行时一致）。
//
// Package systemd wraps the systemctl queries the watchdog and doctor need (is-enabled, show -p PROP
// --value) via internal/sysexec. It deliberately shells to systemctl rather than using D-Bus (keeping
// zero third-party deps, matching the runtime).
package systemd

import (
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/commandpath"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

const systemctlCommandTimeout = 15 * time.Second

// Available 报告本机是否有 systemctl。
func Available() bool {
	_, err := commandpath.Resolve("systemctl")
	return err == nil
}

// IsEnabled reports whether systemctl considers unit persistently or runtime enabled.
// Other successful states such as static, alias, and indirect do not guarantee that
// the unit is scheduled across boots.
func IsEnabled(unit string) bool {
	return isEnabledWithTimeout(unit, systemctlCommandTimeout)
}

func isEnabledWithTimeout(unit string, timeout time.Duration) bool {
	command, err := commandpath.Resolve("systemctl")
	if err != nil {
		return false
	}
	return isEnabledWithCommand(command, unit, timeout)
}

func isEnabledWithCommand(command, unit string, timeout time.Duration) bool {
	result := sysexec.RunTimeout(timeout, command, "is-enabled", unit)
	if !completeSuccessfulResult(result) {
		return false
	}
	state := strings.TrimSpace(result.Stdout)
	return state == "enabled" || state == "enabled-runtime"
}

// ShowValue 复刻 `systemctl show <unit> -p <prop> --value`，去掉尾部换行。第二个返回值区分
// “查询成功但属性为空”和“systemctl 查询失败”，避免健康检查把未知状态当作合法空值。
func ShowValue(unit, prop string) (string, bool) {
	return showValueWithTimeout(unit, prop, systemctlCommandTimeout)
}

func showValueWithTimeout(unit, prop string, timeout time.Duration) (string, bool) {
	command, err := commandpath.Resolve("systemctl")
	if err != nil {
		return "", false
	}
	return showValueWithCommand(command, unit, prop, timeout)
}

func showValueWithCommand(command, unit, prop string, timeout time.Duration) (string, bool) {
	r := sysexec.RunTimeout(timeout, command, "show", unit, "-p", prop, "--value")
	if !completeSuccessfulResult(r) {
		return "", false
	}
	return strings.TrimRight(r.Stdout, "\n"), true
}

func completeSuccessfulResult(result sysexec.Result) bool {
	return result.Err == nil && result.Code == 0 && !result.StdoutTruncated && !result.StderrTruncated &&
		strings.TrimSpace(result.Stderr) == ""
}

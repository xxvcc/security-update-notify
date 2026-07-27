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

	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

const systemctlCommandTimeout = 15 * time.Second

// Available 报告本机是否有 systemctl。
func Available() bool { return sysexec.Look("systemctl") }

// IsEnabled reports whether systemctl considers unit persistently or runtime enabled.
// Other successful states such as static, alias, and indirect do not guarantee that
// the unit is scheduled across boots.
func IsEnabled(unit string) bool {
	return isEnabledWithTimeout(unit, systemctlCommandTimeout)
}

func isEnabledWithTimeout(unit string, timeout time.Duration) bool {
	result := sysexec.RunTimeout(timeout, "systemctl", "is-enabled", unit)
	if result.Code != 0 {
		return false
	}
	state := strings.TrimSpace(result.Stdout)
	return state == "enabled" || state == "enabled-runtime"
}

// ShowValue 复刻 `systemctl show <unit> -p <prop> --value`，去掉尾部换行；失败返回空。
func ShowValue(unit, prop string) string {
	return showValueWithTimeout(unit, prop, systemctlCommandTimeout)
}

func showValueWithTimeout(unit, prop string, timeout time.Duration) string {
	r := sysexec.RunTimeout(timeout, "systemctl", "show", unit, "-p", prop, "--value")
	if r.Code != 0 {
		return ""
	}
	return strings.TrimRight(r.Stdout, "\n")
}

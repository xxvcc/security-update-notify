// Package systemd 用 internal/sysexec 封装看门狗与 doctor 需要的 systemctl 查询（is-enabled、
// show -p PROP --value）。刻意 shell 到 systemctl 而非走 D-Bus（保持零第三方依赖，与运行时一致）。
//
// Package systemd wraps the systemctl queries the watchdog and doctor need (is-enabled, show -p PROP
// --value) via internal/sysexec. It deliberately shells to systemctl rather than using D-Bus (keeping
// zero third-party deps, matching the runtime).
package systemd

import (
	"strings"

	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

// Available 报告本机是否有 systemctl。
func Available() bool { return sysexec.Look("systemctl") }

// IsEnabled 复刻 `systemctl is-enabled <unit>`（退出 0 视为已启用）。
func IsEnabled(unit string) bool {
	return sysexec.Run("systemctl", "is-enabled", unit).Code == 0
}

// ShowValue 复刻 `systemctl show <unit> -p <prop> --value`，去掉尾部换行；失败返回空。
func ShowValue(unit, prop string) string {
	r := sysexec.Run("systemctl", "show", unit, "-p", prop, "--value")
	if r.Code != 0 && r.Err != nil {
		return ""
	}
	return strings.TrimRight(r.Stdout, "\n")
}

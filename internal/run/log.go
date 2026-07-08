package run

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// logEvent 复刻运行时 log_event：向 /var/log/security-update-notify.log 追加一行
// `YYYY-mm-dd HH:MM:SS ±ZZZZ <line>`。日志不存在时以 0640 创建（避免被删后按宽松 umask 重建为
// world-readable）。所有写入均 best-effort（失败静默，绝不影响通知流程），与 Bash 的 `|| true` 一致。
//
// logEvent reproduces the runtime's log_event: append `YYYY-mm-dd HH:MM:SS ±ZZZZ <line>` to the log,
// creating it 0640 if absent. All writes are best-effort (silent on failure, never affecting the notify
// flow), matching the Bash `|| true`.
func logEvent(line string) {
	path := logFilePath()
	_ = os.MkdirAll(filepath.Dir(path), 0o755)
	if _, err := os.Stat(path); err != nil {
		if f, e := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o640); e == nil {
			_ = f.Close()
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o640)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05 -0700"), line)
}

func b01(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

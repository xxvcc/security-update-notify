package run

import "os"

// 运行时路径。默认与 Bash 运行时一致；可用环境变量覆盖，便于隔离测试（差分/黄金）而不触碰真实状态。
// Runtime paths. Defaults match the Bash runtime; overridable via env for isolated testing (differential/
// golden) without touching real state.
const (
	defaultStateDir = "/var/lib/security-update-notify"
	defaultLockFile = "/run/security-update-notify.lock"
	defaultLogFile  = "/var/log/security-update-notify.log"
)

func stateDirPath() string { return envOr("SECURITY_UPDATE_NOTIFY_STATE_DIR", defaultStateDir) }
func lockFilePath() string { return envOr("SECURITY_UPDATE_NOTIFY_LOCK_FILE", defaultLockFile) }
func logFilePath() string  { return envOr("SECURITY_UPDATE_NOTIFY_LOG_FILE", defaultLogFile) }

func envOr(key, dflt string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return dflt
}

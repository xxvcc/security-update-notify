package run

import "github.com/xxvcc/security-update-notify/internal/runtimeenv"

// 运行时路径保留稳定的 2.x 磁盘契约；可用环境变量覆盖，便于隔离测试而不触碰真实状态。
// Runtime paths retain the stable 2.x on-disk contract and are overridable for isolated tests.
const (
	defaultStateDir = "/var/lib/security-update-notify"
	defaultLockFile = "/run/security-update-notify.lock"
	defaultLogFile  = "/var/log/security-update-notify.log"
)

func stateDirPath() string { return envOr("SECURITY_UPDATE_NOTIFY_STATE_DIR", defaultStateDir) }
func lockFilePath() string { return envOr("SECURITY_UPDATE_NOTIFY_LOCK_FILE", defaultLockFile) }
func logFilePath() string  { return envOr("SECURITY_UPDATE_NOTIFY_LOG_FILE", defaultLogFile) }

func envOr(key, dflt string) string {
	if v := runtimeenv.Override(key); v != "" {
		return v
	}
	return dflt
}

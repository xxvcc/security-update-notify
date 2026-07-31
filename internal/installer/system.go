package installer

import (
	"context"
	"errors"
	"fmt"

	"strings"

	"github.com/xxvcc/security-update-notify/internal/aptconfig"
)

const aptPeriodicConfig = aptconfig.Periodic

const (
	aptPeriodicPath          = "/etc/apt/apt.conf.d/20auto-upgrades"
	aptStableBackupPath      = aptPeriodicPath + ".security-update-notify.bak"
	aptAbsentMarkerPath      = aptPeriodicPath + ".security-update-notify.absent.bak"
	aptLegacyAbsentPath      = aptPeriodicPath + ".security-update-notify.absent"
	aptDependencyProofPath   = aptPeriodicPath + ".security-update-notify.dependency-default.bak"
	aptAbsentMarkerContents  = "security-update-notify: original file absent\n"
	dnfAutomaticPath         = "/etc/dnf/automatic.conf"
	dnfStableBackupPath      = dnfAutomaticPath + ".security-update-notify.bak"
	dnfAbsentMarkerPath      = dnfAutomaticPath + ".security-update-notify.absent.bak"
	dnfDependencyProofPath   = dnfAutomaticPath + ".security-update-notify.dependency-default.bak"
	dnfAbsentMarkerContents  = "security-update-notify: original file absent; engine=dnf4\n"
	dnf5AbsentMarkerContents = "security-update-notify: original file absent; engine=dnf5\n"
)

const aptUnattendedPolicy = `// 本地策略：永不自动重启。发行版软件包保留其默认 Origins-Pattern 安全规则。
// Local policy: never reboot automatically. The distribution package keeps
// its default Origins-Pattern security rules.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::SyslogEnable "true";
`

func renderTimer(checkTime string) string {
	return `[Unit]
Description=每日检查安全补丁维护风险、重启需求与 SUN 新版本 / Daily check for security patch maintenance risks, restart needs, and new SUN releases

[Timer]
OnCalendar=*-*-* ` + checkTime + `:00
RandomizedDelaySec=10m
Persistent=true

[Install]
WantedBy=timers.target
`
}

func (i *Installer) requiredCommand(op string, command Command) error {
	return i.requiredCommandContext(context.Background(), op, command)
}

func (i *Installer) requiredCommandContext(ctx context.Context, op string, command Command) error {
	result := i.runner.Run(ctx, command)
	if commandResultIncomplete(result) || result.Err != nil || result.Code != 0 {
		return failure(op, commandResultError(result))
	}
	return nil
}

func commandResultError(result CommandResult) error {
	if result.Err != nil {
		return result.Err
	}
	if commandResultIncomplete(result) {
		return errors.New("command output exceeded the capture limit")
	}
	detail := strings.TrimSpace(string(result.Stderr))
	if detail == "" {
		detail = strings.TrimSpace(string(result.Stdout))
	}
	if len(detail) > 4096 {
		detail = detail[:4096]
	}
	if detail == "" {
		detail = fmt.Sprintf("command exited with status %d", result.Code)
	}
	return errors.New(detail)
}

func commandResultIncomplete(result CommandResult) bool {
	return result.StdoutTruncated || result.StderrTruncated
}

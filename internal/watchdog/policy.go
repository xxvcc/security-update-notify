package watchdog

import (
	"strings"

	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
)

// CheckAPTPolicy validates the effective apt-config output and the metadata-refresh timer. The existing
// CheckHealth function separately validates apt-daily-upgrade.timer and its service result.
func CheckAPTPolicy(dump string, aptDailyEnabled bool) []Issue {
	lower := strings.ToLower(dump)
	var issues []Issue
	if !aptDailyEnabled {
		issues = append(issues, Issue{"apt-daily-disabled", "APT 软件源刷新定时器未启用（apt-daily.timer）", "APT metadata refresh timer is not enabled (apt-daily.timer)"})
	}
	if !aptBoolEnabled(lower, "apt::periodic::update-package-lists") {
		issues = append(issues, Issue{"apt-periodic-update-disabled", "APT 每日软件源刷新策略未启用", "APT daily package-list refresh is not enabled"})
	}
	if !aptBoolEnabled(lower, "apt::periodic::unattended-upgrade") {
		issues = append(issues, Issue{"apt-unattended-disabled", "APT 自动安全更新策略未启用", "APT unattended security upgrades are not enabled"})
	}
	securityOrigin := false
	for _, line := range strings.Split(lower, "\n") {
		if (strings.Contains(line, "unattended-upgrade::origins-pattern") || strings.Contains(line, "unattended-upgrade::allowed-origins")) &&
			(strings.Contains(line, "security") || strings.Contains(line, "esm")) {
			securityOrigin = true
			break
		}
	}
	if !securityOrigin {
		issues = append(issues, Issue{"apt-security-origin-missing", "APT unattended-upgrades 未发现安全更新源策略", "No security origin policy was found for APT unattended-upgrades"})
	}
	if aptBoolEnabled(lower, "unattended-upgrade::automatic-reboot") {
		issues = append(issues, Issue{"apt-auto-reboot-enabled", "APT 被配置为自动重启，偏离 SUN 的人工维护策略", "APT is configured to reboot automatically, contrary to SUN's manual-maintenance policy"})
	}
	return issues
}

func aptBoolEnabled(dump, key string) bool {
	prefix := strings.ToLower(key) + " "
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			v := strings.Trim(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, prefix)), ";"), `"'`)
			switch v {
			case "1", "true", "yes", "on":
				return true
			default:
				return false
			}
		}
	}
	return false
}

// CheckDNFPolicy validates the settings that make dnf-automatic install only security updates without rebooting.
func CheckDNFPolicy(content string) []Issue {
	values, err := dnfconfig.ParseStrict([]byte(content))
	if err != nil {
		return []Issue{{
			"dnf-automatic-config-invalid",
			"dnf-automatic 配置语法无效或存在重复项",
			"dnf-automatic configuration has invalid or duplicate INI data",
		}}
	}
	var issues []Issue
	if values["commands.upgrade_type"] != "security" {
		issues = append(issues, Issue{"dnf-upgrade-type-drift", "dnf-automatic 未配置为只安装安全更新", "dnf-automatic is not configured for security-only updates"})
	}
	if !dnfBoolEnabled(values["commands.apply_updates"]) {
		issues = append(issues, Issue{"dnf-apply-updates-disabled", "dnf-automatic 未启用自动应用更新", "dnf-automatic is not configured to apply updates"})
	}
	if values["commands.reboot"] != "never" {
		issues = append(issues, Issue{"dnf-auto-reboot-enabled", "dnf-automatic 未明确禁止自动重启", "dnf-automatic is not configured to avoid automatic reboots"})
	}
	return issues
}

func dnfBoolEnabled(value string) bool {
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

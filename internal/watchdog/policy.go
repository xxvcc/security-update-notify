package watchdog

import "strings"

// CheckAPTPolicy validates the effective apt-config output and the metadata-refresh timer. The existing
// CheckHealth function separately validates apt-daily-upgrade.timer and its service result.
func CheckAPTPolicy(dump string, aptDailyEnabled bool) []Issue {
	lower := strings.ToLower(dump)
	var issues []Issue
	if !aptDailyEnabled {
		issues = append(issues, Issue{"apt-daily-disabled", "APT 软件源刷新定时器未启用（apt-daily.timer）", "APT metadata refresh timer is not enabled (apt-daily.timer)"})
	}
	if !aptBoolValue(lower, "apt::periodic::update-package-lists", "1") {
		issues = append(issues, Issue{"apt-periodic-update-disabled", "APT 每日软件源刷新策略未启用", "APT daily package-list refresh is not enabled"})
	}
	if !aptBoolValue(lower, "apt::periodic::unattended-upgrade", "1") {
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
	if aptBoolValue(lower, "unattended-upgrade::automatic-reboot", "true") {
		issues = append(issues, Issue{"apt-auto-reboot-enabled", "APT 被配置为自动重启，偏离 SUN 的人工维护策略", "APT is configured to reboot automatically, contrary to SUN's manual-maintenance policy"})
	}
	return issues
}

func aptBoolValue(dump, key, value string) bool {
	prefix := strings.ToLower(key) + " "
	for _, line := range strings.Split(dump, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			v := strings.Trim(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(line, prefix)), ";"), `"'`)
			return v == strings.ToLower(value)
		}
	}
	return false
}

// CheckDNFPolicy validates the two settings that make dnf-automatic install security updates.
func CheckDNFPolicy(content string) []Issue {
	values := parseINI(content)
	var issues []Issue
	if values["commands.upgrade_type"] != "security" {
		issues = append(issues, Issue{"dnf-upgrade-type-drift", "dnf-automatic 未配置为只安装安全更新", "dnf-automatic is not configured for security-only updates"})
	}
	if values["commands.apply_updates"] != "yes" {
		issues = append(issues, Issue{"dnf-apply-updates-disabled", "dnf-automatic 未启用自动应用更新", "dnf-automatic is not configured to apply updates"})
	}
	return issues
}

func parseINI(content string) map[string]string {
	values := map[string]string{}
	section := ""
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}
		if i := strings.IndexByte(line, '='); i >= 0 {
			key := strings.ToLower(strings.TrimSpace(line[:i]))
			value := strings.ToLower(strings.TrimSpace(line[i+1:]))
			if j := strings.IndexAny(value, "#;"); j >= 0 {
				value = strings.TrimSpace(value[:j])
			}
			values[section+"."+key] = value
		}
	}
	return values
}

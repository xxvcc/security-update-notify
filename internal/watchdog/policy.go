package watchdog

import (
	"math"
	"strconv"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/dnfconfig"
)

// CheckAPTPolicy validates the effective apt-config output and the metadata-refresh timer. The existing
// CheckHealth function separately validates apt-daily-upgrade.timer and its service result.
func CheckAPTPolicy(dump string, aptDailyEnabled bool) []Issue {
	lower := strings.ToLower(dump)
	var issues []Issue
	if !APTPeriodicEnabled(dump) {
		issues = append(issues, Issue{"apt-periodic-disabled", "APT 周期更新总开关未启用或无效", "The APT periodic-update master switch is disabled or invalid"})
	}
	if !aptDailyEnabled {
		issues = append(issues, Issue{"apt-daily-disabled", "APT 软件源刷新定时器未启用（apt-daily.timer）", "APT metadata refresh timer is not enabled (apt-daily.timer)"})
	}
	if !aptIntervalEnabled(dump, "apt::periodic::update-package-lists") {
		issues = append(issues, Issue{"apt-periodic-update-disabled", "APT 每日软件源刷新策略未启用", "APT daily package-list refresh is not enabled"})
	}
	if !aptIntervalEnabled(dump, "apt::periodic::unattended-upgrade") {
		issues = append(issues, Issue{"apt-unattended-disabled", "APT 自动安全更新策略未启用", "APT unattended security upgrades are not enabled"})
	}
	if !aptSecurityOriginEnabled(lower) {
		issues = append(issues, Issue{"apt-security-origin-missing", "APT unattended-upgrades 未发现安全更新源策略", "No security origin policy was found for APT unattended-upgrades"})
	}
	if aptBoolEnabled(lower, "unattended-upgrade::automatic-reboot") {
		issues = append(issues, Issue{"apt-auto-reboot-enabled", "APT 被配置为自动重启，偏离 SUN 的人工维护策略", "APT is configured to reboot automatically, contrary to SUN's manual-maintenance policy"})
	}
	return issues
}

// APTPeriodicEnabled follows apt.systemd.daily's default-on numeric master
// switch. Malformed values are not evidence of a working periodic policy.
func APTPeriodicEnabled(dump string) bool {
	value, present := aptConfigValue(dump, "apt::periodic::enable")
	if !present {
		return true
	}
	n, err := strconv.ParseInt(value, 10, 64)
	return err == nil && n != 0
}

func aptIntervalEnabled(dump, key string) bool {
	value, present := aptConfigValue(dump, key)
	if !present || value == "" || value == "0" {
		return false
	}
	if value == "always" {
		return true
	}
	multiplier := int64(86400)
	base := 0 // apt.systemd.daily evaluates minute/hour/day intervals as shell arithmetic.
	switch value[len(value)-1] {
	case 's':
		multiplier, base = 1, 10
		value = value[:len(value)-1]
	case 'm':
		multiplier = 60
		value = value[:len(value)-1]
	case 'h':
		multiplier = 3600
		value = value[:len(value)-1]
	case 'd':
		value = value[:len(value)-1]
	}
	if value == "" || strings.TrimLeft(value, "0123456789") != "" {
		return false
	}
	n, err := strconv.ParseInt(value, base, 64)
	return err == nil && n <= math.MaxInt64/multiplier
}

func aptConfigValue(dump, key string) (string, bool) {
	for _, line := range strings.Split(dump, "\n") {
		name, raw, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || !strings.EqualFold(name, key) {
			continue
		}
		raw = strings.TrimSpace(raw)
		value, valid := aptQuotedValue(raw)
		if !valid {
			return "", true
		}
		return value, true
	}
	return "", false
}

func aptQuotedValue(raw string) (string, bool) {
	// apt-config dump preserves literal backslashes; it does not emit Go string
	// escapes. In particular, a literal \x31 must never become numeric 1.
	if len(raw) < 3 || raw[0] != '"' || raw[len(raw)-2:] != "\";" {
		return "", false
	}
	return raw[1 : len(raw)-2], true
}

func aptSecurityOriginEnabled(dump string) bool {
	for _, line := range strings.Split(dump, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch key {
		case "unattended-upgrade::origins-pattern", "unattended-upgrade::origins-pattern::",
			"unattended-upgrade::allowed-origins", "unattended-upgrade::allowed-origins::":
		default:
			continue
		}
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
		}) {
			if token == "security" || token == "esm" || token == "esmapps" || token == "esminfra" ||
				strings.HasPrefix(token, "ubuntuesm") {
				return true
			}
		}
	}
	return false
}

// CheckAPTSecurityOriginCodenames catches an explicit release left behind after
// a distro upgrade. It only disproves literal codename rules against available
// security Release metadata; variable/glob rules require unattended-upgrades'
// own matching engine and are deliberately left to that engine.
func CheckAPTSecurityOriginCodenames(dump string, codenames []string) []Issue {
	if len(codenames) == 0 {
		return nil
	}
	explicitSecurityRule := false
	for _, line := range strings.Split(dump, "\n") {
		key, raw, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		switch strings.ToLower(key) {
		case "unattended-upgrade::origins-pattern", "unattended-upgrade::origins-pattern::",
			"unattended-upgrade::allowed-origins", "unattended-upgrade::allowed-origins::":
		default:
			continue
		}
		value, valid := aptQuotedValue(strings.TrimSpace(raw))
		if !valid || strings.Contains(value, "\\") {
			return nil
		}
		if value == "" {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(key), "unattended-upgrade::origins-pattern") ||
			!aptSecurityOriginEnabled(strings.ToLower(line)) {
			return nil
		}
		codename := ""
		for _, token := range strings.Split(value, ",") {
			name, candidate, ok := strings.Cut(token, "=")
			if !ok {
				return nil
			}
			if name = strings.TrimSpace(name); name == "n" || name == "codename" {
				codename = strings.TrimSpace(candidate)
			}
		}
		if codename == "" || strings.ContainsAny(codename, "*?[\\$") {
			return nil
		}
		for _, available := range codenames {
			if codename == available {
				return nil
			}
		}
		explicitSecurityRule = true
	}
	if !explicitSecurityRule {
		return nil
	}
	return []Issue{{"apt-security-origin-release-mismatch", "APT 安全更新策略指定的发行版与本地安全源元数据不匹配", "APT security origin policies name a release absent from local security repository metadata"}}
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

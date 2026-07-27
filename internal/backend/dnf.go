package backend

import (
	"regexp"
	"strings"
)

var (
	dnfServiceUnitRe = regexp.MustCompile(`^[A-Za-z0-9:_.@\\-]+\.service$`)
	// 仅把形如“包名.架构”的 $NF 视为相关包，过滤表头/汇总噪声。
	archRe = regexp.MustCompile(`\.(x86_64|noarch|aarch64|i686|ppc64le|s390x)$`)
)

// DNFRebootDecision validates the documented needs-restarting text/exit-status pair.
func DNFRebootDecision(output string, rc int) (required, valid bool) {
	requiredLines, notNeededLines := 0, 0
	for _, line := range splitLines(output) {
		line = strings.TrimSuffix(line, "\r")
		if line == "Reboot is required to fully utilize these updates." {
			requiredLines++
		}
		if line == "Reboot should not be necessary." {
			notNeededLines++
		}
	}
	if requiredLines+notNeededLines != 1 {
		return false, false
	}
	if requiredLines == 1 {
		if rc != 1 {
			return false, false
		}
		return true, true
	}
	return false, rc == 0
}

// NormalizeDNFServiceList validates and sorts the systemd service names emitted by needs-restarting -s.
func NormalizeDNFServiceList(output string) (string, bool) {
	for _, line := range splitLines(output) {
		if line != strings.TrimSpace(line) || len(line) > 255 || !dnfServiceUnitRe.MatchString(line) {
			return "", false
		}
	}
	return sortUniqNonEmpty(output), true
}

// DNFInput 是 check_dnf 的原始输入（run 层采集；--test-reboot 夹具在 run 层构造）。
type DNFInput struct {
	Generation         DNFGeneration
	HasNeedsRestarting bool
	NeedsRestartingR   string // `needs-restarting -r` / `dnf needs-restarting` stdout
	NeedsRestartingRC  int    // -r 退出码
	HasS               bool   // 本机 needs-restarting 是否支持 -s（--help 含 -s）
	NeedsRestartingS   string // `needs-restarting -s` stdout（HasS 为真时）
	UpdateInfo         string // `dnf -q updateinfo list security updates` 前 40 行（无 dnf 时为空）
}

// ParseDNF 复刻 check_dnf：整机重启按 needs-restarting -r 的文案和退出码共同判断，避免命令错误或
// 输出漂移被误判为“需要重启”或“不需要重启”；关注信号只取 needs-restarting -s 报告的服务；
// 老版不支持 -s 时退回“仅整机重启”并在摘要给出可见提示。restart_signal = 排序去重的服务列表本身。
func ParseDNF(in DNFInput) RestartState {
	var st RestartState
	rebootLabel, servicesLabel := "needs-restarting -r", "needs-restarting -s"
	missingSummary := "needs-restarting 命令不存在；请安装 dnf-utils/yum-utils / needs-restarting command not found; install dnf-utils/yum-utils"
	if in.Generation == DNF5 {
		rebootLabel, servicesLabel = "dnf needs-restarting", "dnf needs-restarting -s"
		missingSummary = "dnf needs-restarting 子命令不可用；请安装 dnf5-plugins / dnf needs-restarting unavailable; install dnf5-plugins"
	}

	if in.HasNeedsRestarting {
		if required, valid := DNFRebootDecision(in.NeedsRestartingR, in.NeedsRestartingRC); valid {
			st.RebootRequired = required
		}
		var nrSvc string
		if in.HasS {
			nrSvc, _ = NormalizeDNFServiceList(in.NeedsRestartingS)
		}
		st.RestartAttention = nrSvc != ""
		if in.HasS {
			st.RestartSummary = rebootLabel + ":\\n" + in.NeedsRestartingR +
				"\\n\\n" + servicesLabel + ":\\n" + nrSvc
		} else {
			st.RestartSummary = rebootLabel + ":\\n" + in.NeedsRestartingR +
				"\\n\\n此版本 needs-restarting 不支持 -s，仅按整机重启判断。/ This needs-restarting lacks -s; reboot-only detection."
		}
		st.RestartSignal = nrSvc
	} else {
		st.RestartSummary = missingSummary
	}

	// reboot_pkgs：从 update_summary 取像“包名.架构”的 $NF，去空、排序去重、取前 40。
	var pkgs []string
	for _, ln := range splitLines(in.UpdateInfo) {
		f := strings.Fields(ln)
		if len(f) == 0 {
			continue
		}
		last := f[len(f)-1]
		if archRe.MatchString(last) {
			pkgs = append(pkgs, last)
		}
	}
	sorted := sortUniqNonEmpty(strings.Join(pkgs, "\n"))
	if sorted != "" {
		st.RebootPkgs = strings.Join(firstN(strings.Split(sorted, "\n"), 40), "\n")
	}
	return st
}

package backend

import (
	"regexp"
	"strings"
)

var (
	dnfRebootRequiredRe  = regexp.MustCompile(`(?i)reboot is required`)
	dnfRebootNotNeededRe = regexp.MustCompile(`(?i)reboot should not be necessary|no core libraries`)
	// 仅把形如“包名.架构”的 $NF 视为相关包，过滤表头/汇总噪声。
	archRe = regexp.MustCompile(`\.(x86_64|noarch|aarch64|i686|ppc64le|s390x)$`)
)

// DNFInput 是 check_dnf 的原始输入（run 层采集；--test-reboot 夹具在 run 层构造）。
type DNFInput struct {
	HasNeedsRestarting bool
	NeedsRestartingR   string // `needs-restarting -r` 的合并输出（Bash 用 2>&1）
	NeedsRestartingRC  int    // -r 退出码
	HasS               bool   // 本机 needs-restarting 是否支持 -s（--help 含 -s）
	NeedsRestartingS   string // `needs-restarting -s` stdout（HasS 为真时）
	UpdateInfo         string // `dnf -q updateinfo list security updates` 前 40 行（无 dnf 时为空）
}

// ParseDNF 复刻 check_dnf：整机重启优先按 needs-restarting -r 的文案判断（命令报错的非零码不误判为
// “需要重启”，仅 rc==1 作为文案无法匹配时的回退）；关注信号只取 needs-restarting -s 报告的服务；
// 老版不支持 -s 时退回“仅整机重启”并在摘要给出可见提示。restart_signal = 排序去重的服务列表本身。
func ParseDNF(in DNFInput) RestartState {
	var st RestartState

	if in.HasNeedsRestarting {
		switch {
		case dnfRebootRequiredRe.MatchString(in.NeedsRestartingR):
			st.RebootRequired = true
		case dnfRebootNotNeededRe.MatchString(in.NeedsRestartingR):
			st.RebootRequired = false
		case in.NeedsRestartingRC == 1:
			st.RebootRequired = true
		}
		var nrSvc string
		if in.HasS {
			nrSvc = sortUniqNonEmpty(in.NeedsRestartingS)
		}
		st.RestartAttention = nrSvc != ""
		if in.HasS {
			st.RestartSummary = "needs-restarting -r:\\n" + in.NeedsRestartingR +
				"\\n\\nneeds-restarting -s:\\n" + nrSvc
		} else {
			st.RestartSummary = "needs-restarting -r:\\n" + in.NeedsRestartingR +
				"\\n\\n此版本 needs-restarting 不支持 -s，仅按整机重启判断。/ This needs-restarting lacks -s; reboot-only detection."
		}
		st.RestartSignal = nrSvc
	} else {
		st.RestartSummary = "needs-restarting 命令不存在；请安装 dnf-utils/yum-utils / needs-restarting command not found; install dnf-utils/yum-utils"
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

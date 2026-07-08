package backend

import (
	"fmt"
	"strings"
)

// APTInput 是 check_apt 的原始输入（由 run 层采集；--test-reboot 的固定夹具在 run 层构造，不走此解析）。
type APTInput struct {
	RebootRequiredExists bool   // /var/run/reboot-required 是否存在
	RebootRequiredPkgs   string // /var/run/reboot-required.pkgs 内容（可空）
	HasNeedrestart       bool   // needrestart 命令是否存在
	NeedrestartB         string // `needrestart -b` stdout（HasNeedrestart 为真时）
}

// ParseAPT 复刻 check_apt：整机重启来自 /var/run/reboot-required；服务/内核关注与 restart_signal 来自
// needrestart -b 的 KCUR/KEXP/KSTA/SVC 字段。关注信号只取真内核更换、KSTA∈{2,3}、或存在任一 SVC 行
// （HasSVCLine 与用于 signal 的 SVC 值列表解耦）。KSTA=0 与 SESS/AUX 不触发关注。
func ParseAPT(in APTInput) RestartState {
	var st RestartState
	if in.RebootRequiredExists {
		st.RebootRequired = true
		st.RebootPkgs = sortUniqNonEmpty(in.RebootRequiredPkgs)
	}
	if !in.HasNeedrestart {
		st.RestartSummary = "needrestart 命令不存在 / needrestart command not found"
		return st
	}
	st.RestartSummary = in.NeedrestartB // 原始输出，真换行
	kcur := firstField2(in.NeedrestartB, "NEEDRESTART-KCUR:")
	kexp := firstField2(in.NeedrestartB, "NEEDRESTART-KEXP:")
	ksta := firstField2(in.NeedrestartB, "NEEDRESTART-KSTA:")

	if kcur != "" && kexp != "" && kcur != kexp {
		st.RestartAttention = true
	}
	if ksta == "2" || ksta == "3" {
		st.RestartAttention = true
	}
	// HasSVCLine：任一 ^NEEDRESTART-SVC: 行即触发关注（与下方用于 signal 的非空 SVC 值列表解耦）。
	hasSVCLine := false
	var svcVals []string
	for _, ln := range splitLines(in.NeedrestartB) {
		if strings.HasPrefix(ln, "NEEDRESTART-SVC:") {
			hasSVCLine = true
			svcVals = append(svcVals, field2(ln))
		}
	}
	if hasSVCLine {
		st.RestartAttention = true
	}
	// 稳定去重信号：KCUR/KEXP/KSTA + 排序去重的非空 SVC 值，printf 成帧后（命令替换）TrimRight 换行。
	svcSorted := sortUniqNonEmpty(strings.Join(svcVals, "\n"))
	framed := fmt.Sprintf("KCUR=%s\nKEXP=%s\nKSTA=%s\n%s\n", kcur, kexp, ksta, svcSorted)
	st.RestartSignal = strings.TrimRight(framed, "\n")
	return st
}

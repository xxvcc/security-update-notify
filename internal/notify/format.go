package notify

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

// otherKindRe 复刻 grep -Ec '^NEEDRESTART-(AUX|SESS|UCSTA|UCCUR|UCEXP):'。
var otherKindRe = regexp.MustCompile(`^NEEDRESTART-(AUX|SESS|UCSTA|UCCUR|UCEXP):`)

// formatRestartSummary 复刻 format_restart_summary：先把 restart_summary 里的字面 \n 转成真换行
// （dnf 端携带字面 \n），再按后端渲染重启检测摘要（内核状态、需重启服务、其它会话/容器等）。
// 返回值不含末尾换行；调用方再截前 80 行。
func formatRestartSummary(lang i18n.Lang, backend, restartSummary string, rebootRequired bool) string {
	summary := strings.ReplaceAll(restartSummary, `\n`, "\n") // ${restart_summary//\\n/$'\n'}
	switch backend {
	case "apt":
		return formatAPT(lang, summary)
	case "dnf":
		return formatDNF(lang, summary, rebootRequired)
	}
	return ""
}

func formatAPT(lang i18n.Lang, summary string) string {
	kcur := firstField2(summary, "NEEDRESTART-KCUR:")
	kexp := firstField2(summary, "NEEDRESTART-KEXP:")
	ksta := firstField2(summary, "NEEDRESTART-KSTA:")
	var svcVals []string
	otherCount := 0
	for _, ln := range splitLines(summary) {
		if strings.HasPrefix(ln, "NEEDRESTART-SVC:") {
			svcVals = append(svcVals, field2(ln))
		}
		if otherKindRe.MatchString(ln) {
			otherCount++
		}
	}
	services := sortUniqNonEmpty(strings.Join(svcVals, "\n"))
	serviceCount := 0
	if services != "" {
		serviceCount = len(strings.Split(services, "\n"))
	}

	var out []string
	if lang == i18n.EN {
		if kcur != "" || kexp != "" {
			out = append(out, fmt.Sprintf("Kernel: current %s, expected %s", or(kcur, "unknown"), or(kexp, "unknown")))
		}
		if ksta != "" {
			out = append(out, "Kernel status code: "+ksta)
		}
		if serviceCount > 0 {
			out = append(out, fmt.Sprintf("Services to review/restart (%d):", serviceCount))
			out = appendBulleted(out, services, serviceCount, "• ... and %d more")
		}
		if otherCount > 0 {
			out = append(out, "Additional sessions/containers/processes need review. Run needrestart on the server for details.")
		}
		if kcur == "" && kexp == "" && services == "" && otherCount == 0 {
			out = append(out, "No detailed restart list was available. Run needrestart -b on the server for details.")
		}
	} else {
		if kcur != "" || kexp != "" {
			out = append(out, fmt.Sprintf("内核：当前 %s，建议 %s", or(kcur, "未知"), or(kexp, "未知")))
		}
		if ksta != "" {
			out = append(out, "内核状态码："+ksta)
		}
		if serviceCount > 0 {
			out = append(out, fmt.Sprintf("建议评估/重启的服务（%d 个）：", serviceCount))
			out = appendBulleted(out, services, serviceCount, "• ……另有 %d 个")
		}
		if otherCount > 0 {
			out = append(out, "另有用户会话、容器或进程需要关注；可在服务器上运行 needrestart 查看详情。")
		}
		if kcur == "" && kexp == "" && services == "" && otherCount == 0 {
			out = append(out, "没有拿到详细重启列表；可在服务器上运行 needrestart -b 查看详情。")
		}
	}
	return strings.Join(out, "\n")
}

func formatDNF(lang i18n.Lang, summary string, rebootRequired bool) string {
	// services：awk '/^needs-restarting -s:$/{f=1; next} /^needs-restarting/{f=0} f && NF {print}' | sort -u
	var collected []string
	f := false
	for _, ln := range splitLines(summary) {
		if ln == "needs-restarting -s:" {
			f = true
			continue
		}
		if strings.HasPrefix(ln, "needs-restarting") {
			f = false
		}
		if f && strings.TrimSpace(ln) != "" { // awk 的 NF>0：非空白行
			collected = append(collected, ln)
		}
	}
	services := sortUniqNonEmpty(strings.Join(collected, "\n"))
	serviceCount := 0
	if services != "" {
		serviceCount = len(strings.Split(services, "\n"))
	}
	sUnsupported := strings.Contains(summary, "lacks -s") || strings.Contains(summary, "不支持 -s")

	var out []string
	if lang == i18n.EN {
		if rebootRequired {
			out = append(out, "Full reboot: required by needs-restarting -r")
		}
		if sUnsupported {
			out = append(out, "Note: this needs-restarting lacks -s; per-service detection unavailable (reboot-only).")
		}
		if serviceCount > 0 {
			out = append(out, fmt.Sprintf("Services to review/restart (%d):", serviceCount))
			out = appendBulleted(out, services, serviceCount, "• ... and %d more")
		} else if !rebootRequired && !sUnsupported {
			out = append(out, "No services were reported as needing a restart. Run needs-restarting on the server for details.")
		}
	} else {
		if rebootRequired {
			out = append(out, "整机重启：needs-restarting -r 判断为需要")
		}
		if sUnsupported {
			out = append(out, "提示：此版本 needs-restarting 不支持 -s，无法按服务检测（仅整机重启）。")
		}
		if serviceCount > 0 {
			out = append(out, fmt.Sprintf("建议评估/重启的服务（%d 个）：", serviceCount))
			out = appendBulleted(out, services, serviceCount, "• ……另有 %d 个")
		} else if !rebootRequired && !sUnsupported {
			out = append(out, "没有服务被报告需要重启；可在服务器上运行 needs-restarting 查看详情。")
		}
	}
	return strings.Join(out, "\n")
}

// appendBulleted 复刻 `sed -n '1,12p' | sed 's/^/• /'` + 超 12 的“另有 N 个”行。
func appendBulleted(out []string, services string, serviceCount int, moreFmt string) []string {
	lines := strings.Split(services, "\n")
	limit := len(lines)
	if limit > 12 {
		limit = 12
	}
	for _, s := range lines[:limit] {
		out = append(out, "• "+s)
	}
	if serviceCount > 12 {
		out = append(out, fmt.Sprintf(moreFmt, serviceCount-12))
	}
	return out
}

func or(v, dflt string) string {
	if v == "" {
		return dflt
	}
	return v
}

// —— 小工具（与 internal/backend 同义；此处独立一份，避免包间耦合）——

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func field2(line string) string {
	p := strings.Split(line, ": ")
	if len(p) > 1 {
		return p[1]
	}
	return ""
}

func firstField2(text, prefix string) string {
	for _, ln := range splitLines(text) {
		if strings.HasPrefix(ln, prefix) {
			return field2(ln)
		}
	}
	return ""
}

func sortUniqNonEmpty(s string) string {
	var xs []string
	for _, ln := range splitLines(s) {
		if ln != "" {
			xs = append(xs, ln)
		}
	}
	if len(xs) == 0 {
		return ""
	}
	sort.Strings(xs)
	out := xs[:0]
	var prev string
	for i, x := range xs {
		if i == 0 || x != prev {
			out = append(out, x)
		}
		prev = x
	}
	return strings.Join(out, "\n")
}

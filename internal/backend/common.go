// Package backend 把 apt(needrestart) 与 dnf(needs-restarting) 的重启/服务检测从 Bash 的 awk/sed/grep
// 迁成对“原始命令输出”的纯函数解析，产出运行时用于去重 hash 的 restart_signal（成帧/裁剪敏感）
// 与用于通知正文的 restart_summary（apt 携带真换行、dnf 携带字面 \n）。解析不 exec，便于表驱动测试。
//
// Package backend ports the apt(needrestart) and dnf(needs-restarting) reboot/service detection from
// Bash awk/sed/grep into pure parsers over raw command output, producing the runtime's restart_signal
// (used in the dedup hash; framing/trim-sensitive) and restart_summary (used in the body: apt carries real
// newlines, dnf carries literal "\n"). Parsing does not exec, so it is table-testable.
package backend

import (
	"sort"
	"strings"
)

// RestartState 是一次重启/服务检测的结果。RebootPkgs / RestartSignal 直接进入去重 hash，必须字节精确。
type RestartState struct {
	RebootRequired   bool
	RebootPkgs       string // sort -u 后换行连接，无末尾换行
	RestartAttention bool
	RestartSummary   string // 通知正文用；apt=真换行原文，dnf=含字面 \n
	RestartSignal    string // 去重 hash 用；apt=KCUR/KEXP/KSTA+SVC 成帧后 TrimRight，dnf=SVC 列表
}

// splitLines 按 \n 切分（不产生末尾空串），模拟对命令输出逐行处理。
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

// sortUniqNonEmpty 复刻 `sed '/^$/d' | sort -u`：丢空行、字节序去重排序、换行连接（无末尾换行）。
// sort.Strings 是字节序，等价于 LC_ALL=C 下的 sort。
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

// field2 复刻 `awk -F': ' '{print $2}'`：按 ": " 分隔取第二字段（不足则空）。
func field2(line string) string {
	f := strings.Split(line, ": ")
	if len(f) > 1 {
		return f[1]
	}
	return ""
}

// firstField2 复刻 `awk -F': ' '/^PREFIX/{print $2; exit}'`：首个以 prefix 起始行的第二字段。
func firstField2(text, prefix string) string {
	for _, ln := range splitLines(text) {
		if strings.HasPrefix(ln, prefix) {
			return field2(ln)
		}
	}
	return ""
}

// firstN 取前 n 行（sed -n '1,Np'）。
func firstN(lines []string, n int) []string {
	if len(lines) > n {
		return lines[:n]
	}
	return lines
}

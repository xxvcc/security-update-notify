// Package notify 组装发给 Telegram 的中/英文正文，逐字节复刻 files/security-update-notify 的告警/OK
// 模板与 format_restart_summary。运行时用字面 \n 再统一替换为换行；此处直接用真换行构造，等价且更清晰。
// 所有全角标点、箭头、圆点、省略号、emoji（含变体选择符）均按源文件原样保留。
//
// Package notify assembles the bilingual Telegram body, reproducing the alert/OK templates and
// format_restart_summary from files/security-update-notify byte-for-byte. The runtime uses literal \n then
// substitutes newlines; here we emit real newlines directly (equivalent, clearer). Full-width punctuation,
// arrows, bullets, ellipses and emoji (incl. variation selectors) are preserved verbatim.
package notify

import (
	"fmt"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

// Message 是渲染一条通知正文所需的全部显示数据（不含决策/hash 逻辑）。
type Message struct {
	Alert           bool // true=告警，false=OK
	Lang            i18n.Lang
	Host            string
	IncludePublicIP bool
	PublicIP        string // PUBLIC_IP_VALUE
	OS              string
	Backend         string
	Kernel          string
	Now             string
	RebootRequired  bool
	RebootPkgs      string // 空 -> 无/None
	RestartSummary  string // 原始 restart_summary（apt 真换行 / dnf 字面 \n）
	// 看门狗附加段（由 watchdog 产出；空则不出现）。
	HealthTxtZH, HealthTxtEN   string
	PendingTxtZH, PendingTxtEN string
	EolTxtZH, EolTxtEN         string
}

// Render 生成完整正文（无末尾换行）。
func Render(m Message) string {
	if m.Alert {
		return m.renderAlert()
	}
	return m.renderOK()
}

// hostBlock 复刻 "主机/系统/后端/内核/时间" 段（含可选公网 IP 行），两种语言共用。
func (m Message) hostBlock() string {
	var b strings.Builder
	if m.Lang == i18n.EN {
		fmt.Fprintf(&b, "Host: %s", m.Host)
		if m.IncludePublicIP {
			fmt.Fprintf(&b, "\nPublic IP: %s", m.PublicIP)
		}
		fmt.Fprintf(&b, "\nOS: %s\nBackend: %s\nCurrent kernel: %s\nTime: %s", m.OS, m.Backend, m.Kernel, m.Now)
	} else {
		fmt.Fprintf(&b, "主机：%s", m.Host)
		if m.IncludePublicIP {
			fmt.Fprintf(&b, "\n公网 IP：%s", m.PublicIP)
		}
		fmt.Fprintf(&b, "\n系统：%s\n后端：%s\n当前内核：%s\n时间：%s", m.OS, m.Backend, m.Kernel, m.Now)
	}
	return b.String()
}

// extra 复刻 extra_zh/extra_en：机制异常 / 待装安全更新 / EOL 三段，各以 "\n\n" 前缀拼接。
func (m Message) extra() string {
	var b strings.Builder
	en := m.Lang == i18n.EN
	if m.HealthTxtZH != "" {
		if en {
			b.WriteString("\n\n⚠️ Automatic security-update mechanism problem:\n" + m.HealthTxtEN)
		} else {
			b.WriteString("\n\n⚠️ 自动安全更新机制异常：\n" + m.HealthTxtZH)
		}
	}
	if m.PendingTxtZH != "" {
		if en {
			b.WriteString("\n\n" + m.PendingTxtEN)
		} else {
			b.WriteString("\n\n" + m.PendingTxtZH)
		}
	}
	if m.EolTxtZH != "" {
		if en {
			b.WriteString("\n\n" + m.EolTxtEN)
		} else {
			b.WriteString("\n\n" + m.EolTxtZH)
		}
	}
	return b.String()
}

func (m Message) renderAlert() string {
	pkgs := m.RebootPkgs
	rs := formatRestartSummary(m.Lang, m.Backend, m.RestartSummary, m.RebootRequired)
	rs = limitLines(rs, 80)
	if m.Lang == i18n.EN {
		if pkgs == "" {
			pkgs = "None"
		}
		rebootText := "Not required for now"
		if m.RebootRequired {
			rebootText = "Required"
		}
		return "⚠️ Security update action required\n\n" + m.hostBlock() +
			"\n\nFull reboot: " + rebootText +
			"\nRelated packages/security updates:\n" + pkgs +
			"\n\nRestart detection summary:\n" + rs + m.extra() +
			"\n\nRecommendation: SSH into this server during a suitable maintenance window and run reboot if a full reboot is required. If only services need restarting, review them first and restart the affected services manually."
	}
	if pkgs == "" {
		pkgs = "无"
	}
	rebootText := "暂不需要"
	if m.RebootRequired {
		rebootText = "需要"
	}
	return "⚠️ 安全更新后需要处理\n\n" + m.hostBlock() +
		"\n\n整机重启：" + rebootText +
		"\n相关包/安全更新：\n" + pkgs +
		"\n\n重启检测摘要：\n" + rs + m.extra() +
		"\n\n建议：请在方便的维护窗口 SSH 登录该服务器后手动执行 reboot；如只是服务需要重启，可先评估并重启对应服务。"
}

func (m Message) renderOK() string {
	if m.Lang == i18n.EN {
		return "✅ Security update check OK\n\n" + m.hostBlock() +
			"\n\nNo reboot or service/process restart requiring attention was detected." + m.extra()
	}
	return "✅ 安全更新检查正常\n\n" + m.hostBlock() +
		"\n\n没有发现整机重启或服务/进程重启需要关注的问题。" + m.extra()
}

// limitLines 复刻 `sed -n '1,Np'`：只保留前 n 行。
func limitLines(s string, n int) string {
	if s == "" {
		return s
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

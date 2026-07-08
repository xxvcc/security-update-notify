// Package watchdog 复刻安全更新看门狗的纯逻辑：自动更新机制健康（check_update_health）、待安装安全
// 更新统计（collect_security_updates）、发行版 EOL（check_eol / eol_date_for）。产出进入去重 hash 的
// HEALTH_SIG / EOL_SIG（成帧敏感：HEALTH_SIG 尾逗号）与进入正文的双语文案。系统采集（systemctl/df/
// date）在 run 层完成，此处只对已采集值做纯函数处理，便于表驱动测试。
//
// Package watchdog reproduces the security-update watchdog's pure logic: auto-update health, pending
// security-update counts, and distro EOL. It produces HEALTH_SIG / EOL_SIG (hashed; HEALTH_SIG has a
// trailing comma) and the bilingual body text. System collection (systemctl/df/date) happens in the run
// layer; here we operate on already-collected values so the logic is table-testable.
package watchdog

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Health 是 check_update_health 的结果。
type Health struct {
	Attention bool
	Sig       string // sort -u 的 reason 逗号连接，带尾逗号；无则空
	TxtZH     string
	TxtEN     string
}

// DiskAvail 是一个挂载点的可用空间（KB）。仅传入实际存在的挂载点，顺序 / 然后 /boot。
type DiskAvail struct {
	Mount   string
	AvailKB int64
}

// HealthInput 是 check_update_health 的已采集输入。
type HealthInput struct {
	Backend           string // apt|dnf；其它直接返回空 Health
	TimerEnabled      bool   // systemctl is-enabled <timer> 成功
	SvcResult         string // systemctl show <svc> -p Result --value（可空）
	HaveSvcExit       bool   // ExecMainExitTimestamp 是否非空
	SvcExitEpoch      int64  // 解析后的 epoch（解析失败为 0）
	HaveTimerTrigger  bool   // LastTriggerUSec 是否非空且非 n/a
	TimerTriggerEpoch int64
	Now               int64
	StaleDays         int
	Disks             []DiskAvail
}

// CheckHealth 复刻 check_update_health：定时器未启用 / 上次失败 / 超期未成功 / 磁盘将满，任一命中即
// 关注。reason 顺序化为 HEALTH_SIG（sort -u + 尾逗号），文案按检查顺序拼接。
func CheckHealth(in HealthInput) Health {
	var h Health
	var timer, svc string
	switch in.Backend {
	case "apt":
		timer, svc = "apt-daily-upgrade.timer", "apt-daily-upgrade.service"
	case "dnf":
		timer, svc = "dnf-automatic.timer", "dnf-automatic.service"
	default:
		return h
	}
	var reasons []string
	var zh, en strings.Builder

	if !in.TimerEnabled {
		h.Attention = true
		reasons = append(reasons, "disabled")
		fmt.Fprintf(&zh, "• 自动安全更新定时器未启用（%s）\n", timer)
		fmt.Fprintf(&en, "• Automatic security-update timer is not enabled (%s)\n", timer)
	}
	if in.SvcResult != "" && in.SvcResult != "success" {
		h.Attention = true
		reasons = append(reasons, "failed")
		fmt.Fprintf(&zh, "• 上次自动更新运行失败（%s：%s）\n", svc, in.SvcResult)
		fmt.Fprintf(&en, "• The last automatic-update run failed (%s: %s)\n", svc, in.SvcResult)
	}
	staleDays := in.StaleDays
	if staleDays < 0 {
		staleDays = 7
	}
	if staleDays > 0 {
		if in.HaveSvcExit {
			if in.SvcExitEpoch > 0 && in.Now-in.SvcExitEpoch > int64(staleDays)*86400 {
				days := (in.Now - in.SvcExitEpoch) / 86400
				h.Attention = true
				reasons = append(reasons, "stale")
				fmt.Fprintf(&zh, "• 已 %d 天没有成功的自动安全更新（阈值 %d 天）\n", days, staleDays)
				fmt.Fprintf(&en, "• No successful automatic security update for %d days (threshold %d)\n", days, staleDays)
			}
		} else if in.HaveTimerTrigger {
			if in.TimerTriggerEpoch > 0 && in.Now-in.TimerTriggerEpoch > int64(staleDays)*86400 {
				days := (in.Now - in.TimerTriggerEpoch) / 86400
				h.Attention = true
				reasons = append(reasons, "never-success")
				fmt.Fprintf(&zh, "• 自动安全更新定时器已触发过，但没有成功运行记录（最近触发约 %d 天前）\n", days)
				fmt.Fprintf(&en, "• The automatic-update timer has triggered, but no successful run was recorded (last trigger ~%d days ago)\n", days)
			}
		}
	}
	for _, d := range in.Disks {
		if d.AvailKB < 204800 {
			h.Attention = true
			reasons = append(reasons, "disk")
			fmt.Fprintf(&zh, "• %s 剩余空间不足（%d MB），可能导致更新失败\n", d.Mount, d.AvailKB/1024)
			fmt.Fprintf(&en, "• Low free space on %s (%d MB); updates may fail\n", d.Mount, d.AvailKB/1024)
		}
	}
	h.TxtZH = strings.TrimRight(zh.String(), "\n")
	h.TxtEN = strings.TrimRight(en.String(), "\n")
	if len(reasons) > 0 {
		h.Sig = sortUniqCSV(reasons)
	}
	return h
}

// sortUniqCSV 复刻 `printf '%s\n' reasons | sort -u | tr '\n' ','`：字节序去重排序后逗号连接，带尾逗号。
func sortUniqCSV(xs []string) string {
	cp := append([]string(nil), xs...)
	sort.Strings(cp)
	var out []string
	var prev string
	for i, x := range cp {
		if i == 0 || x != prev {
			out = append(out, x)
		}
		prev = x
	}
	return strings.Join(out, ",") + ","
}

// Pending 是 collect_security_updates 的结果（信息项，不单独触发发送）。
type Pending struct {
	Count int
	Crit  int
	TxtZH string
	TxtEN string
}

// archTail 复刻 `$NF ~ /\.(x86_64|noarch|aarch64|i686|ppc64le|s390x)$/`。
var archTails = []string{".x86_64", ".noarch", ".aarch64", ".i686", ".ppc64le", ".s390x"}

func hasArchTail(s string) bool {
	for _, a := range archTails {
		if strings.HasSuffix(s, a) {
			return true
		}
	}
	return false
}

// CollectPending 复刻 collect_security_updates：
//   - dnf：`dnf -q updateinfo list security` 中 $NF 形如包名.架构 的行计数，另计含 critical 的行；
//   - apt：`apt-get -s upgrade` 中以 "Inst " 起始且（小写）含 "security" 的行计数。
func CollectPending(backend, out string) Pending {
	var p Pending
	switch backend {
	case "dnf":
		for _, ln := range strings.Split(out, "\n") {
			f := strings.Fields(ln)
			if len(f) == 0 {
				continue
			}
			last := f[len(f)-1]
			if hasArchTail(last) {
				p.Count++
				if strings.Contains(strings.ToLower(ln), "critical") {
					p.Crit++
				}
			}
		}
	case "apt":
		for _, ln := range strings.Split(out, "\n") {
			if strings.HasPrefix(ln, "Inst ") && strings.Contains(strings.ToLower(ln), "security") {
				p.Count++
			}
		}
	default:
		return p
	}
	if p.Count > 0 {
		if p.Crit > 0 {
			p.TxtZH = fmt.Sprintf("待安装安全更新：%d 个（其中高危/重要 %d 个）", p.Count, p.Crit)
			p.TxtEN = fmt.Sprintf("Pending security updates: %d (%d critical/important)", p.Count, p.Crit)
		} else {
			p.TxtZH = fmt.Sprintf("待安装安全更新：%d 个", p.Count)
			p.TxtEN = fmt.Sprintf("Pending security updates: %d", p.Count)
		}
	}
	return p
}

// EOL 是 check_eol 的结果。
type EOL struct {
	Attention bool
	Sig       string // "past" | "soon" | ""
	TxtZH     string
	TxtEN     string
}

// EolDateFor 复刻 eol_date_for：各发行版“安全支持终止”近似日期（best-effort）。无匹配返回 ""。
func EolDateFor(id, ver, pretty string) string {
	major := ver
	if i := strings.IndexByte(ver, '.'); i >= 0 {
		major = ver[:i]
	}
	switch id {
	case "debian":
		switch ver {
		case "11":
			return "2026-08-31"
		case "12":
			return "2028-06-30"
		case "13":
			return "2030-06-30"
		}
	case "ubuntu":
		switch ver {
		case "20.04":
			return "2025-05-31"
		case "22.04":
			return "2027-06-01"
		case "24.04":
			return "2029-05-31"
		}
	case "rhel", "rocky", "ol", "cloudlinux":
		switch major {
		case "8":
			return "2029-05-31"
		case "9":
			return "2032-05-31"
		case "10":
			return "2035-05-31"
		}
	case "almalinux":
		switch major {
		case "8":
			return "2029-03-01"
		case "9":
			return "2032-05-31"
		case "10":
			return "2035-05-31"
		}
	case "centos":
		if strings.Contains(pretty, "Stream") {
			switch major {
			case "8":
				return "2024-05-31"
			case "9":
				return "2027-05-31"
			}
		} else {
			switch major {
			case "7":
				return "2024-06-30"
			case "8":
				return "2021-12-31"
			}
		}
	case "amzn":
		switch ver {
		case "2023":
			return "2029-06-30"
		}
	}
	return ""
}

// CheckEOL 复刻 check_eol：已过 EOL 触发告警（sig=past）；90 天内临近仅信息（sig=soon）。
// now 为当前 epoch；EOL 日期按本地时区 00:00 解释（对应 Bash `date -d "$eol" +%s`）。
func CheckEOL(id, ver, pretty string, now int64) EOL {
	var e EOL
	eol := EolDateFor(id, ver, pretty)
	if eol == "" {
		return e
	}
	t, err := time.ParseInLocation("2006-01-02", eol, time.Local)
	if err != nil {
		return e
	}
	eolEpoch := t.Unix()
	if eolEpoch <= 0 {
		return e
	}
	const warnDays = 90
	if now > eolEpoch {
		e.Attention = true
		e.Sig = "past"
		e.TxtZH = fmt.Sprintf("⛔ 本系统的安全支持已于 %s 终止，将不再收到安全更新，请尽快规划升级发行版。", eol)
		e.TxtEN = fmt.Sprintf("⛔ Security support for this release ended on %s; it no longer receives security updates. Plan a distro upgrade.", eol)
	} else if eolEpoch-now < warnDays*86400 {
		days := (eolEpoch - now) / 86400
		e.Sig = "soon"
		e.TxtZH = fmt.Sprintf("⚠️ 本系统的安全支持将于 %s 终止（约剩 %d 天），请规划升级。", eol, days)
		e.TxtEN = fmt.Sprintf("⚠️ Security support for this release ends on %s (~%d days left). Plan an upgrade.", eol, days)
	}
	return e
}

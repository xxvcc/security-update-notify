package watchdog

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Issue is a stable machine-readable reason plus bilingual operator text.
type Issue struct {
	Code string
	ZH   string
	EN   string
}

type PatchInput struct {
	Pending             Pending
	PendingAgeDays      int
	PendingAlertDays    int
	BlockedPackages     []string
	Issues              []Issue
	RebootAgeDays       int
	ServiceAgeDays      int
	RestartAlertDays    int
	CurrentVersion      string
	LatestVersion       string
	SelfUpdateAvailable bool
	SelfUpdateCheckErr  bool
}

// Patch contains risks that should trigger an alert and a separately classified SUN update notice.
// Sig shares the existing HEALTH_SIG slot so the 11-field dedup wire format remains unchanged.
type Patch struct {
	RiskAttention      bool
	UpdateAvailable    bool
	Sig                string
	TxtZH              string
	TxtEN              string
	UpdateTxtZH        string
	UpdateTxtEN        string
	LatestVersion      string
	SelfUpdateCheckErr bool
}

func CheckPatch(in PatchInput) Patch {
	p := Patch{LatestVersion: in.LatestVersion, SelfUpdateCheckErr: in.SelfUpdateCheckErr}
	var reasons []string
	var zh, en []string
	add := func(code, zhText, enText string) {
		p.RiskAttention = true
		reasons = append(reasons, code)
		zh = append(zh, "• "+zhText)
		en = append(en, "• "+enText)
	}

	if in.Pending.Count > 0 && in.PendingAlertDays > 0 && in.PendingAgeDays >= in.PendingAlertDays {
		add("pending-stale",
			fmt.Sprintf("待安装安全更新已连续存在 %d 天（阈值 %d 天）", in.PendingAgeDays, in.PendingAlertDays),
			fmt.Sprintf("Pending security updates have remained for %d days (threshold %d days)", in.PendingAgeDays, in.PendingAlertDays))
	}
	blocked := sortUniqStrings(in.BlockedPackages)
	if len(blocked) > 0 {
		reasons = append(reasons, StableReason("blocked-packages", blocked))
		p.RiskAttention = true
		zh = append(zh, "• 安全更新被 hold、versionlock 或 exclude 阻止："+summarize(blocked, 8))
		en = append(en, "• Security updates are blocked by hold, versionlock, or exclude: "+summarize(blocked, 8))
	}
	for _, issue := range in.Issues {
		if issue.Code == "" {
			continue
		}
		add(issue.Code, issue.ZH, issue.EN)
	}
	if in.RestartAlertDays > 0 && in.RebootAgeDays >= in.RestartAlertDays {
		add("reboot-stale",
			fmt.Sprintf("整机重启需求已持续 %d 天（阈值 %d 天）", in.RebootAgeDays, in.RestartAlertDays),
			fmt.Sprintf("The full-reboot requirement has remained for %d days (threshold %d days)", in.RebootAgeDays, in.RestartAlertDays))
	}
	if in.RestartAlertDays > 0 && in.ServiceAgeDays >= in.RestartAlertDays {
		add("service-restart-stale",
			fmt.Sprintf("服务重启需求已持续 %d 天（阈值 %d 天）", in.ServiceAgeDays, in.RestartAlertDays),
			fmt.Sprintf("Service restart requirements have remained for %d days (threshold %d days)", in.ServiceAgeDays, in.RestartAlertDays))
	}
	if in.SelfUpdateAvailable {
		p.UpdateAvailable = true
		reasons = append(reasons, StableReason("sun-update", []string{in.LatestVersion}))
		p.UpdateTxtZH = fmt.Sprintf("SUN 新版本可用：%s -> %s。请手动运行 sudo security-update-notify --upgrade。", in.CurrentVersion, in.LatestVersion)
		p.UpdateTxtEN = fmt.Sprintf("A new SUN version is available: %s -> %s. Run sudo security-update-notify --upgrade manually.", in.CurrentVersion, in.LatestVersion)
	}
	p.TxtZH = strings.Join(zh, "\n")
	p.TxtEN = strings.Join(en, "\n")
	p.Sig = signal(reasons)
	return p
}

// StableReason binds a reason to its relevant detail set without putting arbitrary text in HEALTH_SIG.
func StableReason(prefix string, details []string) string {
	details = sortUniqStrings(details)
	sum := sha256.Sum256([]byte(strings.Join(details, "\n")))
	return prefix + "-" + hex.EncodeToString(sum[:6])
}

// MergeSignals combines existing comma-framed HEALTH_SIG values while preserving sorted trailing-comma form.
func MergeSignals(signals ...string) string {
	var reasons []string
	for _, sig := range signals {
		for _, reason := range strings.Split(sig, ",") {
			if reason != "" {
				reasons = append(reasons, reason)
			}
		}
	}
	return signal(reasons)
}

func signal(reasons []string) string {
	reasons = sortUniqStrings(reasons)
	if len(reasons) == 0 {
		return ""
	}
	return strings.Join(reasons, ",") + ","
}

func sortUniqStrings(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	out := append([]string(nil), xs...)
	sort.Strings(out)
	n := 0
	for _, x := range out {
		if x == "" || (n > 0 && out[n-1] == x) {
			continue
		}
		out[n] = x
		n++
	}
	return out[:n]
}

func summarize(xs []string, limit int) string {
	if len(xs) <= limit {
		return strings.Join(xs, ", ")
	}
	return fmt.Sprintf("%s ... (+%d)", strings.Join(xs[:limit], ", "), len(xs)-limit)
}

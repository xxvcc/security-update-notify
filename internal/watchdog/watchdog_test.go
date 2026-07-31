package watchdog

import (
	"strings"
	"testing"
	"time"
)

// 证明 golden apt-health-disabled 依赖的 HEALTH_SIG 与健康文案是被“派生”出来的（非仅硬编码于
// dedup/notify 的 golden 测试）：定时器未启用 -> sig="disabled,"，文案与 golden 正文一致。
func TestCheckHealthDisabledDerivesGoldenValues(t *testing.T) {
	h := CheckHealth(HealthInput{
		Backend:      "apt",
		TimerEnabled: false,
		StaleDays:    0, // golden 场景 STALE_UPDATE_DAYS=0 -> 跳过 stale 检查
		Disks:        []DiskAvail{{Mount: "/", AvailKB: 99000000}, {Mount: "/boot", AvailKB: 99000000}},
	})
	if !h.Attention {
		t.Fatal("expected attention")
	}
	if h.Sig != "disabled," {
		t.Errorf("Sig=%q want %q (trailing comma landmine)", h.Sig, "disabled,")
	}
	if h.TxtZH != "• 自动安全更新定时器未启用（apt-daily-upgrade.timer）" {
		t.Errorf("TxtZH=%q", h.TxtZH)
	}
	if h.TxtEN != "• Automatic security-update timer is not enabled (apt-daily-upgrade.timer)" {
		t.Errorf("TxtEN=%q", h.TxtEN)
	}
}

func TestCheckHealthMultiReasonSortedWithTrailingComma(t *testing.T) {
	// disk 后于 disabled 触发，但 HEALTH_SIG 是 sort -u -> "disabled,disk,"。
	h := CheckHealth(HealthInput{
		Backend:      "dnf",
		TimerEnabled: false,
		StaleDays:    0,
		Disks:        []DiskAvail{{Mount: "/", AvailKB: 1000}}, // < 200MB
	})
	if h.Sig != "disabled,disk," {
		t.Errorf("Sig=%q want disabled,disk,", h.Sig)
	}
}

func TestCheckHealthStale(t *testing.T) {
	now := int64(1_700_000_000)
	h := CheckHealth(HealthInput{
		Backend: "apt", TimerEnabled: true, SvcResult: "success",
		HaveSvcExit: true, SvcExitEpoch: now - 10*86400, Now: now, StaleDays: 7,
	})
	if !h.Attention || h.Sig != "stale," {
		t.Errorf("Attention=%v Sig=%q want true,stale,", h.Attention, h.Sig)
	}
}

func TestCheckHealthRejectsInvalidSystemdTimestamps(t *testing.T) {
	now := int64(1_700_000_000)
	for _, test := range []HealthInput{
		{Backend: "apt", TimerEnabled: true, HaveSvcExit: true, SvcExitEpoch: 0, Now: now, StaleDays: 7},
		{Backend: "apt", TimerEnabled: true, HaveSvcExit: true, SvcExitEpoch: now + 1, Now: now, StaleDays: 7},
		{Backend: "dnf", TimerEnabled: true, HaveTimerTrigger: true, TimerTriggerEpoch: 0, Now: now, StaleDays: 7},
		{Backend: "dnf", TimerEnabled: true, HaveTimerTrigger: true, TimerTriggerEpoch: now + 1, Now: now, StaleDays: 7},
	} {
		health := CheckHealth(test)
		if !health.Attention || health.Sig != "timestamp," {
			t.Errorf("invalid timestamp input=%+v health=%+v", test, health)
		}
	}
}

func TestCheckHealthHealthy(t *testing.T) {
	h := CheckHealth(HealthInput{
		Backend: "apt", TimerEnabled: true, SvcResult: "success", StaleDays: 7,
		Disks: []DiskAvail{{Mount: "/", AvailKB: 99000000}},
	})
	if h.Attention || h.Sig != "" {
		t.Errorf("healthy host: Attention=%v Sig=%q", h.Attention, h.Sig)
	}
}

func TestCheckHealthReportsSystemdQueryFailure(t *testing.T) {
	h := CheckHealth(HealthInput{
		Backend: "apt", TimerEnabled: true, SystemdQueryFailed: true,
		Disks: []DiskAvail{{Mount: "/", AvailKB: 99000000}},
	})
	if !h.Attention || h.Sig != "query," {
		t.Fatalf("query failure health=%+v", h)
	}
	if !strings.Contains(h.TxtZH, "无法可靠查询 systemd") || !strings.Contains(h.TxtEN, "Could not reliably query systemd") {
		t.Fatalf("query failure text zh=%q en=%q", h.TxtZH, h.TxtEN)
	}
}

// 镜像 ci.yml “EOL 表”回归用例。
func TestEolDateFor(t *testing.T) {
	cases := []struct{ id, ver, pretty, want string }{
		{"centos", "8", "CentOS Stream 8", "2024-05-31"},
		{"centos", "9", "CentOS Stream 9", "2027-05-31"},
		{"centos", "8", "CentOS Linux 8", "2021-12-31"},
		{"centos", "7", "CentOS Linux 7", "2024-06-30"},
		{"amzn", "2023", "Amazon Linux 2023", "2029-06-30"},
		{"almalinux", "8", "AlmaLinux 8", "2029-03-01"},
		{"rhel", "9", "Red Hat Enterprise Linux 9", "2032-05-31"},
		{"debian", "12", "Debian GNU/Linux 12", "2028-06-30"},
		{"ubuntu", "24.04", "Ubuntu 24.04", "2029-05-31"},
		{"ubuntu", "26.04", "Ubuntu 26.04", "2031-05-31"},
		{"ol", "9", "Oracle Linux 9", "2032-05-31"},
		{"fedora", "43", "Fedora 43", "2026-12-02"},
		{"fedora", "44", "Fedora 44", "2027-05-19"},
		{"centos", "10", "CentOS Stream 10", "2030-05-31"},
		{"fedora", "40", "Fedora 40", ""},
	}
	for _, c := range cases {
		if got := EolDateFor(c.id, c.ver, c.pretty); got != c.want {
			t.Errorf("EolDateFor(%q,%q,%q)=%q want %q", c.id, c.ver, c.pretty, got, c.want)
		}
	}
}

func TestCheckEOL(t *testing.T) {
	// debian 11 EOL 2026-08-31。
	eol := time.Date(2026, 8, 31, 0, 0, 0, 0, time.Local).Unix()
	past := CheckEOL("debian", "11", "Debian 11", eol+86400)
	if !past.Attention || past.Sig != "past" {
		t.Errorf("past: Attention=%v Sig=%q", past.Attention, past.Sig)
	}
	soon := CheckEOL("debian", "11", "Debian 11", eol-30*86400)
	if soon.Attention || soon.Sig != "soon" {
		t.Errorf("soon: Attention=%v Sig=%q (approaching is informational only)", soon.Attention, soon.Sig)
	}
	far := CheckEOL("debian", "11", "Debian 11", eol-200*86400)
	if far.Attention || far.Sig != "" {
		t.Errorf("far: Attention=%v Sig=%q", far.Attention, far.Sig)
	}
	none := CheckEOL("fedora", "40", "Fedora 40", eol)
	if none.Sig != "" {
		t.Errorf("not in table: Sig=%q", none.Sig)
	}
	fromSupportEnd := CheckEOLDate("2026-08-31", eol-30*86400)
	if fromSupportEnd.Attention || fromSupportEnd.Sig != "soon" {
		t.Errorf("SUPPORT_END: Attention=%v Sig=%q", fromSupportEnd.Attention, fromSupportEnd.Sig)
	}
	if invalid := CheckEOLDate("2026-8-31", eol); invalid != (EOL{}) {
		t.Errorf("invalid SUPPORT_END=%+v", invalid)
	}
}

func TestCollectPending(t *testing.T) {
	dnf := CollectPending("dnf", "Last metadata ...\nFEDORA-x Critical/Sec. kernel-6.9.x86_64\nFEDORA-y Important/Sec. openssl.x86_64\n")
	if dnf.Count != 2 || dnf.Crit != 2 {
		t.Errorf("dnf count=%d crit=%d want 2,2", dnf.Count, dnf.Crit)
	}
	if dnf.TxtZH != "待安装安全更新：2 个（其中高危/重要 2 个）" {
		t.Errorf("dnf TxtZH=%q", dnf.TxtZH)
	}
	apt := CollectPending("apt", "Inst libc6 [1] (2 Debian:12/stable [amd64]) security\nInst bash [5] (5.1 Debian:12/stable [amd64])\n")
	if apt.Count != 1 {
		t.Errorf("apt count=%d want 1", apt.Count)
	}
	if len(apt.Packages) != 1 || apt.Packages[0] != "libc6" {
		t.Errorf("apt packages=%v", apt.Packages)
	}
	none := CollectPending("apt", "")
	if none.Count != 0 || none.TxtZH != "" {
		t.Errorf("empty: count=%d txt=%q", none.Count, none.TxtZH)
	}
}

func TestBlockedPackages(t *testing.T) {
	normalAPT := CollectPending("apt", "Inst bash [1] (2 Debian-Security) security\n")
	ignoreHold := CollectPending("apt", "Inst bash [1] (2 Debian-Security) security\nInst openssl [1] (2 Debian-Security) security\n")
	if got := BlockedAPT(normalAPT, ignoreHold, "openssl\nnonsecurity\n"); len(got) != 1 || got[0] != "openssl" {
		t.Fatalf("BlockedAPT=%v", got)
	}
	normalDNF := CollectPending("dnf", "ADV Moderate/Sec. bash.x86_64\n")
	allDNF := CollectPending("dnf", "ADV Moderate/Sec. bash.x86_64\nADV Important/Sec. openssl.x86_64\n")
	if got := BlockedDNF(normalDNF, allDNF); len(got) != 1 || got[0] != "openssl.x86_64" {
		t.Fatalf("BlockedDNF=%v", got)
	}
}

func TestPolicyChecks(t *testing.T) {
	apt := `APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,label=Debian-Security";
Unattended-Upgrade::Automatic-Reboot "false";`
	if issues := CheckAPTPolicy(apt, true); len(issues) != 0 {
		t.Fatalf("healthy apt policy issues=%v", issues)
	}
	if issues := CheckAPTPolicy(strings.Replace(apt, `"1"`, `"0"`, 1), false); len(issues) < 2 {
		t.Fatalf("drifted apt policy issues=%v", issues)
	}
	for _, value := range []string{"1", "true", "yes", "on"} {
		aptEquivalentTrue := `APT::Periodic::Update-Package-Lists "` + value + `";
APT::Periodic::Unattended-Upgrade "` + value + `";
Unattended-Upgrade::Origins-Pattern:: "origin=Debian,label=Debian-Security";
Unattended-Upgrade::Automatic-Reboot "false";`
		if issues := CheckAPTPolicy(aptEquivalentTrue, true); len(issues) != 0 {
			t.Errorf("APT true value %q issues=%v", value, issues)
		}
	}
	for _, origin := range []string{
		`Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}-security";`,
		`Unattended-Upgrade::Origins-Pattern:: "origin=${distro_id}ESMApps";`,
	} {
		candidate := strings.Replace(apt, `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,label=Debian-Security";`, origin, 1)
		if issues := CheckAPTPolicy(candidate, true); len(issues) != 0 {
			t.Errorf("valid APT security origin %q issues=%v", origin, issues)
		}
	}
	for _, lookalike := range []string{
		`Unattended-Upgrade::Origins-Pattern:: "origin=Example,label=NotSecurity";`,
		`Nested::Unattended-Upgrade::Origins-Pattern:: "origin=Example,label=Security";`,
	} {
		candidate := strings.Replace(apt, `Unattended-Upgrade::Origins-Pattern:: "origin=Debian,label=Debian-Security";`, lookalike, 1)
		issues := CheckAPTPolicy(candidate, true)
		if !hasIssueCode(issues, "apt-security-origin-missing") {
			t.Errorf("APT origin lookalike %q was accepted: issues=%v", lookalike, issues)
		}
	}
	for _, value := range []string{"1", "true", "yes", "on"} {
		aptAutoReboot := strings.Replace(apt, `"false"`, `"`+value+`"`, 1)
		issues := CheckAPTPolicy(aptAutoReboot, true)
		if len(issues) != 1 || issues[0].Code != "apt-auto-reboot-enabled" {
			t.Errorf("APT automatic-reboot value %q issues=%v", value, issues)
		}
	}
	dnf := "[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n"
	if issues := CheckDNFPolicy(dnf); len(issues) != 0 {
		t.Fatalf("healthy dnf policy issues=%v", issues)
	}
	for _, value := range []string{"1", "true", "yes", "on"} {
		equivalent := "[commands]\nupgrade_type = security\napply_updates = " + value + "\nreboot = never\n"
		if issues := CheckDNFPolicy(equivalent); len(issues) != 0 {
			t.Errorf("DNF true value %q issues=%v", value, issues)
		}
	}
	if issues := CheckDNFPolicy("[commands]\nupgrade_type = default\napply_updates = no\nreboot = when-needed\n"); len(issues) != 3 {
		t.Fatalf("drifted dnf policy issues=%v", issues)
	}
	for _, malformed := range []string{
		"[commands\nupgrade_type = security\napply_updates = yes\nreboot = never\n",
		"[commands]\nupgrade_type = security\napply_updates = yes\nreboot = never\n[COMMANDS]\napply_updates = yes\n",
		"[commands]\nupgrade_type = default\nupgrade_type = security\napply_updates = yes\nreboot = never\n",
	} {
		issues := CheckDNFPolicy(malformed)
		if len(issues) != 1 || issues[0].Code != "dnf-automatic-config-invalid" {
			t.Errorf("malformed DNF policy issues=%v", issues)
		}
	}
}

func hasIssueCode(issues []Issue, code string) bool {
	for _, issue := range issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}

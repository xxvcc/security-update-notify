package watchdog

import (
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

func TestCheckHealthHealthy(t *testing.T) {
	h := CheckHealth(HealthInput{
		Backend: "apt", TimerEnabled: true, SvcResult: "success", StaleDays: 7,
		Disks: []DiskAvail{{Mount: "/", AvailKB: 99000000}},
	})
	if h.Attention || h.Sig != "" {
		t.Errorf("healthy host: Attention=%v Sig=%q", h.Attention, h.Sig)
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
		{"ol", "9", "Oracle Linux 9", "2032-05-31"},
		{"fedora", "40", "Fedora 40", ""}, // 表中不列 Fedora
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
}

func TestCollectPending(t *testing.T) {
	dnf := CollectPending("dnf", "Last metadata ...\nFEDORA-x Critical/Sec. kernel-6.9.x86_64\nFEDORA-y Moderate/Sec. openssl.x86_64\n")
	if dnf.Count != 2 || dnf.Crit != 1 {
		t.Errorf("dnf count=%d crit=%d want 2,1", dnf.Count, dnf.Crit)
	}
	if dnf.TxtZH != "待安装安全更新：2 个（其中高危/重要 1 个）" {
		t.Errorf("dnf TxtZH=%q", dnf.TxtZH)
	}
	apt := CollectPending("apt", "Inst libc6 [1] (2 Debian:12/stable [amd64]) security\nInst bash [5] (5.1 Debian:12/stable [amd64])\n")
	if apt.Count != 1 {
		t.Errorf("apt count=%d want 1", apt.Count)
	}
	none := CollectPending("apt", "")
	if none.Count != 0 || none.TxtZH != "" {
		t.Errorf("empty: count=%d txt=%q", none.Count, none.TxtZH)
	}
}

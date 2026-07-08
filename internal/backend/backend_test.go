package backend

import (
	"strings"
	"testing"
)

func TestParseAPTNeedrestartSVC(t *testing.T) {
	// 与 golden apt-needrestart-svc 场景同输入：KCUR!=KEXP + 两个 SVC。
	nrb := "NEEDRESTART-VER: 3.6\n" +
		"NEEDRESTART-KCUR: 6.1.0-43-amd64\n" +
		"NEEDRESTART-KEXP: 6.1.0-44-amd64\n" +
		"NEEDRESTART-KSTA: 3\n" +
		"NEEDRESTART-SVC: nginx.service\n" +
		"NEEDRESTART-SVC: ssh.service"
	st := ParseAPT(APTInput{HasNeedrestart: true, NeedrestartB: nrb})
	if !st.RestartAttention {
		t.Error("expected attention (kernel change + SVC lines)")
	}
	// restart_signal 逐字节：printf 成帧后 TrimRight，SVC 排序去重。
	want := "KCUR=6.1.0-43-amd64\nKEXP=6.1.0-44-amd64\nKSTA=3\nnginx.service\nssh.service"
	if st.RestartSignal != want {
		t.Errorf("RestartSignal =\n%q\nwant\n%q", st.RestartSignal, want)
	}
}

func TestParseAPTEmptySVCNoDoubleNewline(t *testing.T) {
	// KSTA=3 触发关注但无 SVC：signal 不得有末尾/双换行（命令替换 TrimRight）。
	nrb := "NEEDRESTART-KCUR: a\nNEEDRESTART-KEXP: b\nNEEDRESTART-KSTA: 3"
	st := ParseAPT(APTInput{HasNeedrestart: true, NeedrestartB: nrb})
	want := "KCUR=a\nKEXP=b\nKSTA=3"
	if st.RestartSignal != want {
		t.Errorf("RestartSignal = %q want %q (no trailing/double newline)", st.RestartSignal, want)
	}
	if !st.RestartAttention {
		t.Error("KSTA=3 must raise attention")
	}
}

func TestParseAPTKSTA0NoAttention(t *testing.T) {
	// KSTA=0（未知）且内核未换、无 SVC：不得触发关注（降噪不变量）。
	nrb := "NEEDRESTART-KCUR: same\nNEEDRESTART-KEXP: same\nNEEDRESTART-KSTA: 0\nNEEDRESTART-SESS: user @ pts/0"
	st := ParseAPT(APTInput{HasNeedrestart: true, NeedrestartB: nrb})
	if st.RestartAttention {
		t.Error("KSTA=0 + SESS must NOT raise attention")
	}
}

func TestParseAPTNoNeedrestart(t *testing.T) {
	st := ParseAPT(APTInput{HasNeedrestart: false})
	if st.RestartAttention || st.RestartSignal != "" {
		t.Errorf("absent needrestart: attention=%v signal=%q", st.RestartAttention, st.RestartSignal)
	}
	if st.RestartSummary != "needrestart 命令不存在 / needrestart command not found" {
		t.Errorf("summary = %q", st.RestartSummary)
	}
}

func TestParseAPTRebootRequiredPkgs(t *testing.T) {
	st := ParseAPT(APTInput{
		RebootRequiredExists: true,
		RebootRequiredPkgs:   "linux-image-amd64\n\nlinux-image-amd64\nlibc6\n",
		HasNeedrestart:       false,
	})
	if !st.RebootRequired {
		t.Error("expected reboot required")
	}
	// sort -u + 去空。
	if st.RebootPkgs != "libc6\nlinux-image-amd64" {
		t.Errorf("RebootPkgs = %q", st.RebootPkgs)
	}
}

func TestParseDNFServices(t *testing.T) {
	// 与 golden dnf-services 同输入。
	st := ParseDNF(DNFInput{
		HasNeedsRestarting: true,
		NeedsRestartingR:   "Reboot should not be necessary.",
		NeedsRestartingRC:  0,
		HasS:               true,
		NeedsRestartingS:   "sshd.service\ncrond.service",
	})
	if st.RebootRequired {
		t.Error("text says reboot not necessary")
	}
	if !st.RestartAttention {
		t.Error("services present -> attention")
	}
	if st.RestartSignal != "crond.service\nsshd.service" {
		t.Errorf("RestartSignal = %q want sorted services", st.RestartSignal)
	}
}

func TestParseDNFRebootDecision(t *testing.T) {
	cases := []struct {
		name   string
		out    string
		rc     int
		reboot bool
	}{
		{"text-required", "Reboot is required to ensure ...", 0, true},
		{"text-not-needed", "Reboot should not be necessary.", 0, false},
		{"no-core-libs", "No core libraries or services have been updated.", 1, false}, // 文案优先于 rc==1
		{"generic-error-rc2", "needs-restarting: unexpected error", 2, false},          // 报错非零码不误判
		{"rc1-fallback", "", 1, true},                                                  // 文案不匹配时 rc==1 回退
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st := ParseDNF(DNFInput{HasNeedsRestarting: true, NeedsRestartingR: c.out, NeedsRestartingRC: c.rc, HasS: true})
			if st.RebootRequired != c.reboot {
				t.Errorf("reboot=%v want %v", st.RebootRequired, c.reboot)
			}
		})
	}
}

func TestParseDNFNoSSupport(t *testing.T) {
	st := ParseDNF(DNFInput{HasNeedsRestarting: true, NeedsRestartingR: "Reboot should not be necessary.", HasS: false})
	if st.RestartSignal != "" || st.RestartAttention {
		t.Errorf("no -s: signal=%q attention=%v", st.RestartSignal, st.RestartAttention)
	}
	if !strings.Contains(st.RestartSummary, "lacks -s") {
		t.Errorf("summary should note -s unsupported: %q", st.RestartSummary)
	}
}

func TestParseDNFRebootPkgs(t *testing.T) {
	info := "Last metadata expiration ...\n" +
		"FEDORA-2026-x Important/Sec. kernel-6.9.0.x86_64\n" +
		"FEDORA-2026-y Moderate/Sec. openssl.x86_64\n" +
		"FEDORA-2026-y Moderate/Sec. openssl.x86_64\n" // 重复
	st := ParseDNF(DNFInput{HasNeedsRestarting: false, UpdateInfo: info})
	if st.RebootPkgs != "kernel-6.9.0.x86_64\nopenssl.x86_64" {
		t.Errorf("RebootPkgs = %q", st.RebootPkgs)
	}
}

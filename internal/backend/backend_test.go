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
		valid  bool
	}{
		{"text-required", "Reboot is required to fully utilize these updates.", 1, true, true},
		{"text-not-needed", "Reboot should not be necessary.", 0, false, true},
		{"no-core-libs-wrong-rc", "No core libraries or services have been updated.", 1, false, false},
		{"no-core-libs-is-not-final-status", "No core libraries or services have been updated since boot-up.", 0, false, false},
		{"official-no-reboot-output", "No core libraries or services have been updated since boot-up.\nReboot should not be necessary.\n", 0, false, true},
		{"required-wrong-rc", "Reboot is required to fully utilize these updates.", 0, false, false},
		{"generic-error-rc2", "needs-restarting: unexpected error", 2, false, false},
		{"generic-error-rc1", "metadata load failed", 1, false, false},
		{"required-phrase-inside-error", "Failed to determine whether reboot is required: D-Bus unavailable", 1, false, false},
		{"not-needed-phrase-inside-error", "probe failed after: Reboot should not be necessary.", 0, false, false},
		{"official-line-among-details", "Core libraries or services have been updated since boot-up:\n  * systemd\n\nReboot is required to fully utilize these updates.\nMore information: https://access.redhat.com/solutions/27943\n", 1, true, true},
		{"unsupported-old-wording", "Reboot is required to ensure that your system benefits from these updates.", 1, false, false},
		{"unsupported-generic-wording", "Reboot is required to apply updates.", 1, false, false},
		{"case-drift", "reboot is required to fully utilize these updates.", 1, false, false},
		{"indented-status", " Reboot is required to fully utilize these updates.", 1, false, false},
		{"duplicate-status", "Reboot should not be necessary.\nReboot should not be necessary.", 0, false, false},
		{"required-with-unknown-suffix", "Reboot is required because the probe failed.", 1, false, false},
		{"empty-success", "", 0, false, false},
		{"unknown-success", "future reboot state", 0, false, false},
		{"conflicting-text", "Reboot is required to fully utilize these updates.\nReboot should not be necessary.", 1, false, false},
		{"rc1-without-text", "", 1, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			required, valid := DNFRebootDecision(c.out, c.rc)
			if required != c.reboot || valid != c.valid {
				t.Fatalf("decision=(%v,%v) want (%v,%v)", required, valid, c.reboot, c.valid)
			}
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

func TestDetectDNFGeneration(t *testing.T) {
	for _, test := range []struct {
		name, command, output string
		want                  DNFGeneration
	}{
		{name: "dnf4", command: "dnf", output: "4.14.0\n", want: DNF4},
		{name: "dnf5 version output", command: "dnf", output: "dnf5 version 5.2.18.0\n", want: DNF5},
		{name: "explicit dnf5", command: "/usr/bin/dnf5", want: DNF5},
		{name: "failed probe is conservative", command: "dnf", want: DNF4},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := DetectDNFGeneration(test.command, test.output); got != test.want {
				t.Fatalf("DetectDNFGeneration()=%v want %v", got, test.want)
			}
		})
	}
}

func TestProbeDNFGeneration(t *testing.T) {
	for _, test := range []struct {
		name, command, output string
		want                  DNFGeneration
		known                 bool
	}{
		{name: "dnf4 numeric version", command: "dnf", output: "4.14.0\n", want: DNF4, known: true},
		{name: "yum dnf4 numeric version", command: "/usr/bin/yum", output: "4.7.0\nInstalled: dnf-4.7.0", want: DNF4, known: true},
		{name: "dnf5 version output", command: "dnf", output: "dnf5 version 5.2.18.0\n", want: DNF5, known: true},
		{name: "explicit dnf5", command: "/usr/bin/dnf5", output: "", want: DNF5, known: true},
		{name: "empty probe", command: "dnf", output: "", want: DNF4, known: false},
		{name: "unknown output", command: "dnf", output: "dnf version future\n", want: DNF4, known: false},
		{name: "invalid labelled dnf5 version", command: "dnf", output: "dnf5 version future\n", want: DNF4, known: false},
		{name: "unlabelled dnf5 version", command: "dnf", output: "5.2.18.0\n", want: DNF4, known: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, known := ProbeDNFGeneration(test.command, test.output)
			if got != test.want || known != test.known {
				t.Fatalf("ProbeDNFGeneration()=(%v, %v) want (%v, %v)", got, known, test.want, test.known)
			}
		})
	}
}

func TestDNF5AdvisoryAndTransactionParsing(t *testing.T) {
	advisories := `[
  {"name":"FEDORA-2026-a","type":"security","severity":"Moderate","nevra":"openssl-libs-1:3.2.1-1.fc43.x86_64"},
  {"name":"FEDORA-2026-b","type":"security","severity":"Important","nevra":"openssl-libs-1:3.2.2-1.fc43.x86_64"},
  {"name":"FEDORA-2026-c","type":"security","severity":"Low","nevra":"systemd-258.1-2.fc43.x86_64"},
  {"name":"FEDORA-2026-d","type":"bugfix","severity":"None","nevra":"ignored-1-1.fc43.noarch"}
]`
	// DNF 5.4 (Fedora 44) adds the section heading; DNF 5.2 (Fedora 43) may omit it under -q.
	upgrades := "Upgrades\nopenssl-libs.x86_64 1:3.2.3-1.fc43 updates\n"

	normalized, err := NormalizeDNF5Pending(advisories, upgrades)
	if err != nil {
		t.Fatal(err)
	}
	want := "FEDORA-2026-b Important/Sec. openssl-libs-1:3.2.3-1.fc43.x86_64"
	if normalized != want {
		t.Fatalf("normalized=%q want %q", normalized, want)
	}
	blocked, err := BlockedDNF5(advisories, upgrades, upgrades)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(blocked, ","); got != "systemd.x86_64" {
		t.Fatalf("blocked=%q", got)
	}
}

func TestParseDNF5AdvisoriesRejectsMalformedSecurityEntry(t *testing.T) {
	for _, input := range []string{
		`not-json`,
		`null`,
		`[null]`,
		`[{"name":"FEDORA-2026-a","severity":"Important","nevra":"openssl-2-1.fc43.x86_64"}]`,
		`[{"name":"FEDORA-2026-a","type":"security","severity":"Unknown","nevra":"openssl-2-1.fc43.x86_64"}]`,
		`[{"name":"FEDORA-2026-a","type":"future","severity":"Important","nevra":"openssl-2-1.fc43.x86_64"}]`,
		`[{"name":"FEDORA-2026-a","type":"security","severity":"Important","nevra":"missing-arch"}]`,
	} {
		if _, err := ParseDNF5Advisories(input); err == nil {
			t.Fatalf("ParseDNF5Advisories(%q) succeeded", input)
		}
	}
}

func TestParseDNF5CheckUpgradesAcceptsFedora43And44Output(t *testing.T) {
	for _, output := range []string{
		"openssl-libs.x86_64 1:3.2.3-1.fc43 updates\n",
		"Upgrades\nopenssl-libs.x86_64 1:3.2.3-1.fc44 updates\n",
		"",
		"No security updates needed, but 16 update(s) available\n",
	} {
		if _, err := ParseDNF5CheckUpgrades(output); err != nil {
			t.Fatalf("ParseDNF5CheckUpgrades(%q): %v", output, err)
		}
	}
}

func TestParseDNF5CheckUpgradesAcceptsObsoletingSection(t *testing.T) {
	output := `Upgrades
replacement.x86_64 3-1.fc44 updates
new-name.noarch 1-1.fc44 updates

Obsoleting packages
replacement.x86_64 3-1.fc44 updates
    retired.x86_64 2-1.fc44 @System
	retired-compat.x86_64 2-1.fc44 @System
new-name.noarch 1-1.fc44 updates
    old-name.noarch 1-1.fc43 @System
`
	upgrades, err := ParseDNF5CheckUpgrades(output)
	if err != nil {
		t.Fatal(err)
	}
	if len(upgrades) != 2 || upgrades[0].Key != "new-name.noarch" || upgrades[1].Key != "replacement.x86_64" {
		t.Fatalf("upgrades=%+v", upgrades)
	}
}

func TestParseDNF5CheckUpgradesRejectsOutputDrift(t *testing.T) {
	for _, output := range []string{
		"Upgrades\n",
		"Upgrades\nUpgrades\nopenssl.x86_64 2-1.fc44 updates\n",
		"Obsoleting packages\nObsoleting packages\n",
		"Future heading\nopenssl.x86_64 2-1.fc44 updates\n",
		"openssl.x86_64 2-1.fc44\n",
		"openssl.x86_64 2-1.fc44 updates\nopenssl.x86_64 3-1.fc44 updates\n",
		"    retired.x86_64 2-1.fc44 @System\n",
		"Obsoleting packages\n    retired.x86_64 2-1.fc44 @System\n",
		"Obsoleting packages\nreplacement.x86_64 3-1.fc44 updates\n",
		"Obsoleting packages\nreplacement.x86_64 3-1.fc44 updates\n    retired.x86_64 invalid @System\n",
		"Obsoleting packages\nreplacement.x86_64 3-1.fc44 updates\n    retired.x86_64 2-1.fc44 installed\n",
		"Obsoleting packages\nreplacement.x86_64 3-1.fc44 updates\n    retired.x86_64 2-1.fc44 @System\nreplacement.x86_64 3-1.fc44 updates\n    retired-again.x86_64 2-1.fc44 @System\n",
		"Upgrades\nreplacement.x86_64 3-1.fc44 updates\nObsoleting packages\nunknown.x86_64 3-1.fc44 updates\n    retired.x86_64 2-1.fc44 @System\n",
		"No security updates needed, maybe ordinary updates exist\n",
	} {
		if _, err := ParseDNF5CheckUpgrades(output); err == nil {
			t.Fatalf("ParseDNF5CheckUpgrades(%q) succeeded", output)
		}
	}
}

func TestDNF5VersionLockUsesFullTransactionNEVRA(t *testing.T) {
	advisories := `[
  {"name":"FEDORA-old","type":"security","severity":"Moderate","nevra":"pkg-2-1.fc44.x86_64"},
  {"name":"FEDORA-new","type":"security","severity":"Critical","nevra":"pkg-3-1.fc44.x86_64"}
]`
	restricted := "pkg.x86_64 2.5-1.fc44 updates\n"
	unrestricted := "pkg.x86_64 3-1.fc44 updates\n"
	normalized, err := NormalizeDNF5Pending(advisories, restricted)
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "FEDORA-old Moderate/Sec. pkg-2.5-1.fc44.x86_64" {
		t.Fatalf("normalized=%q", normalized)
	}
	blocked, err := BlockedDNF5(advisories, restricted, unrestricted)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(blocked, ","); got != "pkg.x86_64" {
		t.Fatalf("blocked=%q", got)
	}
}

func TestDNF5NewerTransactionCoversOlderAdvisories(t *testing.T) {
	advisories := `[
  {"name":"FEDORA-old","type":"security","severity":"Moderate","nevra":"pkg-2-1.fc44.x86_64"},
  {"name":"FEDORA-new","type":"security","severity":"Critical","nevra":"pkg-3-1.fc44.x86_64"}
]`
	restricted := "pkg.x86_64 4-1.fc44 updates\n"
	unrestricted := "pkg.x86_64 5-1.fc44 updates\n"
	normalized, err := NormalizeDNF5Pending(advisories, restricted)
	if err != nil {
		t.Fatal(err)
	}
	if normalized != "FEDORA-new Critical/Sec. pkg-4-1.fc44.x86_64" {
		t.Fatalf("normalized=%q", normalized)
	}
	blocked, err := BlockedDNF5(advisories, restricted, unrestricted)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocked) != 0 {
		t.Fatalf("blocked=%q", blocked)
	}
}

func TestNormalizeDNF5PendingRejectsTransactionWithoutAdvisory(t *testing.T) {
	if _, err := NormalizeDNF5Pending(`[]`, "openssl.x86_64 2-1.fc44 updates\n"); err == nil {
		t.Fatal("transaction package without a security advisory was accepted")
	}
}

func TestParseDNF5SummaryUsesNativeCommandLabels(t *testing.T) {
	st := ParseDNF(DNFInput{
		Generation:         DNF5,
		HasNeedsRestarting: true,
		NeedsRestartingR:   "Reboot should not be necessary.",
		HasS:               true,
		NeedsRestartingS:   "sshd.service",
	})
	if !strings.Contains(st.RestartSummary, "dnf needs-restarting:\\n") ||
		!strings.Contains(st.RestartSummary, "dnf needs-restarting -s:\\n") {
		t.Fatalf("DNF5 summary uses wrong command labels: %q", st.RestartSummary)
	}
}

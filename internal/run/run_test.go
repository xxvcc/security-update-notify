package run

import (
	"encoding/json"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/golden"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

// TestAssembleMatchesGolden 是全链路 make-or-break 证明：重建每个受控场景的“已采集输入”，经 Assemble
// 组合，产出的 alert_hash 与正文都必须逐字节等于真 Bash 运行时的 golden。这一条覆盖
// parse→derive→compose→frame→hash 与 parse→derive→compose→render 整条链。
func TestAssembleMatchesGolden(t *testing.T) {
	want, err := golden.ByName()
	if err != nil {
		t.Fatal(err)
	}

	aptTestSummary := "NEEDRESTART-VER: test\nNEEDRESTART-KCUR: test-current\nNEEDRESTART-KEXP: test-expected\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service"
	dnfTestSummary := "needs-restarting -r:\nReboot is required to ensure that your system benefits from these updates.\n\nneeds-restarting -s:\ntest-service.service"

	// --test-reboot 直接构造的固定重启状态（restart_signal 未设 -> 空）。
	aptTestReboot := backend.RestartState{RebootRequired: true, RebootPkgs: "linux-image-amd64\nTEST-MODE-no-real-reboot", RestartAttention: true, RestartSummary: aptTestSummary}
	dnfTestReboot := backend.RestartState{RebootRequired: true, RebootPkgs: "kernel\nTEST-MODE-no-real-reboot", RestartAttention: true, RestartSummary: dnfTestSummary}

	// 经解析器/看门狗派生的状态。
	svc := backend.ParseAPT(backend.APTInput{HasNeedrestart: true, NeedrestartB: "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-43-amd64\nNEEDRESTART-KEXP: 6.1.0-44-amd64\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: ssh.service"})
	dnfSvc := backend.ParseDNF(backend.DNFInput{HasNeedsRestarting: true, NeedsRestartingR: "Reboot should not be necessary.", HasS: true, NeedsRestartingS: "sshd.service\ncrond.service"})
	healthRestart := backend.ParseAPT(backend.APTInput{HasNeedrestart: true, NeedrestartB: ""})
	disabledHealth := watchdog.CheckHealth(watchdog.HealthInput{Backend: "apt", TimerEnabled: false, StaleDays: 0, Disks: []watchdog.DiskAvail{{Mount: "/", AvailKB: 99000000}, {Mount: "/boot", AvailKB: 99000000}}})
	okDNF := backend.ParseDNF(backend.DNFInput{HasNeedsRestarting: true, NeedsRestartingR: "Reboot should not be necessary.", HasS: true, NeedsRestartingS: ""})

	base := func(b string, lang i18n.Lang) Input {
		return Input{Host: "golden-host", Backend: b, NotifyLang: lang, OS: "<OS>", Kernel: "<KERNEL>", Now: "<NOW>"}
	}
	withRestart := func(in Input, r backend.RestartState) Input { in.Restart = r; return in }

	scenarios := map[string]Input{
		"apt-test-reboot-zh":     withRestart(base("apt", i18n.ZH), aptTestReboot),
		"apt-test-reboot-en":     withRestart(base("apt", i18n.EN), aptTestReboot),
		"dnf-test-reboot-zh":     withRestart(base("dnf", i18n.ZH), dnfTestReboot),
		"dnf-test-reboot-en":     withRestart(base("dnf", i18n.EN), dnfTestReboot),
		"apt-needrestart-svc-zh": withRestart(base("apt", i18n.ZH), svc),
		"dnf-services-zh":        withRestart(base("dnf", i18n.ZH), dnfSvc),
	}
	// 看门狗健康场景。
	health := withRestart(base("apt", i18n.ZH), healthRestart)
	health.Health = disabledHealth
	scenarios["apt-health-disabled-zh"] = health
	// OK 路径（--test-ok -> SendOK，公网 IP）。
	ok := withRestart(base("dnf", i18n.ZH), okDNF)
	ok.SendOK = true
	ok.IncludePublicIP = true
	ok.PublicIP = "203.0.113.10"
	scenarios["dnf-ok-pubip-zh"] = ok

	if len(scenarios) != len(want) {
		t.Fatalf("test covers %d scenarios, golden has %d", len(scenarios), len(want))
	}
	for name, in := range scenarios {
		v := want[name]
		out := Assemble(in)
		if got := out.Hash(); got != v.Hash {
			t.Errorf("%s: hash=%s want %s", name, got, v.Hash)
		}
		if !out.Send {
			t.Errorf("%s: expected Send=true", name)
			continue
		}
		if out.Message != v.Message {
			t.Errorf("%s: message mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, out.Message, v.Message)
		}
		var card map[string]any
		if err := json.Unmarshal(out.FeishuCard, &card); err != nil {
			t.Errorf("%s: invalid Feishu card: %v", name, err)
		} else if card["schema"] != "2.0" {
			t.Errorf("%s: Feishu card schema=%v", name, card["schema"])
		}
	}
}

// 无关注且未要求 OK 通知 -> 静默不发。
func TestAssembleSilentOK(t *testing.T) {
	out := Assemble(Input{Host: "h", Backend: "dnf", NotifyLang: i18n.ZH, SendOK: false})
	if out.Attention || out.Send || out.Message != "" || len(out.FeishuCard) != 0 {
		t.Errorf("silent path: attention=%v send=%v msg=%q", out.Attention, out.Send, out.Message)
	}
	// 但 hash 仍应可计算（用于状态一致性）。
	if out.Hash() == "" {
		t.Error("hash should still be computable on silent path")
	}
}

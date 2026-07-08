package notify

import (
	"testing"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/golden"
	"github.com/xxvcc/security-update-notify/internal/i18n"
)

// TestRenderMatchesGolden 是消息侧的 make-or-break 证明：对每个受控场景，Go 渲染的正文（易变行
// OS/内核/时间 用占位符）必须逐字节等于“真·Bash 运行时”捕获并归一化后的正文。派生 restart_summary
// 的场景经 internal/backend 解析器产出，形成 backend→notify 的端到端校验。
func TestRenderMatchesGolden(t *testing.T) {
	want, err := golden.ByName()
	if err != nil {
		t.Fatal(err)
	}
	const host = "golden-host"
	ph := func(m Message) Message {
		m.Host = host
		m.OS = "<OS>"
		m.Kernel = "<KERNEL>"
		m.Now = "<NOW>"
		return m
	}

	aptTestSummary := "NEEDRESTART-VER: test\nNEEDRESTART-KCUR: test-current\nNEEDRESTART-KEXP: test-expected\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service"
	dnfTestSummary := "needs-restarting -r:\nReboot is required to ensure that your system benefits from these updates.\n\nneeds-restarting -s:\ntest-service.service"

	// apt-needrestart-svc：经解析器派生 restart_summary/reboot 状态。
	svcState := backend.ParseAPT(backend.APTInput{HasNeedrestart: true, NeedrestartB: "NEEDRESTART-VER: 3.6\nNEEDRESTART-KCUR: 6.1.0-43-amd64\nNEEDRESTART-KEXP: 6.1.0-44-amd64\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: nginx.service\nNEEDRESTART-SVC: ssh.service"})
	dnfSvcState := backend.ParseDNF(backend.DNFInput{HasNeedsRestarting: true, NeedsRestartingR: "Reboot should not be necessary.", HasS: true, NeedsRestartingS: "sshd.service\ncrond.service"})
	healthState := backend.ParseAPT(backend.APTInput{HasNeedrestart: true, NeedrestartB: ""})

	msgs := map[string]Message{
		"apt-test-reboot-zh": ph(Message{Alert: true, Lang: i18n.ZH, Backend: "apt", RebootRequired: true,
			RebootPkgs: "linux-image-amd64\nTEST-MODE-no-real-reboot", RestartSummary: aptTestSummary}),
		"apt-test-reboot-en": ph(Message{Alert: true, Lang: i18n.EN, Backend: "apt", RebootRequired: true,
			RebootPkgs: "linux-image-amd64\nTEST-MODE-no-real-reboot", RestartSummary: aptTestSummary}),
		"dnf-test-reboot-zh": ph(Message{Alert: true, Lang: i18n.ZH, Backend: "dnf", RebootRequired: true,
			RebootPkgs: "kernel\nTEST-MODE-no-real-reboot", RestartSummary: dnfTestSummary}),
		"dnf-test-reboot-en": ph(Message{Alert: true, Lang: i18n.EN, Backend: "dnf", RebootRequired: true,
			RebootPkgs: "kernel\nTEST-MODE-no-real-reboot", RestartSummary: dnfTestSummary}),
		"apt-needrestart-svc-zh": ph(Message{Alert: true, Lang: i18n.ZH, Backend: "apt",
			RebootRequired: svcState.RebootRequired, RebootPkgs: svcState.RebootPkgs, RestartSummary: svcState.RestartSummary}),
		"dnf-services-zh": ph(Message{Alert: true, Lang: i18n.ZH, Backend: "dnf",
			RebootRequired: dnfSvcState.RebootRequired, RebootPkgs: dnfSvcState.RebootPkgs, RestartSummary: dnfSvcState.RestartSummary}),
		"apt-health-disabled-zh": ph(Message{Alert: true, Lang: i18n.ZH, Backend: "apt",
			RestartSummary: healthState.RestartSummary,
			HealthTxtZH:    "• 自动安全更新定时器未启用（apt-daily-upgrade.timer）",
			HealthTxtEN:    "• Automatic security-update timer is not enabled (apt-daily-upgrade.timer)"}),
		"dnf-ok-pubip-zh": ph(Message{Alert: false, Lang: i18n.ZH, Backend: "dnf",
			IncludePublicIP: true, PublicIP: "203.0.113.10"}),
	}
	for name, m := range msgs {
		v, ok := want[name]
		if !ok {
			t.Errorf("golden missing %q", name)
			continue
		}
		if got := Render(m); got != v.Message {
			t.Errorf("scenario %s message mismatch:\n--- got ---\n%s\n--- want ---\n%s", name, got, v.Message)
		}
	}
}

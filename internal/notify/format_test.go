package notify

import (
	"strings"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

// 守护 format_restart_summary 的边缘渲染（golden 8 场景未覆盖）：>12 服务截断、SESS/AUX “其它会话”
// 提示、dnf 缺 -s 提示。这些在真机差分中已确认与 Bash 一致，此处锁死防回归。
func TestFormatRestartSummaryEdges(t *testing.T) {
	// >12 个服务 -> 只列前 12，再加“……另有 N 个”。
	svc := "NEEDRESTART-KCUR: 6.1.0-49\nNEEDRESTART-KEXP: 6.1.0-50\nNEEDRESTART-KSTA: 3"
	for i := 1; i <= 14; i++ {
		svc += "\nNEEDRESTART-SVC: svc" + pad2(i) + ".service"
	}
	zh := formatRestartSummary(i18n.ZH, "apt", svc, false)
	if !strings.Contains(zh, "建议评估/重启的服务（14 个）：") {
		t.Errorf("missing service count header:\n%s", zh)
	}
	if strings.Count(zh, "• svc") != 12 {
		t.Errorf("expected exactly 12 bullets, got %d:\n%s", strings.Count(zh, "• svc"), zh)
	}
	if !strings.Contains(zh, "• ……另有 2 个") {
		t.Errorf("missing zh truncation line:\n%s", zh)
	}
	en := formatRestartSummary(i18n.EN, "apt", svc, false)
	if !strings.Contains(en, "Services to review/restart (14):") || !strings.Contains(en, "• ... and 2 more") {
		t.Errorf("en truncation wrong:\n%s", en)
	}

	// SESS/AUX（无 SVC、内核未换）-> 只出“另有用户会话/容器/进程”提示，不列服务。
	sess := "NEEDRESTART-KCUR: same\nNEEDRESTART-KEXP: same\nNEEDRESTART-KSTA: 0\nNEEDRESTART-SESS: root @ pts/0\nNEEDRESTART-AUX: 123 /usr/bin/foo"
	out := formatRestartSummary(i18n.ZH, "apt", sess, false)
	if !strings.Contains(out, "另有用户会话、容器或进程需要关注") {
		t.Errorf("missing SESS/AUX 'other' note:\n%s", out)
	}
	if strings.Contains(out, "建议评估/重启的服务") {
		t.Errorf("SESS/AUX must not be listed as services:\n%s", out)
	}

	// dnf 缺 -s（restart_summary 带 'lacks -s' 标记）-> “不支持 -s”提示。
	dnfNoS := "needs-restarting -r:\\nReboot is required.\\n\\n此版本 needs-restarting 不支持 -s，仅按整机重启判断。/ This needs-restarting lacks -s; reboot-only detection."
	d := formatRestartSummary(i18n.ZH, "dnf", dnfNoS, true)
	if !strings.Contains(d, "不支持 -s") {
		t.Errorf("missing dnf no-s note:\n%s", d)
	}
	if !strings.Contains(d, "整机重启：needs-restarting -r 判断为需要") {
		t.Errorf("missing dnf reboot-required line:\n%s", d)
	}
}

// internal/backend/dnf.go labels the DNF5 sections "dnf needs-restarting[ -s]" instead of the bare
// DNF4 command name. Identical restart facts must therefore render identically on both generations:
// when the dnf5 labels were unrecognised the service list was dropped and the body claimed no service
// needed a restart, contradicting the very alert those services raised.
func TestFormatRestartSummaryHandlesBothDNFGenerations(t *testing.T) {
	const (
		reboot   = "Reboot should not be necessary."
		services = "crond.service\nsshd.service"
	)
	dnf4 := "needs-restarting -r:\\n" + reboot + "\\n\\nneeds-restarting -s:\\n" + services
	dnf5 := "dnf needs-restarting:\\n" + reboot + "\\n\\ndnf needs-restarting -s:\\n" + services

	for _, lang := range []i18n.Lang{i18n.EN, i18n.ZH} {
		got4 := formatRestartSummary(lang, "dnf", dnf4, false)
		got5 := formatRestartSummary(lang, "dnf", dnf5, false)
		if got5 != got4 {
			t.Errorf("lang %s: dnf5 rendering differs from dnf4:\n--- dnf4 ---\n%s\n--- dnf5 ---\n%s", lang, got4, got5)
		}
		for _, service := range []string{"crond.service", "sshd.service"} {
			if !strings.Contains(got5, service) {
				t.Errorf("lang %s: dnf5 rendering dropped %s:\n%s", lang, service, got5)
			}
		}
	}
}

func TestFormatRestartSummaryUsesNativeDNF5Command(t *testing.T) {
	const summary = "dnf needs-restarting:\\nReboot is required to fully utilize these updates.\\n\\ndnf needs-restarting -s:\\n"

	for _, lang := range []i18n.Lang{i18n.EN, i18n.ZH} {
		got := formatRestartSummary(lang, "dnf", summary, true)
		if !strings.Contains(got, "dnf needs-restarting") {
			t.Errorf("lang %s: missing native DNF5 command:\n%s", lang, got)
		}
		if strings.Contains(got, "needs-restarting -r") {
			t.Errorf("lang %s: DNF5 message recommends the DNF4-only -r form:\n%s", lang, got)
		}
	}

	got := formatRestartSummary(i18n.EN, "dnf", strings.Replace(summary, "Reboot is required to fully utilize these updates.", "Reboot should not be necessary.", 1), false)
	if !strings.Contains(got, "Run dnf needs-restarting on the server") {
		t.Fatalf("DNF5 no-service guidance uses the wrong command:\n%s", got)
	}
}

func pad2(i int) string {
	if i < 10 {
		return "0" + string(rune('0'+i))
	}
	return string(rune('0'+i/10)) + string(rune('0'+i%10))
}

package notify

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

func TestRenderFeishuCardJSON2(t *testing.T) {
	m := Message{
		Alert:            true,
		Lang:             i18n.ZH,
		Version:          "2.2.0",
		Host:             `生产服务器<&"01`,
		IncludePublicIP:  true,
		PublicIP:         "203.0.113.10",
		OS:               "Debian 12",
		Backend:          "apt",
		Kernel:           "6.1.0-test",
		Now:              "2026-07-24 17:20:00 CST",
		RebootRequired:   true,
		RestartAttention: true,
		RebootPkgs:       "linux-image-amd64\nTEST-MODE-no-real-reboot",
		RestartSummary:   "NEEDRESTART-KCUR: 6.1.0-test\nNEEDRESTART-KEXP: 6.1.0-new\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service",
		PendingCount:     2,
		PendingTxtZH:     "• 待安装安全更新：2 项",
		PendingTxtEN:     "• Pending security updates: 2",
	}
	b := RenderFeishuCard(m)
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["schema"] != "2.0" {
		t.Fatalf("schema=%v", doc["schema"])
	}
	header, _ := doc["header"].(map[string]any)
	if header["template"] != "orange" {
		t.Fatalf("header template=%v", header["template"])
	}
	encoded := string(b)
	for _, want := range []string{"生产服务器", "203.0.113.10", "Debian 12", "服务/进程重启", "维护详情", "ssh.service", "sudo reboot", projectURL} {
		if !strings.Contains(encoded, want) {
			t.Errorf("card missing %q", want)
		}
	}
	for _, forbidden := range []string{"重启检测", "template_id", "callback", "event_id"} {
		if strings.Contains(encoded, forbidden) {
			t.Errorf("card unexpectedly contains %q", forbidden)
		}
	}
	if !strings.Contains(encoded, `生产服务器\u003c\u0026\"01`) {
		t.Fatal("host characters were not safely JSON encoded")
	}
}

func TestRenderFeishuCardTreatsUntrustedInputAsPlainText(t *testing.T) {
	host := "prod\"\\\r\n<at id=\"all\"></at>&😺\x00" + string([]byte{0xff})
	b := RenderFeishuCard(Message{Alert: true, Lang: i18n.EN, Host: host})
	var doc any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	want := "prod\"\\\n<at id=\"all\"></at>&😺�"
	found := false
	var walk func(any)
	walk = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			if value["content"] == want {
				found = true
				if value["tag"] != "plain_text" {
					t.Errorf("host text tag=%v want plain_text", value["tag"])
				}
			}
			for _, child := range value {
				walk(child)
			}
		case []any:
			for _, child := range value {
				walk(child)
			}
		}
	}
	walk(doc)
	if !found {
		t.Fatalf("sanitized hostile host %q not found in card", want)
	}
	if strings.Contains(string(b), `\u0000`) {
		t.Fatal("control character was not removed")
	}
}

func TestRenderFeishuCardStatusColors(t *testing.T) {
	tests := []struct {
		name     string
		message  Message
		template string
		title    string
	}{
		{name: "ok", message: Message{Lang: i18n.ZH}, template: "green", title: "安全更新检查正常"},
		{name: "maintenance", message: Message{Alert: true, Lang: i18n.ZH, RestartAttention: true}, template: "orange", title: "主机需要安全维护"},
		{name: "health", message: Message{Alert: true, Lang: i18n.ZH, HealthAttention: true}, template: "red", title: "自动安全更新机制异常"},
		{name: "eol", message: Message{Alert: true, Lang: i18n.EN, EolAttention: true}, template: "red", title: "Distribution security support ended"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var doc struct {
				Header struct {
					Template string `json:"template"`
					Title    struct {
						Content string `json:"content"`
					} `json:"title"`
				} `json:"header"`
			}
			if err := json.Unmarshal(RenderFeishuCard(tt.message), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Header.Template != tt.template || doc.Header.Title.Content != tt.title {
				t.Fatalf("got template=%q title=%q", doc.Header.Template, doc.Header.Title.Content)
			}
		})
	}
}

func TestRenderFeishuCardSizeBound(t *testing.T) {
	huge := strings.Repeat("界\\\"\n", 30000)
	b := RenderFeishuCard(Message{
		Alert:            true,
		Lang:             i18n.ZH,
		Host:             huge,
		OS:               huge,
		RebootPkgs:       huge,
		RestartSummary:   huge,
		HealthTxtZH:      huge,
		PendingTxtZH:     huge,
		EolTxtZH:         huge,
		HealthAttention:  true,
		EolAttention:     true,
		RestartAttention: true,
	})
	if !json.Valid(b) {
		t.Fatal("card is not valid JSON")
	}
	outer, err := json.Marshal(map[string]string{
		"receive_id": "ou_abcdefghijklmnopqrstuvwxyz0123456789",
		"msg_type":   "interactive",
		"content":    string(b),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(outer) > 30*1024 {
		t.Fatalf("Feishu request body=%d bytes, want <= 30 KB", len(outer))
	}
}

func TestRenderFeishuUpgradeCard(t *testing.T) {
	b := RenderFeishuUpgradeCard(UpgradeMessage{
		Lang: i18n.ZH, Host: "host-01", IncludePublicIP: true, PublicIP: "203.0.113.10",
		From: "2.1.0", To: "2.2.0", Now: "2026-07-24 17:20:00 CST",
	})
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	header := doc["header"].(map[string]any)
	if header["template"] != "blue" {
		t.Fatalf("template=%v", header["template"])
	}
	for _, want := range []string{"SUN 已升级", "2.1.0", "2.2.0", "host-01", projectURL} {
		if !strings.Contains(string(b), want) {
			t.Errorf("upgrade card missing %q", want)
		}
	}
}

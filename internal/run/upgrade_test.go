package run

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/i18n"
)

func TestCheckUpgradeRejectsInvalidLocalVersionBeforeNetwork(t *testing.T) {
	var calls int
	var stdout, stderr bytes.Buffer
	rc := checkUpgrade(" 3.1.1\n", i18n.EN, func(*http.Client, string) (string, error) {
		calls++
		return "9.9.9", nil
	}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("rc=%d want 1", rc)
	}
	if calls != 0 {
		t.Fatalf("latest release was queried %d times", calls)
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid local version was displayed: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Invalid local version") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestCheckUpgradeRejectsInvalidLatestVersionBeforeDisplayingIt(t *testing.T) {
	var stdout, stderr bytes.Buffer
	rc := checkUpgrade("3.1.1", i18n.EN, func(*http.Client, string) (string, error) {
		return " 3.1.2\n", nil
	}, &stdout, &stderr)
	if rc != 1 {
		t.Fatalf("rc=%d want 1", rc)
	}
	if strings.Contains(stdout.String(), "3.1.2") || strings.Contains(stdout.String(), "Latest version") {
		t.Fatalf("invalid latest version was displayed: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Invalid version data") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestSaySanitizesTerminalControls(t *testing.T) {
	var out bytes.Buffer
	say(&out, i18n.EN, "unused", "first\nsecond\r\x1b[31m\u202Espoof\u2028tail")
	if got, want := out.String(), "first\nsecond  [31m spoof tail\n"; got != want {
		t.Fatalf("say output = %q, want %q", got, want)
	}
}

func TestNotifyUpgradeEventIsBestEffortAcrossChannels(t *testing.T) {
	var telegramSends atomic.Int32
	var feishuTokens atomic.Int32
	var feishuSends atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			telegramSends.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"ok":false}`)
		case strings.HasSuffix(r.URL.Path, "/tenant_access_token/internal"):
			feishuTokens.Add(1)
			_, _ = io.WriteString(w, `{"code":0,"tenant_access_token":"tenant-token"}`)
		case strings.HasSuffix(r.URL.Path, "/im/v1/messages"):
			feishuSends.Add(1)
			var envelope map[string]string
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Errorf("decode Feishu envelope: %v", err)
			} else {
				if envelope["msg_type"] != "interactive" || envelope["receive_id"] != "ou_lanny" {
					t.Errorf("Feishu envelope=%v", envelope)
				}
				var card map[string]any
				if err := json.Unmarshal([]byte(envelope["content"]), &card); err != nil {
					t.Errorf("decode Feishu card: %v", err)
				} else {
					header, _ := card["header"].(map[string]any)
					if card["schema"] != "2.0" || header["template"] != "blue" || !strings.Contains(envelope["content"], "2.2.0") {
						t.Errorf("Feishu upgrade card=%v", card)
					}
				}
			}
			_, _ = io.WriteString(w, `{"code":0}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	credentials := t.TempDir()
	if err := os.WriteFile(filepath.Join(credentials, feishuCredentialName), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", credentials)
	t.Setenv(telegramBaseURLEnv, srv.URL)
	t.Setenv(feishuBaseURLEnv, srv.URL)
	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram,feishu\nTELEGRAM_BOT_TOKEN=123456:fake\nTELEGRAM_CHAT_ID=-100123\nFEISHU_APP_ID=cli_test\nFEISHU_RECEIVE_ID=ou_lanny\nNOTIFY_UPGRADE=1\nINCLUDE_PUBLIC_IP=0\n")

	if rc := NotifyUpgradeEvent(cfg, "2.2.0", "2.1.0", "2.2.0"); rc != 0 {
		t.Fatalf("rc=%d want best-effort success", rc)
	}
	if telegramSends.Load() != 1 || feishuTokens.Load() != 1 || feishuSends.Load() != 1 {
		t.Fatalf("attempts telegram=%d feishu-token=%d feishu-send=%d", telegramSends.Load(), feishuTokens.Load(), feishuSends.Load())
	}
}

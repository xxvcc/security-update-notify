package run

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

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

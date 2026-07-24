package run

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/delivery"
	"github.com/xxvcc/security-update-notify/internal/feishu"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

type fakeSender struct {
	name  string
	err   error
	sends *int
}

func (s *fakeSender) Name() string                                 { return s.name }
func (s *fakeSender) Probe(context.Context) error                  { return s.err }
func (s *fakeSender) Send(context.Context, delivery.Message) error { *s.sends++; return s.err }

func loadDeliveryConfig(t *testing.T, body string) *config.Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notify.env")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestDeliverChannelsPartialFailureDoesNotRepeatSuccess(t *testing.T) {
	for _, failed := range []string{"telegram", "feishu"} {
		t.Run(failed+" fails", func(t *testing.T) {
			state := t.TempDir()
			t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", state)
			t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
			cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram,feishu\nDEDUP_MODE=once\n")
			counts := map[string]*int{"telegram": new(int), "feishu": new(int)}
			factory := func(_ *config.Config, name string) (delivery.Sender, error) {
				var err error
				if name == failed {
					err = errors.New("temporary failure")
				}
				return &fakeSender{name: name, err: err, sends: counts[name]}, nil
			}

			message := delivery.Message{Text: "message", FeishuCard: []byte(`{"schema":"2.0"}`)}
			rc := deliverChannels(cfg, []string{"telegram", "feishu"}, message, "hash", "apt", "host", true, true, false, 100, factory)
			if rc != 1 || *counts["telegram"] != 1 || *counts["feishu"] != 1 {
				t.Fatalf("first rc=%d counts=%d,%d", rc, *counts["telegram"], *counts["feishu"])
			}
			rc = deliverChannels(cfg, []string{"telegram", "feishu"}, message, "hash", "apt", "host", true, true, false, 200, factory)
			if rc != 1 || *counts[failed] != 2 {
				t.Fatalf("second rc=%d failed channel count=%d", rc, *counts[failed])
			}

			succeeded := "telegram"
			if failed == "telegram" {
				succeeded = "feishu"
			}
			if *counts[succeeded] != 1 {
				t.Fatalf("successful %s channel repeated %d times", succeeded, *counts[succeeded])
			}
			statePath := func(channel string) string {
				if channel == "telegram" {
					return filepath.Join(state, "last-alert.sha256")
				}
				return filepath.Join(state, "last-alert.feishu.sha256")
			}
			if _, err := os.Stat(statePath(succeeded)); err != nil {
				t.Fatalf("successful %s channel state missing", succeeded)
			}
			if _, err := os.Stat(statePath(failed)); !os.IsNotExist(err) {
				t.Fatalf("failed %s channel must not persist delivery state", failed)
			}
		})
	}
}

func TestFeishuSenderFallsBackToTextOnlyForLocalCardFailure(t *testing.T) {
	var messageTypes []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tenant-token","expire":7200}`))
		case "/open-apis/im/v1/messages":
			var envelope map[string]string
			if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
				t.Errorf("decode message: %v", err)
			}
			messageTypes = append(messageTypes, envelope["msg_type"])
			_, _ = w.Write([]byte(`{"code":0}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sender := &feishuSender{
		client:    &feishu.Client{HTTP: server.Client(), BaseURL: server.URL},
		appID:     "cli_test",
		appSecret: "secret-value",
		receiveID: "ou_lanny",
	}
	if err := sender.Send(context.Background(), delivery.Message{
		Text:       "canonical text",
		FeishuCard: []byte(`{"schema":"1.0"}`),
	}); err != nil {
		t.Fatal(err)
	}
	if len(messageTypes) != 1 || messageTypes[0] != "text" {
		t.Fatalf("message types=%v want one text fallback", messageTypes)
	}
}

func TestTelegramSenderIgnoresFeishuCardAndPreservesText(t *testing.T) {
	want := "canonical Telegram text\n<at id=\"all\"></at>\\尾"
	got := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form: %v", err)
		}
		got = r.Form.Get("text")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	sender := &telegramSender{
		client: &telegram.Client{HTTP: server.Client(), BaseURL: server.URL},
		token:  "123456:fake_TOKEN",
		chatID: "-100123",
	}
	if err := sender.Send(context.Background(), delivery.Message{
		Text:       want,
		FeishuCard: []byte(`{"schema":"2.0","body":{"elements":[]}}`),
	}); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Telegram text=%q want byte-identical %q", got, want)
	}
}

func TestFeishuSenderDoesNotFallbackAfterRemoteCardFailure(t *testing.T) {
	messageRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/open-apis/auth/v3/tenant_access_token/internal":
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"tenant-token","expire":7200}`))
		case "/open-apis/im/v1/messages":
			messageRequests++
			http.Error(w, `{"code":400,"msg":"rejected"}`, http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	sender := &feishuSender{
		client:    &feishu.Client{HTTP: server.Client(), BaseURL: server.URL},
		appID:     "cli_test",
		appSecret: "secret-value",
		receiveID: "ou_lanny",
	}
	err := sender.Send(context.Background(), delivery.Message{
		Text:       "canonical text",
		FeishuCard: []byte(`{"schema":"2.0","body":{"elements":[]}}`),
	})
	if err == nil {
		t.Fatal("expected remote send failure")
	}
	if messageRequests != 1 {
		t.Fatalf("message requests=%d want 1 (no text fallback)", messageRequests)
	}
}

func TestReadFeishuSecretFromCredentialDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, feishuCredentialName), []byte("secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv(feishuSecretFileEnv, "")
	got, err := readFeishuSecret()
	if err != nil || got != "secret-value" {
		t.Fatalf("secret=%q err=%v", got, err)
	}
}

func TestReadFeishuSecretFromPlainCredentialFallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feishu-app-secret")
	if err := os.WriteFile(path, []byte("plain-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(feishuSecretFileEnv, "")
	t.Setenv(feishuEncryptedCredentialEnv, filepath.Join(t.TempDir(), "missing-encrypted"))
	t.Setenv(feishuPlainCredentialEnv, path)
	got, err := readFeishuSecret()
	if err != nil || got != "plain-secret" {
		t.Fatalf("secret=%q err=%v", got, err)
	}
}

func TestSenderForRejectsMalformedFeishuOpenID(t *testing.T) {
	t.Setenv(feishuSecretFileEnv, filepath.Join(t.TempDir(), "unused"))
	for _, receiveID := range []string{"ou_", "ou_bad/value", "ou_bad value"} {
		cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=feishu\nFEISHU_APP_ID=cli_test\nFEISHU_RECEIVE_ID="+receiveID+"\n")
		if _, err := senderFor(cfg, "feishu"); err == nil {
			t.Fatalf("expected invalid recipient %q to be rejected", receiveID)
		}
	}
}

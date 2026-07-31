package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dedup"
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

func TestDecryptFeishuSecretKillsDescendants(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "descendant-survived")
	credential := filepath.Join(dir, "credential")
	if err := os.WriteFile(credential, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(dir, "systemd-creds")
	body := "#!/bin/sh\n(/bin/sleep 0.2; printf survived > '" + marker + "') &\nwait\n"
	if err := os.WriteFile(command, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	setTestCommandPath(t, dir)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := decryptFeishuSecretContext(ctx, credential); err == nil {
		t.Fatal("timed-out credential decrypt succeeded")
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("systemd-creds descendant survived timeout: %v", err)
	}
}

func TestDeliverChannelsPartialFailureDoesNotRepeatSuccess(t *testing.T) {
	for _, failed := range []string{"telegram", "feishu"} {
		t.Run(failed+" fails", func(t *testing.T) {
			state := t.TempDir()
			t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", state)
			t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
			cfg := loadDeliveryConfig(t, strings.Join([]string{
				"NOTIFY_CHANNELS=telegram,feishu",
				"TELEGRAM_BOT_TOKEN=123456:test_token",
				"TELEGRAM_CHAT_ID=-100123",
				"FEISHU_APP_ID=cli_test",
				"FEISHU_RECEIVE_ID=ou_test",
				"DEDUP_MODE=once",
			}, "\n")+"\n")
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

func TestDeliverChannelsReportsStatePersistenceFailure(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(statePath, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", statePath)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
	cfg := loadDeliveryConfig(t, strings.Join([]string{
		"NOTIFY_CHANNELS=telegram",
		"TELEGRAM_BOT_TOKEN=123456:test_token",
		"TELEGRAM_CHAT_ID=-100123",
		"DEDUP_MODE=once",
	}, "\n")+"\n")
	sends := 0
	factory := func(_ *config.Config, name string) (delivery.Sender, error) {
		return &fakeSender{name: name, sends: &sends}, nil
	}

	rc := deliverChannels(cfg, []string{"telegram"}, delivery.Message{Text: "message"}, "hash", "apt", "host", true, true, false, 100, factory)
	if rc != 1 || sends != 1 {
		t.Fatalf("rc=%d sends=%d want 1,1", rc, sends)
	}
	contents, err := os.ReadFile(statePath)
	if err != nil || string(contents) != "marker\n" {
		t.Fatalf("state path changed: contents=%q err=%v", contents, err)
	}
}

func TestDeliverChannelsAdoptsUnchangedLegacyTargetWithoutResending(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", state)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
	if err := os.WriteFile(filepath.Join(state, "last-alert.sha256"), []byte("same-hash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "last-alert.sent_at"), []byte("100\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram\nTELEGRAM_BOT_TOKEN=123456:legacy_token\nTELEGRAM_CHAT_ID=-100123\nDEDUP_MODE=once\n")
	sends := 0
	factory := func(_ *config.Config, name string) (delivery.Sender, error) {
		return &fakeSender{name: name, sends: &sends}, nil
	}
	if rc := deliverChannels(cfg, []string{"telegram"}, delivery.Message{Text: "message"}, "same-hash", "apt", "host", true, true, false, 200, factory); rc != 0 || sends != 0 {
		t.Fatalf("legacy delivery rc=%d sends=%d want 0,0", rc, sends)
	}
	targetPath := filepath.Join(state, "last-alert.telegram.target.sha256")
	b, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("suppressed legacy state did not adopt its target: %v", err)
	}
	if got, want := string(bytes.TrimSpace(b)), dedup.TargetFingerprint("telegram", "123456", "-100123"); got != want {
		t.Fatalf("adopted target=%q want %q", got, want)
	}

	changed := loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram\nTELEGRAM_BOT_TOKEN=123456:legacy_token\nTELEGRAM_CHAT_ID=-100999\nDEDUP_MODE=once\n")
	if rc := deliverChannels(changed, []string{"telegram"}, delivery.Message{Text: "message"}, "same-hash", "apt", "host", true, true, false, 300, factory); rc != 0 || sends != 1 {
		t.Fatalf("post-migration changed target rc=%d sends=%d want 0,1", rc, sends)
	}
}

func TestDeliverChannelsTracksStableTelegramBotAndChangedChat(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", state)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
	configFor := func(token, chat string) *config.Config {
		return loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram\nTELEGRAM_BOT_TOKEN="+token+"\nTELEGRAM_CHAT_ID="+chat+"\nDEDUP_MODE=once\n")
	}
	sends := 0
	factory := func(_ *config.Config, name string) (delivery.Sender, error) {
		return &fakeSender{name: name, sends: &sends}, nil
	}
	message := delivery.Message{Text: "message"}
	if rc := deliverChannels(configFor("123456:first_token", "-100123"), []string{"telegram"}, message, "same-hash", "apt", "host", true, true, false, 100, factory); rc != 0 {
		t.Fatalf("initial delivery rc=%d", rc)
	}
	if rc := deliverChannels(configFor("123456:rotated_token", "-100123"), []string{"telegram"}, message, "same-hash", "apt", "host", true, true, false, 200, factory); rc != 0 || sends != 1 {
		t.Fatalf("same-bot token rotation rc=%d sends=%d want 0,1", rc, sends)
	}
	if rc := deliverChannels(configFor("123456:rotated_token", "-100999"), []string{"telegram"}, message, "same-hash", "apt", "host", true, true, false, 300, factory); rc != 0 || sends != 2 {
		t.Fatalf("changed chat delivery rc=%d sends=%d want 0,2", rc, sends)
	}
	b, err := os.ReadFile(filepath.Join(state, "last-alert.telegram.target.sha256"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("rotated_token")) || string(bytes.TrimSpace(b)) != dedup.TargetFingerprint("telegram", "123456", "-100999") {
		t.Fatalf("persisted Telegram target fingerprint=%q", b)
	}
}

func TestDeliverChannelsKeepsOldTargetAfterFailedChangedTargetSend(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", state)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
	oldTarget := dedup.TargetFingerprint("feishu", "cli_old", "ou_old")
	store := dedup.NewChannelStore(state, "feishu")
	if err := store.WriteDelivery("same-hash", 100, oldTarget); err != nil {
		t.Fatal(err)
	}
	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=feishu\nFEISHU_APP_ID=cli_new\nFEISHU_RECEIVE_ID=ou_new\nDEDUP_MODE=once\n")
	sends := 0
	factory := func(_ *config.Config, name string) (delivery.Sender, error) {
		return &fakeSender{name: name, sends: &sends, err: errors.New("temporary failure")}, nil
	}
	if rc := deliverChannels(cfg, []string{"feishu"}, delivery.Message{Text: "message"}, "same-hash", "apt", "host", true, true, false, 200, factory); rc != 1 || sends != 1 {
		t.Fatalf("failed changed-target delivery rc=%d sends=%d want 1,1", rc, sends)
	}
	b, err := os.ReadFile(store.TargetFile)
	if err != nil || string(bytes.TrimSpace(b)) != oldTarget {
		t.Fatalf("failed send changed target state=%q err=%v", b, err)
	}
}

func TestDeliverChannelsInstallerPendingMarkerForcesAndClearsDelivery(t *testing.T) {
	state := t.TempDir()
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", state)
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
	store := dedup.NewStore(state)
	if err := store.Write("same-hash", 100); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.TargetPendingFile, []byte("pending\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram\nTELEGRAM_BOT_TOKEN=123456:new_token\nTELEGRAM_CHAT_ID=-100999\nDEDUP_MODE=once\n")
	sends := 0
	factory := func(_ *config.Config, name string) (delivery.Sender, error) {
		return &fakeSender{name: name, sends: &sends}, nil
	}
	if rc := deliverChannels(cfg, []string{"telegram"}, delivery.Message{Text: "message"}, "same-hash", "apt", "host", true, true, false, 200, factory); rc != 0 || sends != 1 {
		t.Fatalf("pending target delivery rc=%d sends=%d want 0,1", rc, sends)
	}
	if _, err := os.Stat(store.TargetPendingFile); !os.IsNotExist(err) {
		t.Fatalf("successful pending target delivery did not clear marker: %v", err)
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
	if sender.Name() != "feishu" {
		t.Fatalf("sender name=%q", sender.Name())
	}
	if err := sender.Probe(context.Background()); err != nil {
		t.Fatalf("probe Feishu credentials: %v", err)
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
	if sender.Name() != "telegram" {
		t.Fatalf("sender name=%q", sender.Name())
	}
	if err := sender.Probe(context.Background()); err != nil {
		t.Fatalf("probe Telegram credentials: %v", err)
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
	t.Setenv(feishuEncryptedCredentialEnv, "")
	t.Setenv(feishuPlainCredentialEnv, path)
	got, err := readFeishuSecret()
	if err != nil || got != "plain-secret" {
		t.Fatalf("secret=%q err=%v", got, err)
	}
}

func TestReadFeishuSecretFallsBackWhenDefaultEncryptedCredentialIsMissing(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "default-plain")
	if err := os.WriteFile(plain, []byte("plain-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"CREDENTIALS_DIRECTORY",
		feishuSecretFileEnv,
		feishuEncryptedCredentialEnv,
		feishuPlainCredentialEnv,
	} {
		unsetTestEnvironment(t, name)
	}

	got, err := readFeishuSecretWithDefaults(filepath.Join(dir, "missing-encrypted"), plain)
	if err != nil || got != "plain-secret" {
		t.Fatalf("default plaintext fallback secret=%q err=%v", got, err)
	}
}

func unsetTestEnvironment(t *testing.T, name string) {
	t.Helper()
	value, existed := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}

func TestReadFeishuSecretDecryptsCredentialAndBoundsCommandOutput(t *testing.T) {
	dir := t.TempDir()
	credential := filepath.Join(dir, "encrypted-credential")
	if err := os.WriteFile(credential, []byte("encrypted"), 0o600); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(dir, "systemd-creds")
	if err := os.WriteFile(command, []byte(`#!/bin/sh
set -eu
[ "$1" = decrypt ]
[ "$2" = --name=feishu_app_secret ]
[ "$3" = /proc/self/fd/3 ]
[ "$4" = - ]
[ "$(cat "$3")" = encrypted ]
printf 'decrypted-secret\n'
`), 0o755); err != nil {
		t.Fatal(err)
	}
	setTestCommandPath(t, dir)
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(feishuSecretFileEnv, "")
	t.Setenv(feishuEncryptedCredentialEnv, credential)
	t.Setenv(feishuPlainCredentialEnv, "")
	got, err := readFeishuSecret()
	if err != nil || got != "decrypted-secret" {
		t.Fatalf("decrypted secret=%q err=%v", got, err)
	}

	output := &limitedSecretOutput{}
	payload := bytes.Repeat([]byte("x"), maxFeishuSecretBytes+2)
	if n, err := output.Write(payload); n != len(payload) || err != nil {
		t.Fatalf("bounded write=(%d, %v)", n, err)
	}
	if len(output.data) != maxFeishuSecretBytes+1 {
		t.Fatalf("bounded output length=%d", len(output.data))
	}
	if n, err := output.Write([]byte("ignored")); n != len("ignored") || err != nil || len(output.data) != maxFeishuSecretBytes+1 {
		t.Fatalf("full bounded write=(%d, %v), length=%d", n, err, len(output.data))
	}
}

func TestEncryptedCredentialInputIsBoundedBeforeCommandExecution(t *testing.T) {
	dir := t.TempDir()
	credential := filepath.Join(dir, "encrypted-credential")
	if err := os.WriteFile(credential, bytes.Repeat([]byte("x"), maxFeishuEncryptedCredBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "command-ran")
	command := filepath.Join(dir, "systemd-creds")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf ran > '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	setTestCommandPath(t, dir)
	if _, err := decryptFeishuSecret(credential); err == nil {
		t.Fatal("oversized encrypted credential was accepted")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("systemd-creds ran for oversized input: %v", err)
	}
}

func TestCredentialDirectoryFailureDoesNotFallBack(t *testing.T) {
	dir := t.TempDir()
	fallback := filepath.Join(t.TempDir(), "fallback-secret")
	if err := os.WriteFile(fallback, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv(feishuSecretFileEnv, fallback)
	if _, err := readFeishuSecret(); err == nil {
		t.Fatal("missing systemd credential unexpectedly fell back to a host credential")
	}
}

func TestExplicitEncryptedCredentialFailureDoesNotFallBack(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain-secret")
	if err := os.WriteFile(plain, []byte("stale-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	t.Setenv(feishuSecretFileEnv, "")
	t.Setenv(feishuEncryptedCredentialEnv, filepath.Join(t.TempDir(), "missing-encrypted"))
	t.Setenv(feishuPlainCredentialEnv, plain)
	if _, err := readFeishuSecret(); err == nil {
		t.Fatal("missing explicit encrypted credential unexpectedly fell back to plaintext")
	}
}

func TestReadFeishuSecretRejectsOversizedAndMultilineValues(t *testing.T) {
	for name, body := range map[string][]byte{
		"oversized": bytes.Repeat([]byte("x"), maxFeishuSecretBytes+1),
		"multiline": []byte("first\nsecond"),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readSecretFile(path); err == nil {
				t.Fatal("invalid secret was accepted")
			}
		})
	}
}

func TestReadFeishuSecretRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(link); err == nil {
		t.Fatal("symlinked secret was accepted")
	}
}

func TestCredentialFilesRequireEffectiveOwnerPrivateModeAndSingleLink(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
		read  func(string) error
	}{
		{
			name: "group readable",
			setup: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o640); err != nil {
					t.Fatal(err)
				}
			},
			read: func(path string) error {
				_, err := readSecretFile(path)
				return err
			},
		},
		{
			name: "hardlinked",
			setup: func(t *testing.T, path string) {
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			},
			read: func(path string) error {
				_, err := readSecretFile(path)
				return err
			},
		},
		{
			name:  "owner mismatch",
			setup: func(*testing.T, string) {},
			read: func(path string) error {
				_, err := readSecretFileForOwner(path, os.Geteuid()+1)
				return err
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			test.setup(t, path)
			if err := test.read(path); err == nil {
				t.Fatal("unsafe credential metadata was accepted")
			}
		})
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

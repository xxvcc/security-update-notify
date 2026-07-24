package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/delivery"
)

type fakeSender struct {
	name  string
	err   error
	sends *int
}

func (s *fakeSender) Name() string                       { return s.name }
func (s *fakeSender) Probe(context.Context) error        { return s.err }
func (s *fakeSender) Send(context.Context, string) error { *s.sends++; return s.err }

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

			rc := deliverChannels(cfg, []string{"telegram", "feishu"}, "message", "hash", "apt", "host", true, true, false, 100, factory)
			if rc != 1 || *counts["telegram"] != 1 || *counts["feishu"] != 1 {
				t.Fatalf("first rc=%d counts=%d,%d", rc, *counts["telegram"], *counts["feishu"])
			}
			rc = deliverChannels(cfg, []string{"telegram", "feishu"}, "message", "hash", "apt", "host", true, true, false, 200, factory)
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

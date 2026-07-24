package run

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/delivery"
	"github.com/xxvcc/security-update-notify/internal/feishu"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

var feishuOpenIDPattern = regexp.MustCompile(`^ou_[A-Za-z0-9_-]+$`)

const (
	telegramBaseURLEnv             = "SECURITY_UPDATE_NOTIFY_TELEGRAM_BASE_URL"
	feishuBaseURLEnv               = "SECURITY_UPDATE_NOTIFY_FEISHU_BASE_URL"
	feishuSecretFileEnv            = "SECURITY_UPDATE_NOTIFY_FEISHU_APP_SECRET_FILE"
	feishuEncryptedCredentialEnv   = "SECURITY_UPDATE_NOTIFY_FEISHU_CREDENTIAL_FILE"
	feishuPlainCredentialEnv       = "SECURITY_UPDATE_NOTIFY_FEISHU_PLAIN_CREDENTIAL_FILE"
	feishuCredentialName           = "feishu_app_secret"
	defaultFeishuEncryptedCredPath = "/etc/credstore.encrypted/security-update-notify-feishu-app-secret.cred"
	defaultFeishuPlainCredPath     = "/etc/security-update-notify/credentials/feishu-app-secret"
)

type telegramSender struct {
	client *telegram.Client
	token  string
	chatID string
}

func (s *telegramSender) Name() string { return "telegram" }
func (s *telegramSender) Send(ctx context.Context, text string) error {
	return s.client.SendMessage(ctx, s.token, s.chatID, text)
}
func (s *telegramSender) Probe(ctx context.Context) error { return s.client.GetMe(ctx, s.token) }

type feishuSender struct {
	client    *feishu.Client
	appID     string
	appSecret string
	receiveID string
}

func (s *feishuSender) Name() string { return "feishu" }
func (s *feishuSender) Send(ctx context.Context, text string) error {
	return s.client.SendText(ctx, s.appID, s.appSecret, s.receiveID, text)
}
func (s *feishuSender) Probe(ctx context.Context) error {
	return s.client.Probe(ctx, s.appID, s.appSecret)
}

func configuredChannels(cfg *config.Config) ([]string, error) {
	return delivery.ParseChannels(cfg.Get("NOTIFY_CHANNELS"))
}

func senderFor(cfg *config.Config, name string) (delivery.Sender, error) {
	switch name {
	case "telegram":
		token := cfg.Get("TELEGRAM_BOT_TOKEN")
		chatID := cfg.Get("TELEGRAM_CHAT_ID")
		if token == "" || chatID == "" {
			return nil, fmt.Errorf("missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")
		}
		return &telegramSender{
			client: &telegram.Client{HTTP: httpx.New(30 * time.Second), BaseURL: os.Getenv(telegramBaseURLEnv)},
			token:  token,
			chatID: chatID,
		}, nil
	case "feishu":
		appID := cfg.Get("FEISHU_APP_ID")
		receiveID := cfg.Get("FEISHU_RECEIVE_ID")
		if appID == "" || receiveID == "" {
			return nil, fmt.Errorf("missing FEISHU_APP_ID or FEISHU_RECEIVE_ID")
		}
		if !feishuOpenIDPattern.MatchString(receiveID) {
			return nil, fmt.Errorf("FEISHU_RECEIVE_ID must be an open_id")
		}
		secret, err := readFeishuSecret()
		if err != nil {
			return nil, err
		}
		return &feishuSender{
			client:    &feishu.Client{HTTP: httpx.New(30 * time.Second), BaseURL: os.Getenv(feishuBaseURLEnv)},
			appID:     appID,
			appSecret: secret,
			receiveID: receiveID,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported notification channel: %s", name)
	}
}

func readFeishuSecret() (string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		if secret, err := readSecretFile(filepath.Join(dir, feishuCredentialName)); err == nil {
			return secret, nil
		}
	}
	if path := os.Getenv(feishuSecretFileEnv); path != "" {
		return readSecretFile(path)
	}
	path := os.Getenv(feishuEncryptedCredentialEnv)
	if path == "" {
		path = defaultFeishuEncryptedCredPath
	}
	if _, err := os.Stat(path); err == nil {
		cmd := exec.Command("systemd-creds", "decrypt", "--name="+feishuCredentialName, path, "-")
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to decrypt Feishu app secret credential")
		}
		secret := strings.TrimRight(string(out), "\r\n")
		if secret == "" {
			return "", fmt.Errorf("Feishu app secret credential is empty")
		}
		return secret, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("Feishu app secret credential is unavailable")
	}
	plainPath := os.Getenv(feishuPlainCredentialEnv)
	if plainPath == "" {
		plainPath = defaultFeishuPlainCredPath
	}
	if _, err := os.Stat(plainPath); err == nil {
		return readSecretFile(plainPath)
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("Feishu app secret credential is unavailable")
	}
	return "", fmt.Errorf("Feishu app secret credential is unavailable")
}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read Feishu app secret credential")
	}
	secret := strings.TrimRight(string(b), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("Feishu app secret credential is empty")
	}
	return secret, nil
}

func channelLabel(name string) string {
	if name == "feishu" {
		return "Feishu"
	}
	return "Telegram"
}

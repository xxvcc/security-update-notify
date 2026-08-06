//lint:file-ignore ST1005 Telegram and Feishu errors intentionally retain official product capitalization.
package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/delivery"
	"github.com/xxvcc/security-update-notify/internal/feishu"
	"github.com/xxvcc/security-update-notify/internal/filetrust"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/runtimeenv"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
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
	maxFeishuSecretBytes           = 64 << 10
	maxFeishuEncryptedCredBytes    = 128 << 10
)

type telegramSender struct {
	client *telegram.Client
	token  string
	chatID string
}

func (s *telegramSender) Name() string { return "telegram" }
func (s *telegramSender) Send(ctx context.Context, message delivery.Message) error {
	return s.client.SendMessage(ctx, s.token, s.chatID, message.Text)
}
func (s *telegramSender) Probe(ctx context.Context) error { return s.client.GetMe(ctx, s.token) }

type feishuSender struct {
	client    *feishu.Client
	appID     string
	appSecret string
	receiveID string
}

func (s *feishuSender) Name() string { return "feishu" }
func (s *feishuSender) Send(ctx context.Context, message delivery.Message) error {
	if len(message.FeishuCard) != 0 {
		err := s.client.SendCard(ctx, s.appID, s.appSecret, s.receiveID, message.FeishuCard)
		if err == nil {
			return nil
		}
		if !feishu.IsCardPreflightError(err) {
			return err
		}
	}
	return s.client.SendText(ctx, s.appID, s.appSecret, s.receiveID, message.Text)
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
			client: &telegram.Client{HTTP: httpx.New(30 * time.Second), BaseURL: runtimeenv.Override(telegramBaseURLEnv)},
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
			client:    &feishu.Client{HTTP: httpx.New(30 * time.Second), BaseURL: runtimeenv.Override(feishuBaseURLEnv)},
			appID:     appID,
			appSecret: secret,
			receiveID: receiveID,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported notification channel: %s", name)
	}
}

func readFeishuSecret() (string, error) {
	return readFeishuSecretWithDefaults(defaultFeishuEncryptedCredPath, defaultFeishuPlainCredPath)
}

func readFeishuSecretWithDefaults(defaultEncryptedPath, defaultPlainPath string) (string, error) {
	if dir := os.Getenv("CREDENTIALS_DIRECTORY"); dir != "" {
		// systemd's credential directory is authoritative. Falling back after a missing or unreadable
		// LoadCredential entry could silently use stale host credentials that the unit did not load.
		return readSecretFile(filepath.Join(dir, feishuCredentialName))
	}
	if path := runtimeenv.Override(feishuSecretFileEnv); path != "" {
		return readSecretFile(path)
	}
	path, encryptedPathSet := runtimeenv.LookupOverride(feishuEncryptedCredentialEnv)
	if !encryptedPathSet {
		path = defaultEncryptedPath
	}
	if path != "" {
		secret, err := decryptFeishuSecret(path)
		if err == nil {
			return secret, nil
		}
		if !errors.Is(err, os.ErrNotExist) || encryptedPathSet {
			return "", fmt.Errorf("Feishu app secret credential is unavailable")
		}
	}
	plainPath, plainPathSet := runtimeenv.LookupOverride(feishuPlainCredentialEnv)
	if !plainPathSet {
		plainPath = defaultPlainPath
	}
	if plainPath != "" {
		secret, err := readSecretFile(plainPath)
		if err == nil {
			return secret, nil
		}
		if !errors.Is(err, os.ErrNotExist) || plainPathSet {
			return "", fmt.Errorf("Feishu app secret credential is unavailable")
		}
	}
	return "", fmt.Errorf("Feishu app secret credential is unavailable")
}

type limitedSecretOutput struct {
	data []byte
}

func (w *limitedSecretOutput) Write(p []byte) (int, error) {
	if remaining := maxFeishuSecretBytes + 1 - len(w.data); remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		w.data = append(w.data, p[:remaining]...)
	}
	return len(p), nil
}

func decryptFeishuSecret(path string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return decryptFeishuSecretContext(ctx, path)
}

func decryptFeishuSecretContext(ctx context.Context, path string) (string, error) {
	credential, err := openCredentialFile(path, maxFeishuEncryptedCredBytes, os.Geteuid())
	if err != nil {
		return "", err
	}
	defer credential.Close()

	cmd := sysexec.CommandContext(ctx, "systemd-creds", "decrypt", "--name="+feishuCredentialName, "/proc/self/fd/3", "-")
	cmd.ExtraFiles = []*os.File{credential}
	out := &limitedSecretOutput{}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to decrypt Feishu app secret credential")
	}
	return normalizeFeishuSecret(out.data)
}

func readSecretFile(path string) (string, error) {
	return readSecretFileForOwner(path, os.Geteuid())
}

func readSecretFileForOwner(path string, euid int) (string, error) {
	f, err := openCredentialFile(path, maxFeishuSecretBytes, euid)
	if err != nil {
		return "", fmt.Errorf("cannot read Feishu app secret credential: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFeishuSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("cannot read Feishu app secret credential: %w", err)
	}
	return normalizeFeishuSecret(b)
}

func openCredentialFile(path string, maxBytes int64, euid int) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open Feishu app secret credential: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(err error) (*os.File, error) {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect Feishu app secret credential: %w", err))
	}
	if err := filetrust.ValidateRegular(info, euid, 0o077, true); err != nil {
		return fail(fmt.Errorf("unsafe Feishu app secret credential: %w", err))
	}
	if maxBytes < 0 || info.Size() > maxBytes {
		return fail(fmt.Errorf("Feishu app secret credential exceeds %d bytes", maxBytes))
	}
	return f, nil
}

func normalizeFeishuSecret(b []byte) (string, error) {
	if len(b) > maxFeishuSecretBytes {
		return "", fmt.Errorf("Feishu app secret credential is too large")
	}
	secret := strings.TrimRight(string(b), "\r\n")
	if secret == "" {
		return "", fmt.Errorf("Feishu app secret credential is empty")
	}
	if strings.ContainsAny(secret, "\x00\r\n") {
		return "", fmt.Errorf("Feishu app secret credential contains invalid line breaks")
	}
	return secret, nil
}

func channelLabel(name string) string {
	if name == "feishu" {
		return "Feishu"
	}
	return "Telegram"
}

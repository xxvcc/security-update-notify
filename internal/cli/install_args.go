package cli

import (
	"bufio"

	"errors"
	"fmt"

	"os"
	"path/filepath"

	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/feishu"

	"github.com/xxvcc/security-update-notify/internal/installer"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

func (c *installCommand) parse(args []string) (installArguments, error) {
	parsed := installArguments{config: make(map[string]string)}
	if value := os.Getenv("SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS"); value != "" {
		if seconds, valid := parseWaitLockSeconds(value); valid {
			parsed.lockWait = time.Duration(seconds) * time.Second
			parsed.lockWaitSet = true
		}
	}
	for index := 0; index < len(args); index++ {
		arg := args[index]
		next := func() (string, error) {
			index++
			if index >= len(args) || args[index] == "" {
				return "", fmt.Errorf("missing value for %s", arg)
			}
			return args[index], nil
		}
		var value string
		var err error
		switch arg {
		case "--env-file":
			if value, err = next(); err == nil {
				err = c.loadInstallEnv(value, &parsed)
			}
		case "--notify-channels":
			value, err = next()
			parsed.config["NOTIFY_CHANNELS"] = value
		case "--telegram-token":
			value, err = next()
			parsed.config["TELEGRAM_BOT_TOKEN"] = value
			parsed.telegramTokenFile = ""
			fmt.Fprintln(c.console.errOut, "WARNING: --telegram-token exposes the token in the process list; prefer --telegram-token-file.")
		case "--telegram-token-file":
			value, err = next()
			parsed.telegramTokenFile = value
			delete(parsed.config, "TELEGRAM_BOT_TOKEN")
		case "--telegram-chat-id":
			value, err = next()
			parsed.config["TELEGRAM_CHAT_ID"] = value
		case "--feishu-app-id":
			value, err = next()
			parsed.config["FEISHU_APP_ID"] = value
		case "--feishu-app-secret-file":
			value, err = next()
			parsed.feishuSecretFile = value
		case "--feishu-receive-id":
			value, err = next()
			parsed.config["FEISHU_RECEIVE_ID"] = value
		case "--time":
			value, err = next()
			parsed.checkTime = value
		case "--host-label":
			value, err = next()
			parsed.config["HOST_LABEL"] = value
		case "--public-ip":
			value, err = next()
			parsed.config["PUBLIC_IP"] = value
		case "--include-public-ip":
			value, err = next()
			parsed.config["INCLUDE_PUBLIC_IP"] = value
		case "--notify-ok":
			value, err = next()
			parsed.config["NOTIFY_OK"] = value
		case "--notify-upgrade":
			value, err = next()
			parsed.config["NOTIFY_UPGRADE"] = value
		case "--dedup-mode":
			value, err = next()
			parsed.config["DEDUP_MODE"] = value
		case "--dedup-interval-days":
			value, err = next()
			parsed.config["DEDUP_INTERVAL_DAYS"] = value
		case "--notify-lang":
			value, err = next()
			parsed.config["NOTIFY_LANG"] = value
		case "--backend":
			value, err = next()
			parsed.config["BACKEND"] = value
		case "--lock-wait":
			if value, err = next(); err == nil {
				seconds, valid := parseWaitLockSeconds(value)
				if !valid {
					err = errors.New("invalid --lock-wait (expected 0..3600 seconds)")
				} else {
					parsed.lockWait = time.Duration(seconds) * time.Second
					parsed.lockWaitSet = true
				}
			}
		case "--lang":
			value, err = next()
			parsed.lang = value
		case "--allow-best-effort":
			parsed.allowBestEffort = true
		case "--configure-notifications":
			parsed.configure = true
		case "--send-test":
			parsed.sendTest = true
		case "--skip-telegram-test":
			parsed.skipTelegram = true
		case "--skip-feishu-test":
			parsed.skipFeishu = true
		case "--skip-notify-test":
			parsed.skipTelegram, parsed.skipFeishu = true, true
		case "--skip-post-install-check":
			parsed.skipPostInstallCheck = true
		case "--non-interactive":
			parsed.nonInteractive = true
		case "-y", "--yes":
			parsed.assumeYes = true
		case "-h", "--help":
			parsed.help = true
		default:
			return parsed, fmt.Errorf("unknown install argument: %s", arg)
		}
		if err != nil {
			return parsed, err
		}
	}
	if parsed.lang != "" && parsed.lang != "zh" && parsed.lang != "en" {
		return parsed, fmt.Errorf("invalid --lang (expected zh or en)")
	}
	return parsed, nil
}

func normalizeCLIChannels(raw string) (string, error) {
	raw = strings.ToLower(strings.Join(strings.Fields(raw), ""))
	if raw == "" {
		return "", errors.New("receiving platforms cannot be empty")
	}
	hasTelegram, hasFeishu := false, false
	for _, item := range strings.Split(raw, ",") {
		switch item {
		case "telegram":
			hasTelegram = true
		case "feishu":
			hasFeishu = true
		default:
			return "", fmt.Errorf("invalid receiving platform: %q", item)
		}
	}
	if hasTelegram && hasFeishu {
		return "telegram,feishu", nil
	}
	if hasTelegram {
		return "telegram", nil
	}
	if hasFeishu {
		return "feishu", nil
	}
	return "", errors.New("receiving platform normalization produced no supported platform")
}

func selectedCLIChannel(channels, channel string) bool {
	for _, item := range strings.Split(channels, ",") {
		if item == channel {
			return true
		}
	}
	return false
}

func cloneCLIConfig(source map[string]string) map[string]string {
	clone := make(map[string]string, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func validCLICheckTime(value string) bool {
	if len(value) != len("HH:MM") || value[2] != ':' {
		return false
	}
	_, err := time.Parse("15:04", value)
	return err == nil
}

func positiveCLIInteger(value string) bool {
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func invalidCLI(err error) error { return &installer.ExitError{Code: 2, Err: err} }

func (c *installCommand) loadInstallEnv(name string, parsed *installArguments) error {
	abs, err := filepath.Abs(name)
	if err != nil {
		return err
	}
	file, err := openRegularNoFollow(abs)
	if err != nil {
		return fmt.Errorf("env file must be a regular non-symlink file no larger than 1 MiB: %s", name)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect env file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 1<<20 {
		return fmt.Errorf("env file must be a regular non-symlink file no larger than 1 MiB: %s", name)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("invalid env line without '='")
		}
		key = dropInstallSpace(key)
		if key == "" {
			return fmt.Errorf("invalid empty env key")
		}
		value = strings.Trim(value, installSpace)
		if !strings.HasPrefix(value, `"`) && !strings.HasPrefix(value, "'") {
			value = stripInstallInlineComment(value)
			value = strings.TrimRight(value, installSpace)
		}
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		if err := applyInstallEnv(key, value, parsed); err != nil {
			return err
		}
	}
	return scanner.Err()
}

const installSpace = " \t\n\v\f\r"

func dropInstallSpace(value string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(installSpace, r) {
			return -1
		}
		return r
	}, value)
}

func stripInstallInlineComment(value string) string {
	for index := 0; index+1 < len(value); index++ {
		if strings.IndexByte(installSpace, value[index]) >= 0 && value[index+1] == '#' {
			return value[:index]
		}
	}
	return value
}

func applyInstallEnv(key, value string, parsed *installArguments) error {
	configKey := map[string]bool{
		"CONFIG_VERSION": true, "NOTIFY_CHANNELS": true, "TELEGRAM_BOT_TOKEN": true, "TELEGRAM_CHAT_ID": true,
		"FEISHU_APP_ID": true, "FEISHU_RECEIVE_ID": true, "HOST_LABEL": true, "PUBLIC_IP": true,
		"INCLUDE_PUBLIC_IP": true, "NOTIFY_OK": true, "NOTIFY_UPGRADE": true, "DEDUP_MODE": true,
		"DEDUP_INTERVAL_DAYS": true, "NOTIFY_LANG": true, "BACKEND": true, "CHECK_UPDATE_HEALTH": true,
		"STALE_UPDATE_DAYS": true, "CHECK_EOL": true, "PENDING_ALERT_DAYS": true,
		"RESTART_ALERT_DAYS": true, "CHECK_SELF_UPDATE": true, "SELF_UPDATE_CHECK_DAYS": true,
	}
	if configKey[key] {
		parsed.config[key] = value
		return nil
	}
	switch key {
	case "CHECK_TIME":
		parsed.checkTime = value
	case "FEISHU_APP_SECRET_FILE":
		parsed.feishuSecretFile = value
	case "UI_LANG":
		parsed.lang = value
	case "SEND_TEST", "SKIP_TELEGRAM_TEST", "SKIP_FEISHU_TEST", "NON_INTERACTIVE", "ASSUME_YES", "ALLOW_BEST_EFFORT", "POST_INSTALL_CHECK":
		boolean, err := envBool(value)
		if err != nil {
			return fmt.Errorf("invalid boolean for %s", key)
		}
		switch key {
		case "SEND_TEST":
			parsed.sendTest = boolean
		case "SKIP_TELEGRAM_TEST":
			parsed.skipTelegram = boolean
		case "SKIP_FEISHU_TEST":
			parsed.skipFeishu = boolean
		case "NON_INTERACTIVE":
			parsed.nonInteractive = boolean
		case "ASSUME_YES":
			parsed.assumeYes = boolean
		case "ALLOW_BEST_EFFORT":
			parsed.allowBestEffort = boolean
		case "POST_INSTALL_CHECK":
			parsed.skipPostInstallCheck = !boolean
		}
	default:
		return fmt.Errorf("unsupported env key: %s", key)
	}
	return nil
}

func envBool(value string) (bool, error) {
	switch strings.ToLower(value) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	default:
		return false, errors.New("invalid boolean")
	}
}

var _ telegramPreflight = (*telegram.Client)(nil)
var _ feishuPreflight = (*feishu.Client)(nil)

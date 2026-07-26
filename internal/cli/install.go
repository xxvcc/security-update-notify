package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/feishu"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/installer"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

type installerAPI interface {
	Install(context.Context, installer.Options) (installer.Result, error)
	ReadTelegramTokenFile(string) (string, error)
	ReadFeishuSecretFile(string) ([]byte, error)
}

type telegramPreflight interface {
	GetMe(context.Context, string) error
	SendMessage(context.Context, string, string, string) error
}

type feishuPreflight interface {
	Probe(context.Context, string, string) error
	ScanDirectory(context.Context, string, string) ([]feishu.DirectoryUser, error)
	SendText(context.Context, string, string, string, string) error
}

type installConsole struct {
	in         *bufio.Reader
	out        io.Writer
	errOut     io.Writer
	readSecret func(string) (string, error)
}

type installCommand struct {
	console      installConsole
	newInstaller func() (installerAPI, error)
	readRuntime  func() ([]byte, error)
	loadConfig   func(string) (*config.Config, error)
	effectiveUID func() int
	telegram     telegramPreflight
	feishu       feishuPreflight
	hostname     func() (string, error)
}

type installArguments struct {
	config               map[string]string
	checkTime            string
	telegramTokenFile    string
	feishuSecretFile     string
	feishuSecret         []byte
	lang                 string
	nonInteractive       bool
	assumeYes            bool
	allowBestEffort      bool
	sendTest             bool
	skipTelegram         bool
	skipFeishu           bool
	verifyFeishu         bool
	skipPostInstallCheck bool
	lockWait             time.Duration
	lockWaitSet          bool
	configure            bool
	help                 bool
}

type localizedInputError struct {
	message string
	cause   error
}

func (e *localizedInputError) Error() string { return e.message }
func (e *localizedInputError) Unwrap() error { return e.cause }

func defaultInstallCommand() *installCommand {
	reader := bufio.NewReader(os.Stdin)
	return &installCommand{
		console: installConsole{
			in: reader, out: os.Stdout, errOut: os.Stderr,
			readSecret: func(prompt string) (string, error) {
				return readHiddenLine(os.Stdin, reader, os.Stdout, prompt)
			},
		},
		newInstaller: func() (installerAPI, error) { return installer.New(installer.Dependencies{}) },
		readRuntime:  currentExecutable,
		loadConfig:   config.Load,
		effectiveUID: os.Geteuid,
		telegram:     &telegram.Client{HTTP: httpx.New(20 * time.Second)},
		feishu:       &feishu.Client{HTTP: httpx.New(30 * time.Second)},
		hostname:     os.Hostname,
	}
}

func installMode(_ string, args []string) int {
	return defaultInstallCommand().run(args, false)
}

func configureMode(_ string, args []string) int {
	if len(args) == 0 || args[0] != "notifications" {
		fmt.Fprintln(os.Stderr, "Usage: security-update-notify configure notifications [install options]")
		return 2
	}
	return defaultInstallCommand().run(args[1:], true)
}

func (c *installCommand) run(rawArgs []string, configure bool) int {
	parsed, err := c.parse(rawArgs)
	if err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return 2
	}
	if parsed.help {
		c.printUsage(configure, parsed.lang)
		return 0
	}
	if parsed.configure {
		configure = true
	}
	if c.effectiveUID() != 0 {
		c.say(c.console.errOut, parsed.lang, "请以 root 运行。", "Please run as root.")
		return 1
	}
	defer func() { zeroCLIBytes(parsed.feishuSecret) }()
	parsed.lang, err = c.chooseLanguage(parsed.lang, parsed.nonInteractive)
	if err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return 2
	}

	current, err := c.loadConfig(defaultEnvFile)
	if err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return 2
	}
	existing := current.Has("CONFIG_VERSION") || current.Has("NOTIFY_CHANNELS")
	if configure && !existing {
		c.say(c.console.errOut, parsed.lang, "尚未检测到已有安装。", "No existing installation was detected.")
		return 2
	}
	if configure && parsed.nonInteractive && len(parsed.config) == 0 && parsed.checkTime == "" && parsed.telegramTokenFile == "" && parsed.feishuSecretFile == "" {
		c.say(c.console.errOut, parsed.lang, "非交互配置没有提供任何修改。", "No non-interactive configuration changes were supplied.")
		return 2
	}

	api, err := c.newInstaller()
	if err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return 1
	}
	if parsed.telegramTokenFile != "" {
		token, readErr := api.ReadTelegramTokenFile(parsed.telegramTokenFile)
		if readErr != nil {
			fmt.Fprintln(c.console.errOut, readErr)
			return installer.ExitCode(readErr)
		}
		parsed.config["TELEGRAM_BOT_TOKEN"] = token
	}
	if parsed.feishuSecretFile != "" {
		secret, readErr := api.ReadFeishuSecretFile(parsed.feishuSecretFile)
		if readErr != nil {
			fmt.Fprintln(c.console.errOut, readErr)
			return installer.ExitCode(readErr)
		}
		parsed.feishuSecret = secret
	}

	original := current.Map()
	effective := cloneCLIConfig(original)
	for key, value := range parsed.config {
		effective[key] = value
	}
	changedBeforeWizard := len(parsed.config) > 0 || parsed.checkTime != "" || len(parsed.feishuSecret) > 0
	if configure && !parsed.nonInteractive {
		changed, wizardErr := c.configureWizard(&parsed, effective)
		if wizardErr != nil {
			fmt.Fprintln(c.console.errOut, wizardErr)
			return 2
		}
		if !changed && !changedBeforeWizard {
			c.say(c.console.out, parsed.lang, "消息通知设置未修改。", "Message notification settings were not changed.")
			return 0
		}
		for key, value := range parsed.config {
			effective[key] = value
		}
	}
	if err := c.completeRequiredInputs(&parsed, effective, original, existing); err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return installer.ExitCode(err)
	}
	if err := c.completeInstallPreferences(&parsed, effective, original, existing); err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return installer.ExitCode(err)
	}

	runtime, err := c.readRuntime()
	if err != nil {
		fmt.Fprintln(c.console.errOut, "read runtime:", err)
		return 1
	}
	preflight := c.makePreflight(&parsed, effective, original, existing)
	result, err := api.Install(context.Background(), installer.Options{
		Config: parsed.config, CheckTime: parsed.checkTime, AllowBestEffort: parsed.allowBestEffort,
		Payload: installer.Payload{Runtime: runtime}, FeishuSecret: parsed.feishuSecret,
		Preflight: preflight, ConfirmDependencies: c.confirmDependencies(&parsed),
		SendTest: parsed.sendTest, SkipPostInstallCheck: parsed.skipPostInstallCheck,
		LockWait: parsed.lockWait, LockWaitSet: parsed.lockWaitSet,
	})
	if err != nil {
		fmt.Fprintln(c.console.errOut, err)
		return installer.ExitCode(err)
	}
	actionZH, actionEN := "已安装 security-update-notify。", "Installed security-update-notify."
	if result.Upgrade {
		actionZH, actionEN = "已升级 security-update-notify。", "Upgraded security-update-notify."
	}
	c.say(c.console.out, parsed.lang, actionZH, actionEN)
	c.say(c.console.out, parsed.lang, "配置文件: "+defaultEnvFile, "Config: "+defaultEnvFile)
	if result.BackupDir != "" {
		c.say(c.console.out, parsed.lang, "事务备份: "+result.BackupDir, "Transaction backup: "+result.BackupDir)
	}
	c.reportPostInstallTest(parsed.lang, result.PostInstallTest)
	c.reportPostInstallDoctor(parsed.lang, result.PostInstallDoctor)
	return 0
}

func (c *installCommand) reportPostInstallTest(lang string, result *installer.CommandResult) {
	if result == nil {
		return
	}
	writeCommandOutput(c.console.out, result.Stdout)
	writeCommandOutput(c.console.errOut, result.Stderr)
	if result.Err == nil && result.Code == 0 {
		return
	}
	if result.Err != nil {
		fmt.Fprintf(c.console.errOut, "%s: %v\n",
			c.pick(lang, "额外测试消息无法完成", "Additional test message could not complete"), result.Err)
	}
	c.say(c.console.errOut, lang,
		"警告：安装已完成，但额外测试消息发送失败；核心安装和定时任务未回滚，请检查接收平台配置与网络后重试测试。",
		"Warning: installation completed, but the additional test message failed; the core installation and timer were not rolled back. Check the receiving-platform settings and network, then retry the test.")
}

func (c *installCommand) reportPostInstallDoctor(lang string, result *installer.CommandResult) {
	if result == nil {
		return
	}
	writeCommandOutput(c.console.out, result.Stdout)
	writeCommandOutput(c.console.errOut, result.Stderr)
	if result.Err == nil && result.Code == 0 {
		return
	}
	if result.Err != nil {
		fmt.Fprintf(c.console.errOut, "%s: %v\n",
			c.pick(lang, "装后自检无法完成", "Post-install self-check could not complete"), result.Err)
	}
	c.say(c.console.errOut, lang,
		"警告：安装已完成，但装后自检未完全通过；安装本身完好，请查看上方诊断输出并处理报告的问题。",
		"Warning: installation completed, but the post-install self-check did not fully pass; the installation itself is intact. Review the diagnostics above and address the reported issue.")
}

func writeCommandOutput(out io.Writer, value []byte) {
	if len(value) == 0 {
		return
	}
	_, _ = out.Write(value)
	if value[len(value)-1] != '\n' {
		_, _ = io.WriteString(out, "\n")
	}
}

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

func (c *installCommand) completeRequiredInputs(parsed *installArguments, effective, original map[string]string, existing bool) error {
	channels := effective["NOTIFY_CHANNELS"]
	if channels == "" {
		if parsed.nonInteractive {
			channels = "telegram"
		} else {
			chosen, err := c.promptChannels(parsed.lang, "telegram")
			if err != nil {
				return invalidCLI(err)
			}
			channels = chosen
		}
		parsed.config["NOTIFY_CHANNELS"] = channels
		effective["NOTIFY_CHANNELS"] = channels
	}
	normalized, err := normalizeCLIChannels(channels)
	if err != nil {
		return invalidCLI(err)
	}
	parsed.config["NOTIFY_CHANNELS"] = normalized
	effective["NOTIFY_CHANNELS"] = normalized
	if selectedCLIChannel(normalized, "telegram") {
		if effective["TELEGRAM_BOT_TOKEN"] == "" {
			if parsed.nonInteractive {
				return invalidCLI(errors.New("missing Telegram Bot Token"))
			}
			value, promptErr := c.promptSecret(parsed.lang, "Telegram Bot Token")
			if promptErr != nil {
				return invalidCLI(promptErr)
			}
			parsed.config["TELEGRAM_BOT_TOKEN"], effective["TELEGRAM_BOT_TOKEN"] = value, value
		}
		if effective["TELEGRAM_CHAT_ID"] == "" {
			if parsed.nonInteractive {
				return invalidCLI(errors.New("missing Telegram Chat ID"))
			}
			value, promptErr := c.promptRequired(parsed.lang, "Telegram Chat ID")
			if promptErr != nil {
				return invalidCLI(promptErr)
			}
			parsed.config["TELEGRAM_CHAT_ID"], effective["TELEGRAM_CHAT_ID"] = value, value
		}
	}
	if selectedCLIChannel(normalized, "feishu") {
		if effective["FEISHU_APP_ID"] == "" {
			if parsed.nonInteractive {
				return invalidCLI(errors.New("missing Feishu App ID"))
			}
			value, promptErr := c.promptRequired(parsed.lang, "飞书 App ID / Feishu App ID")
			if promptErr != nil {
				return invalidCLI(promptErr)
			}
			parsed.config["FEISHU_APP_ID"], effective["FEISHU_APP_ID"] = value, value
		}
		oldApp := original["FEISHU_APP_ID"]
		appChanged := existing && effective["FEISHU_APP_ID"] != oldApp
		if appChanged {
			if _, explicitlyReplaced := parsed.config["FEISHU_RECEIVE_ID"]; !explicitlyReplaced {
				parsed.config["FEISHU_RECEIVE_ID"] = ""
				effective["FEISHU_RECEIVE_ID"] = ""
			}
		}
		needsSecret := len(parsed.feishuSecret) == 0 && (!existing || oldApp == "" || appChanged)
		if needsSecret {
			if parsed.nonInteractive {
				return invalidCLI(errors.New("missing Feishu App Secret"))
			}
			value, promptErr := c.promptSecret(parsed.lang, "飞书 App Secret / Feishu App Secret")
			if promptErr != nil {
				return invalidCLI(promptErr)
			}
			parsed.feishuSecret = []byte(value)
		}
		if effective["FEISHU_RECEIVE_ID"] == "" && parsed.nonInteractive {
			return invalidCLI(errors.New("non-interactive Feishu installation requires --feishu-receive-id"))
		}
	}
	if effective["NOTIFY_LANG"] == "" {
		parsed.config["NOTIFY_LANG"], effective["NOTIFY_LANG"] = parsed.lang, parsed.lang
	}
	return nil
}

func (c *installCommand) configureWizard(parsed *installArguments, effective map[string]string) (bool, error) {
	changed := false
	currentChannels, err := normalizeCLIChannels(effective["NOTIFY_CHANNELS"])
	if err != nil {
		return false, err
	}
	c.say(c.console.out, parsed.lang, "当前通知方式: "+currentChannels, "Current notification method: "+currentChannels)
	if _, explicit := parsed.config["NOTIFY_CHANNELS"]; !explicit {
		answer, readErr := c.promptYesNo(parsed.lang, "更改接收平台？[y/N]: ", "Change receiving platforms? [y/N]: ", false)
		if readErr != nil {
			return false, readErr
		}
		if answer {
			channels, chooseErr := c.promptChannels(parsed.lang, currentChannels)
			if chooseErr != nil {
				return false, chooseErr
			}
			parsed.config["NOTIFY_CHANNELS"], effective["NOTIFY_CHANNELS"] = channels, channels
			currentChannels, changed = channels, true
		}
	} else {
		currentChannels, changed = parsed.config["NOTIFY_CHANNELS"], true
	}
	_, telegramTokenExplicit := parsed.config["TELEGRAM_BOT_TOKEN"]
	_, telegramChatExplicit := parsed.config["TELEGRAM_CHAT_ID"]
	if selectedCLIChannel(currentChannels, "telegram") && !telegramTokenExplicit && !telegramChatExplicit && parsed.telegramTokenFile == "" {
		change, readErr := c.promptYesNo(parsed.lang, "修改 Telegram 配置？[y/N]: ", "Change Telegram settings? [y/N]: ", false)
		if readErr != nil {
			return false, readErr
		}
		if change {
			token, secretErr := c.promptSecret(parsed.lang, "Telegram Bot Token")
			if secretErr != nil {
				return false, secretErr
			}
			chat, textErr := c.promptRequired(parsed.lang, "Telegram Chat ID")
			if textErr != nil {
				return false, textErr
			}
			parsed.config["TELEGRAM_BOT_TOKEN"], parsed.config["TELEGRAM_CHAT_ID"] = token, chat
			effective["TELEGRAM_BOT_TOKEN"], effective["TELEGRAM_CHAT_ID"] = token, chat
			changed = true
		}
	}
	_, feishuAppExplicit := parsed.config["FEISHU_APP_ID"]
	_, feishuReceiverExplicit := parsed.config["FEISHU_RECEIVE_ID"]
	if selectedCLIChannel(currentChannels, "feishu") && !feishuAppExplicit && !feishuReceiverExplicit && parsed.feishuSecretFile == "" && len(parsed.feishuSecret) == 0 {
		choice, readErr := c.promptFeishuSettings(parsed.lang)
		if readErr != nil {
			return false, readErr
		}
		switch choice {
		case "", "1":
		case "2":
			parsed.config["FEISHU_RECEIVE_ID"], effective["FEISHU_RECEIVE_ID"] = "", ""
			changed = true
		case "3":
			appID, textErr := c.promptRequired(parsed.lang, "飞书 App ID / Feishu App ID")
			if textErr != nil {
				return false, textErr
			}
			secret, secretErr := c.promptSecret(parsed.lang, "飞书 App Secret / Feishu App Secret")
			if secretErr != nil {
				return false, secretErr
			}
			parsed.config["FEISHU_APP_ID"], effective["FEISHU_APP_ID"] = appID, appID
			parsed.config["FEISHU_RECEIVE_ID"], effective["FEISHU_RECEIVE_ID"] = "", ""
			parsed.feishuSecret, changed = []byte(secret), true
		case "4":
			secret, secretErr := c.promptSecret(parsed.lang, "飞书 App Secret / Feishu App Secret")
			if secretErr != nil {
				return false, secretErr
			}
			parsed.feishuSecret, changed = []byte(secret), true
		}
	}
	return changed, nil
}

func (c *installCommand) completeInstallPreferences(parsed *installArguments, effective, original map[string]string, existing bool) error {
	if parsed.checkTime == "" && !existing {
		if parsed.nonInteractive {
			parsed.checkTime = "09:00"
		} else {
			value, err := c.promptCheckTime(parsed.lang, "09:00")
			if err != nil {
				return invalidCLI(err)
			}
			parsed.checkTime = value
		}
	}

	mode := effective["DEDUP_MODE"]
	if mode == "" {
		if parsed.nonInteractive {
			mode = "daily"
		} else {
			choice, err := c.promptDedupMode(parsed.lang)
			if err != nil {
				return invalidCLI(err)
			}
			switch choice {
			case "1":
				mode = "once"
			case "", "2":
				mode = "daily"
			case "3":
				mode = "interval"
			}
		}
		parsed.config["DEDUP_MODE"], effective["DEDUP_MODE"] = mode, mode
	}
	if mode == "always" {
		mode = "once"
		parsed.config["DEDUP_MODE"], effective["DEDUP_MODE"] = mode, mode
	}
	if mode == "interval" && effective["DEDUP_INTERVAL_DAYS"] == "" {
		days := "3"
		if !parsed.nonInteractive {
			value, err := c.promptPositiveInteger(parsed.lang,
				"同一告警每 N 天重复提醒", "Repeat the same alert every N days", days)
			if err != nil {
				return invalidCLI(err)
			}
			days = value
		}
		parsed.config["DEDUP_INTERVAL_DAYS"], effective["DEDUP_INTERVAL_DAYS"] = days, days
	}

	channels, _ := normalizeCLIChannels(effective["NOTIFY_CHANNELS"])
	originalChannels := ""
	if existing {
		originalChannels = original["NOTIFY_CHANNELS"]
		if originalChannels == "" {
			originalChannels = "telegram"
		}
		originalChannels, _ = normalizeCLIChannels(originalChannels)
	}
	_, appChanged := parsed.config["FEISHU_APP_ID"]
	_, receiverChanged := parsed.config["FEISHU_RECEIVE_ID"]
	feishuNeedsDeliveryTest := !parsed.skipFeishu && selectedCLIChannel(channels, "feishu") &&
		(!existing || !selectedCLIChannel(originalChannels, "feishu") || appChanged || receiverChanged || len(parsed.feishuSecret) > 0 || effective["FEISHU_RECEIVE_ID"] == "")
	if parsed.sendTest {
		// An explicit all-platform test does not weaken the transaction-scoped
		// validation required for a new or changed Feishu recipient.
		parsed.verifyFeishu = feishuNeedsDeliveryTest
		return nil
	}
	if parsed.nonInteractive {
		parsed.verifyFeishu = feishuNeedsDeliveryTest
		return nil
	}
	if parsed.skipTelegram && parsed.skipFeishu {
		return nil
	}
	var approved bool
	var err error
	if feishuNeedsDeliveryTest {
		approved, err = c.promptYesNo(parsed.lang,
			"安装后发送测试消息，确认飞书接收人可用？[Y/n]: ",
			"Send a post-install test message to verify the Feishu recipient? [Y/n]: ", true)
	} else {
		approved, err = c.promptYesNo(parsed.lang,
			"安装后向已配置接收平台额外发送测试消息？[y/N]: ",
			"Send an additional post-install test message to configured receiving platforms? [y/N]: ", false)
	}
	if err != nil {
		return invalidCLI(err)
	}
	if feishuNeedsDeliveryTest {
		parsed.verifyFeishu = approved
	} else {
		parsed.sendTest = approved
	}
	return nil
}

func (c *installCommand) makePreflight(parsed *installArguments, effective, original map[string]string, existing bool) installer.PreflightFunc {
	channels, _ := normalizeCLIChannels(effective["NOTIFY_CHANNELS"])
	originalChannels := ""
	if existing {
		originalChannels = original["NOTIFY_CHANNELS"]
		if originalChannels == "" {
			originalChannels = "telegram"
		}
		originalChannels, _ = normalizeCLIChannels(originalChannels)
	}
	_, telegramTokenChanged := parsed.config["TELEGRAM_BOT_TOKEN"]
	_, telegramChatChanged := parsed.config["TELEGRAM_CHAT_ID"]
	telegramChanged := selectedCLIChannel(channels, "telegram") &&
		(!existing || !selectedCLIChannel(originalChannels, "telegram") || telegramTokenChanged || telegramChatChanged)
	_, feishuAppChanged := parsed.config["FEISHU_APP_ID"]
	_, feishuReceiverChanged := parsed.config["FEISHU_RECEIVE_ID"]
	feishuChanged := selectedCLIChannel(channels, "feishu") &&
		(!existing || !selectedCLIChannel(originalChannels, "feishu") || feishuAppChanged || feishuReceiverChanged || len(parsed.feishuSecret) > 0)
	needsDirectory := selectedCLIChannel(channels, "feishu") && effective["FEISHU_RECEIVE_ID"] == ""
	if (!telegramChanged || parsed.skipTelegram) && (!feishuChanged || parsed.skipFeishu) && !needsDirectory && !parsed.verifyFeishu {
		return nil
	}
	return func(ctx context.Context, prepared *installer.Prepared) error {
		if telegramChanged && selectedCLIChannel(prepared.Config["NOTIFY_CHANNELS"], "telegram") && !parsed.skipTelegram {
			if err := c.telegramPreflight(ctx, parsed, prepared); err != nil {
				return err
			}
		}
		if selectedCLIChannel(prepared.Config["NOTIFY_CHANNELS"], "feishu") &&
			((feishuChanged && !parsed.skipFeishu) || prepared.Config["FEISHU_RECEIVE_ID"] == "" || parsed.verifyFeishu) {
			if err := c.feishuPreflight(ctx, parsed, prepared); err != nil {
				return err
			}
		}
		return nil
	}
}

func (c *installCommand) confirmDependencies(parsed *installArguments) installer.ConfirmDependenciesFunc {
	return func(ctx context.Context, request installer.DependencyRequest) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if parsed.assumeYes || parsed.nonInteractive {
			c.say(c.console.out, parsed.lang,
				"正在安装依赖软件包: "+strings.Join(request.Packages, " "),
				"Installing dependency packages: "+strings.Join(request.Packages, " "))
			return true, nil
		}
		packages := strings.Join(request.Packages, " ")
		c.say(c.console.out, parsed.lang,
			"缺少依赖软件包: "+packages,
			"Missing dependency packages: "+packages)
		approved, err := c.promptYesNo(parsed.lang,
			"现在安装这些软件包？[Y/n]: ",
			"Install these packages now? [Y/n]: ", true)
		if err != nil || !approved {
			return approved, err
		}
		c.say(c.console.out, parsed.lang,
			"正在安装依赖软件包: "+packages,
			"Installing dependency packages: "+packages)
		return true, nil
	}
}

func (c *installCommand) telegramPreflight(parent context.Context, parsed *installArguments, prepared *installer.Prepared) error {
	for {
		ctx, cancel := context.WithTimeout(parent, 25*time.Second)
		err := c.telegram.GetMe(ctx, prepared.Config["TELEGRAM_BOT_TOKEN"])
		cancel()
		if err == nil {
			host, _ := c.hostname()
			text := c.pick(parsed.lang, "security-update-notify Telegram 测试成功。主机: "+host, "security-update-notify Telegram test succeeded. Host: "+host)
			ctx, cancel = context.WithTimeout(parent, 25*time.Second)
			err = c.telegram.SendMessage(ctx, prepared.Config["TELEGRAM_BOT_TOKEN"], prepared.Config["TELEGRAM_CHAT_ID"], text)
			cancel()
		}
		if err == nil {
			c.say(c.console.out, parsed.lang, "Telegram 测试消息已发送。", "Telegram test message sent.")
			return nil
		}
		fmt.Fprintln(c.console.errOut, "Telegram preflight:", err)
		if telegram.IsTemporary(err) {
			if parsed.nonInteractive {
				return &installer.ExitError{Code: 75, Op: "Telegram preflight", Err: err}
			}
			c.say(c.console.errOut, parsed.lang,
				"Telegram 网络预检暂时失败；这不表示 Bot Token 或 Chat ID 无效。",
				"Telegram network preflight temporarily failed; this does not mean the Bot Token or Chat ID is invalid.")
			choice, readErr := c.promptTemporaryFailureChoice(parsed.lang)
			if readErr != nil {
				return invalidCLI(readErr)
			}
			switch choice {
			case "", "1":
				continue
			case "2":
				c.say(c.console.out, parsed.lang,
					"已跳过本次 Telegram 预检；保留当前输入，但尚未验证。",
					"Skipped this Telegram preflight; the current input was kept but remains unverified.")
				return nil
			case "3":
				return &installer.ExitError{Code: 75, Op: "Telegram preflight", Err: err}
			}
		}
		if parsed.nonInteractive {
			return &installer.ExitError{Code: 2, Op: "Telegram preflight", Err: err}
		}
		retry, promptErr := c.promptYesNo(parsed.lang, "重新输入 Telegram token 和 chat ID？[Y/n]: ", "Re-enter Telegram token and chat ID? [Y/n]: ", true)
		if promptErr != nil {
			return invalidCLI(promptErr)
		}
		if !retry {
			return &installer.ExitError{Code: 2, Op: "Telegram preflight", Err: err}
		}
		token, secretErr := c.promptSecret(parsed.lang, "Telegram Bot Token")
		if secretErr != nil {
			return invalidCLI(secretErr)
		}
		chat, textErr := c.promptRequired(parsed.lang, "Telegram Chat ID")
		if textErr != nil {
			return invalidCLI(textErr)
		}
		prepared.Config["TELEGRAM_BOT_TOKEN"], prepared.Config["TELEGRAM_CHAT_ID"] = token, chat
	}
}

func (c *installCommand) feishuPreflight(parent context.Context, parsed *installArguments, prepared *installer.Prepared) error {
	for {
		appID, secret := prepared.Config["FEISHU_APP_ID"], string(prepared.FeishuSecret)
		if prepared.Config["FEISHU_RECEIVE_ID"] == "" {
			ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
			users, err := c.feishu.ScanDirectory(ctx, appID, secret)
			cancel()
			if err == nil && len(users) > 0 {
				selected, selectErr := c.selectFeishuUser(parsed, users)
				if selectErr != nil {
					return invalidCLI(selectErr)
				}
				prepared.Config["FEISHU_RECEIVE_ID"] = selected
				continue
			}
			if err == nil {
				err = errors.New("no visible active Feishu users")
			}
			fmt.Fprintln(c.console.errOut, "Feishu directory scan:", err)
			if parsed.nonInteractive {
				code := 2
				if feishu.IsTemporary(err) {
					code = 75
				}
				return &installer.ExitError{Code: code, Op: "Feishu directory scan", Err: err}
			}
			if feishu.IsTemporary(err) {
				c.say(c.console.errOut, parsed.lang,
					"飞书通讯录网络扫描暂时失败；这不表示权限或凭据无效。",
					"The Feishu directory scan is temporarily unavailable; this does not mean permissions or credentials are invalid.")
			}
			choice, readErr := c.promptDirectoryFailureChoice(parsed.lang)
			if readErr != nil {
				return invalidCLI(readErr)
			}
			switch choice {
			case "1":
				continue
			case "", "2":
				openID, inputErr := c.promptRequired(parsed.lang, "飞书 open_id / Feishu open_id")
				if inputErr != nil {
					return invalidCLI(inputErr)
				}
				prepared.Config["FEISHU_RECEIVE_ID"] = openID
				if parsed.skipFeishu && !parsed.verifyFeishu {
					return nil
				}
				continue
			case "3":
				code := 2
				if feishu.IsTemporary(err) {
					code = 75
				}
				return &installer.ExitError{Code: code, Op: "Feishu directory scan", Err: err}
			}
		}
		if parsed.skipFeishu && !parsed.verifyFeishu {
			return nil
		}
		if !parsed.skipFeishu {
			ctx, cancel := context.WithTimeout(parent, 25*time.Second)
			err := c.feishu.Probe(ctx, appID, secret)
			cancel()
			if err != nil {
				fmt.Fprintln(c.console.errOut, "Feishu preflight:", err)
				if feishu.IsTemporary(err) {
					if parsed.nonInteractive {
						return &installer.ExitError{Code: 75, Op: "Feishu preflight", Err: err}
					}
					c.say(c.console.errOut, parsed.lang,
						"飞书网络预检暂时失败；这不表示 App ID、Secret 或接收人无效。",
						"The Feishu network preflight temporarily failed; this does not mean the App ID, secret, or recipient is invalid.")
					choice, readErr := c.promptTemporaryFailureChoice(parsed.lang)
					if readErr != nil {
						return invalidCLI(readErr)
					}
					switch choice {
					case "", "1":
						continue
					case "2":
						c.say(c.console.out, parsed.lang,
							"已跳过本次飞书预检；保留当前输入，但尚未验证。",
							"Skipped this Feishu preflight; the current input was kept but remains unverified.")
						return nil
					case "3":
						return &installer.ExitError{Code: 75, Op: "Feishu preflight", Err: err}
					}
				}
				if parsed.nonInteractive {
					return &installer.ExitError{Code: 2, Op: "Feishu preflight", Err: err}
				}
				retry, promptErr := c.promptYesNo(parsed.lang, "重新输入飞书凭据？[Y/n]: ", "Re-enter Feishu credentials? [Y/n]: ", true)
				if promptErr != nil {
					return invalidCLI(promptErr)
				}
				if !retry {
					return &installer.ExitError{Code: 2, Op: "Feishu preflight", Err: err}
				}
				newApp, inputErr := c.promptRequired(parsed.lang, "飞书 App ID / Feishu App ID")
				if inputErr != nil {
					return invalidCLI(inputErr)
				}
				newSecret, secretErr := c.promptSecret(parsed.lang, "飞书 App Secret / Feishu App Secret")
				if secretErr != nil {
					return invalidCLI(secretErr)
				}
				if newApp != appID {
					prepared.Config["FEISHU_RECEIVE_ID"] = ""
				}
				zeroCLIBytes(prepared.FeishuSecret)
				prepared.Config["FEISHU_APP_ID"], prepared.FeishuSecret = newApp, []byte(newSecret)
				continue
			}
		}
		if !parsed.verifyFeishu {
			return nil
		}
		host, _ := c.hostname()
		message := c.pick(parsed.lang,
			"security-update-notify 飞书测试成功。主机: "+host,
			"security-update-notify Feishu test succeeded. Host: "+host)
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		err := c.feishu.SendText(ctx, appID, secret, prepared.Config["FEISHU_RECEIVE_ID"], message)
		cancel()
		if err != nil {
			code := 2
			if feishu.IsTemporary(err) {
				code = 75
			}
			return &installer.ExitError{Code: code, Op: "Feishu recipient delivery test", Err: err}
		}
		c.say(c.console.out, parsed.lang, "飞书接收人测试消息已发送。", "Feishu recipient test message sent.")
		return nil
	}
}

func (c *installCommand) selectFeishuUser(parsed *installArguments, users []feishu.DirectoryUser) (string, error) {
	for index, user := range users {
		hint := user.Name
		if user.MobileTail != "" {
			hint += " ****" + user.MobileTail
		}
		fmt.Fprintf(c.console.out, "%d) %s (%s)\n", index+1, hint, user.OpenID)
	}
	for {
		fmt.Fprint(c.console.out, c.pick(parsed.lang, "请选择飞书接收人编号: ", "Choose Feishu recipient number: "))
		line, err := c.readPromptLine(parsed.lang)
		if err != nil {
			return "", err
		}
		choice, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && choice >= 1 && choice <= len(users) {
			return users[choice-1].OpenID, nil
		}
		fmt.Fprintln(c.console.errOut, c.pick(parsed.lang, "无效编号。", "Invalid number."))
	}
}

func (c *installCommand) promptChannels(lang, current string) (string, error) {
	defaultChoice := "1"
	switch current {
	case "feishu":
		defaultChoice = "2"
	case "telegram,feishu":
		defaultChoice = "3"
	}
	choice, err := c.promptMenuChoice(lang,
		"接收平台: 1) Telegram  2) 飞书  3) Telegram + 飞书 ["+defaultChoice+"]: ",
		"Receiving platforms: 1) Telegram  2) Feishu  3) Telegram + Feishu ["+defaultChoice+"]: ",
		defaultChoice, "1", "2", "3")
	if err != nil {
		return "", err
	}
	switch choice {
	case "1":
		return "telegram", nil
	case "2":
		return "feishu", nil
	case "3":
		return "telegram,feishu", nil
	}
	return "", nil
}

func (c *installCommand) chooseLanguage(lang string, nonInteractive bool) (string, error) {
	if lang == "zh" || lang == "en" {
		return lang, nil
	}
	if env := os.Getenv("UI_LANG"); env == "zh" || env == "en" {
		return env, nil
	}
	if env := os.Getenv("SUN_LANG"); env == "zh" || env == "en" {
		return env, nil
	}
	if nonInteractive {
		return "zh", nil
	}
	choice, err := c.promptMenuChoice("",
		"请选择语言 / Choose a language: 1) 中文  2) English [1]:",
		"请选择语言 / Choose a language: 1) 中文  2) English [1]:",
		"1", "1", "2")
	if err != nil {
		return "zh", err
	}
	if choice == "2" {
		return "en", nil
	}
	return "zh", nil
}

func (c *installCommand) promptSecret(lang, label string) (string, error) {
	for {
		value, err := c.console.readSecret(c.pick(lang, label+"（输入隐藏）: ", label+" (input hidden): "))
		trimmed := strings.TrimRight(value, "\r\n")
		if err != nil && !(errors.Is(err, io.EOF) && trimmed != "") {
			return "", c.localizedInputError(lang, err)
		}
		if trimmed != "" {
			return trimmed, nil
		}
		c.say(c.console.errOut, lang, "输入不能为空，请重新输入。", "Input cannot be empty; try again.")
	}
}

func (c *installCommand) promptRequired(lang, label string) (string, error) {
	for {
		fmt.Fprint(c.console.out, c.pick(lang, label+": ", label+": "))
		line, err := c.readPromptLine(lang)
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line != "" {
			return line, nil
		}
		c.say(c.console.errOut, lang, "输入不能为空，请重新输入。", "Input cannot be empty; try again.")
	}
}

func (c *installCommand) promptDefault(lang, zhLabel, enLabel, defaultValue string) (string, error) {
	fmt.Fprintf(c.console.out, "%s [%s]: ", c.pick(lang, zhLabel, enLabel), defaultValue)
	line, err := c.readPromptLine(lang)
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func (c *installCommand) promptCheckTime(lang, defaultValue string) (string, error) {
	for {
		value, err := c.promptDefault(lang, "每日检查时间 HH:MM", "Daily check time HH:MM", defaultValue)
		if err != nil {
			return "", err
		}
		if validCLICheckTime(value) {
			return value, nil
		}
		c.say(c.console.errOut, lang,
			"时间无效，请使用 HH:MM（00:00 至 23:59）。",
			"Invalid time; use HH:MM (00:00 through 23:59).")
	}
}

func (c *installCommand) promptPositiveInteger(lang, zhLabel, enLabel, defaultValue string) (string, error) {
	for {
		value, err := c.promptDefault(lang, zhLabel, enLabel, defaultValue)
		if err != nil {
			return "", err
		}
		if positiveCLIInteger(value) {
			return value, nil
		}
		c.say(c.console.errOut, lang, "请输入大于 0 的整数。", "Enter an integer greater than 0.")
	}
}

func (c *installCommand) promptYesNo(lang, zh, en string, defaultYes bool) (bool, error) {
	for {
		fmt.Fprint(c.console.out, c.pick(lang, zh, en))
		line, err := c.readPromptLine(lang)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			c.say(c.console.errOut, lang, "无效输入，请输入 y 或 n。", "Invalid input; enter y or n.")
		}
	}
}

func (c *installCommand) promptFeishuSettings(lang string) (string, error) {
	return c.promptMenuChoice(lang,
		"飞书设置: 1) 保持  2) 更换接收人  3) 更换应用和接收人  4) 更新 App Secret [1]: ",
		"Feishu: 1) Keep  2) Change recipient  3) Change app and recipient  4) Update App Secret [1]: ",
		"1", "1", "2", "3", "4")
}

func (c *installCommand) promptDedupMode(lang string) (string, error) {
	c.say(c.console.out, lang, "相同告警重复提醒模式:", "Same-alert reminder mode:")
	return c.promptMenuChoice(lang,
		"1) 仅一次  2) 每天一次（推荐）  3) 每 N 天一次 [2]:",
		"1) Once  2) Daily (recommended)  3) Every N days [2]:",
		"2", "1", "2", "3")
}

func (c *installCommand) promptTemporaryFailureChoice(lang string) (string, error) {
	return c.promptMenuChoice(lang,
		"1) 重试连接  2) 跳过本次预检  3) 中止 [1]: ",
		"1) Retry connection  2) Skip this preflight  3) Abort [1]: ",
		"1", "1", "2", "3")
}

func (c *installCommand) promptDirectoryFailureChoice(lang string) (string, error) {
	return c.promptMenuChoice(lang,
		"1) 重试扫描  2) 手动输入 open_id  3) 中止 [2]: ",
		"1) Retry scan  2) Enter open_id manually  3) Abort [2]: ",
		"2", "1", "2", "3")
}

func (c *installCommand) promptMenuChoice(lang, zh, en, defaultChoice string, valid ...string) (string, error) {
	for {
		fmt.Fprintln(c.console.out, c.pick(lang, zh, en))
		line, err := c.readPromptLine(lang)
		if err != nil {
			return "", err
		}
		choice := strings.TrimSpace(line)
		if choice == "" {
			choice = defaultChoice
		}
		for _, candidate := range valid {
			if choice == candidate {
				return choice, nil
			}
		}
		c.say(c.console.errOut, lang, "无效选择，请重新输入。", "Invalid choice; try again.")
	}
}

func (c *installCommand) readPromptLine(lang string) (string, error) {
	line, err := c.readLine()
	if err != nil {
		return "", c.localizedInputError(lang, err)
	}
	return line, nil
}

func (c *installCommand) localizedInputError(lang string, err error) error {
	message := c.pick(lang, "读取输入失败。", "Unable to read input.")
	if errors.Is(err, io.EOF) {
		message = c.pick(lang, "已取消。", "Cancelled.")
	}
	return &localizedInputError{message: message, cause: err}
}

func (c *installCommand) readLine() (string, error) {
	line, err := c.console.in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", io.EOF
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *installCommand) say(out io.Writer, lang, zh, en string) {
	fmt.Fprintln(out, c.pick(lang, zh, en))
}

func (c *installCommand) pick(lang, zh, en string) string {
	if lang == "en" {
		return en
	}
	return zh
}

func (c *installCommand) printUsage(configure bool, lang string) {
	command := "install"
	if configure {
		command = "configure notifications"
	}
	fmt.Fprintf(c.console.out, `Usage: security-update-notify %s [options]

  --env-file FILE
  --notify-channels telegram|feishu|telegram,feishu
  --telegram-token-file FILE   --telegram-token TOKEN (discouraged)
  --telegram-chat-id CHAT_ID
  --feishu-app-id APP_ID       --feishu-app-secret-file FILE
  --feishu-receive-id OPEN_ID  --time HH:MM
  --host-label NAME            --public-ip IP
  --include-public-ip BOOL     --notify-ok BOOL
  --notify-upgrade BOOL        --dedup-mode once|daily|interval
  --dedup-interval-days N      --notify-lang zh|en
  --backend auto|apt|dnf       --allow-best-effort
  --lock-wait SECONDS          runtime-lock barrier, 0..3600 (default 60)
  --send-test                  --skip-notify-test
  --skip-telegram-test         --skip-feishu-test
  --skip-post-install-check    --lang zh|en
  --non-interactive            -y, --yes
`, command)
}

func normalizeCLIChannels(raw string) (string, error) {
	raw = strings.ToLower(strings.Join(strings.Fields(raw), ""))
	hasTelegram, hasFeishu := false, false
	for _, item := range strings.Split(raw, ",") {
		switch item {
		case "telegram":
			hasTelegram = true
		case "feishu":
			hasFeishu = true
		default:
			return "", fmt.Errorf("invalid receiving platform: %s", item)
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
	return "", errors.New("receiving platforms cannot be empty")
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

func currentExecutable() ([]byte, error) {
	// /proc/self/exe is pinned to the inode executing this process, even if the
	// pathname used to launch it is concurrently replaced during an upgrade.
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 256<<20 {
		return nil, errors.New("current executable is not a regular file within 256 MiB")
	}
	payload, err := io.ReadAll(io.LimitReader(file, 256<<20+1))
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || len(payload) > 256<<20 {
		return nil, errors.New("current executable is not a regular file within 256 MiB")
	}
	return payload, nil
}

func zeroCLIBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

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

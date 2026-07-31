package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/feishu"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/installer"
	"github.com/xxvcc/security-update-notify/internal/telegram"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
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
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
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
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
		return 2
	}

	current, err := c.loadConfig(defaultEnvFile)
	if err != nil {
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
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
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
		return 1
	}
	if parsed.telegramTokenFile != "" {
		token, readErr := api.ReadTelegramTokenFile(parsed.telegramTokenFile)
		if readErr != nil {
			fmt.Fprintln(c.console.errOut, safeCLIText(readErr.Error()))
			return installer.ExitCode(readErr)
		}
		parsed.config["TELEGRAM_BOT_TOKEN"] = token
	}
	if parsed.feishuSecretFile != "" {
		secret, readErr := api.ReadFeishuSecretFile(parsed.feishuSecretFile)
		if readErr != nil {
			fmt.Fprintln(c.console.errOut, safeCLIText(readErr.Error()))
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
			fmt.Fprintln(c.console.errOut, safeCLIText(wizardErr.Error()))
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
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
		return installer.ExitCode(err)
	}
	if err := c.completeInstallPreferences(&parsed, effective, original, existing); err != nil {
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
		return installer.ExitCode(err)
	}

	runtime, err := c.readRuntime()
	if err != nil {
		fmt.Fprintln(c.console.errOut, "read runtime:", safeCLIText(err.Error()))
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
		fmt.Fprintln(c.console.errOut, safeCLIText(err.Error()))
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
	if result.Err == nil && result.Code == 0 && !commandOutputTruncated(result) {
		return
	}
	if commandOutputTruncated(result) {
		c.say(c.console.errOut, lang,
			"额外测试消息的命令输出超过捕获上限，结果不完整。",
			"Additional test message command output exceeded the capture limit; the result is incomplete.")
	}
	if result.Err != nil {
		fmt.Fprintf(c.console.errOut, "%s: %s\n",
			c.pick(lang, "额外测试消息无法完成", "Additional test message could not complete"), safeCLIText(result.Err.Error()))
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
	if result.Err == nil && result.Code == 0 && !commandOutputTruncated(result) {
		return
	}
	if commandOutputTruncated(result) {
		c.say(c.console.errOut, lang,
			"装后自检的命令输出超过捕获上限，结果不完整。",
			"Post-install self-check command output exceeded the capture limit; the result is incomplete.")
	}
	if result.Err != nil {
		fmt.Fprintf(c.console.errOut, "%s: %s\n",
			c.pick(lang, "装后自检无法完成", "Post-install self-check could not complete"), safeCLIText(result.Err.Error()))
	}
	c.say(c.console.errOut, lang,
		"警告：安装已完成，但装后自检未完全通过；安装本身完好，请查看上方诊断输出并处理报告的问题。",
		"Warning: installation completed, but the post-install self-check did not fully pass; the installation itself is intact. Review the diagnostics above and address the reported issue.")
}

func commandOutputTruncated(result *installer.CommandResult) bool {
	return result.StdoutTruncated || result.StderrTruncated
}

func writeCommandOutput(out io.Writer, value []byte) {
	if len(value) == 0 {
		return
	}
	safe := textsafe.Multiline(string(value))
	_, _ = io.WriteString(out, safe)
	if safe == "" || safe[len(safe)-1] != '\n' {
		_, _ = io.WriteString(out, "\n")
	}
}

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

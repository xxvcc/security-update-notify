package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/run"
)

type menuCommand struct {
	version string
	lang    i18n.Lang
	reader  *bufio.Reader
	out     io.Writer
	errOut  io.Writer

	geteuid   func() int
	stdinTTY  func() bool
	stdoutTTY func() bool
	stderrTTY func() bool
	dispatch  func([]string) int
}

type menuActionResult struct {
	status     int
	dispatched bool
	exit       bool
	abort      bool
	redraw     bool
}

type menuPromptResult uint8

const (
	menuPromptCancelled menuPromptResult = iota
	menuPromptConfirmed
	menuPromptAborted
)

func menuModeWithSystemd(ver string, args []string, systemdQuery run.SystemdQuery) int {
	explicitLang, help, ok := parseMenuArgs(args)
	if !ok {
		return 2
	}
	if help {
		fmt.Fprintln(os.Stdout, "Usage: security-update-notify menu [--lang zh|en]")
		return 0
	}

	reader := bufio.NewReader(os.Stdin)
	lang := i18n.Display(explicitLang, i18n.PreReadNotifyLang(envFile()))
	command := &menuCommand{
		version:   ver,
		lang:      lang,
		reader:    reader,
		out:       os.Stdout,
		errOut:    os.Stderr,
		geteuid:   os.Geteuid,
		stdinTTY:  func() bool { return isTerminalFile(os.Stdin) },
		stdoutTTY: func() bool { return isTerminalFile(os.Stdout) },
		stderrTTY: func() bool { return isTerminalFile(os.Stderr) },
	}
	command.dispatch = func(actionArgs []string) int {
		return mainWithSystemdAndReader(ver, actionArgs, systemdQuery, reader)
	}
	return command.run()
}

func parseMenuArgs(args []string) (lang string, help, ok bool) {
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--lang":
			if i+1 >= len(args) {
				fmt.Fprintln(os.Stderr, "Missing value for --lang")
				return "", false, false
			}
			i++
			lang = args[i]
			if lang != "zh" && lang != "en" {
				fmt.Fprintln(os.Stderr, "Invalid --lang (expected zh or en)")
				return "", false, false
			}
		case "-h", "--help":
			help = true
		default:
			fmt.Fprintf(os.Stderr, "Unknown menu argument: %s\n", safeCLIText(args[i]))
			return "", false, false
		}
	}
	return lang, help, true
}

func (m *menuCommand) run() int {
	if m.geteuid == nil || m.geteuid() != 0 {
		m.say(m.errOut, "请以 root 运行。", "Please run as root.")
		return 1
	}
	if m.stdinTTY == nil || m.stdoutTTY == nil || m.stderrTTY == nil ||
		!m.stdinTTY() || !m.stdoutTTY() || !m.stderrTTY() {
		m.say(m.errOut,
			"交互菜单要求 stdin、stdout 和 stderr 都连接到真实终端。",
			"The interactive menu requires stdin, stdout, and stderr to all be attached to a real terminal.")
		return 2
	}
	if m.reader == nil || m.dispatch == nil {
		m.say(m.errOut, "交互菜单未正确初始化。", "The interactive menu is not configured correctly.")
		return 2
	}

	draw := true
	for {
		if draw {
			m.draw()
			draw = false
		}
		fmt.Fprint(m.errOut, m.pick("请选择 [0-9]（回车重新显示菜单）: ", "Select [0-9] (Enter redraws the menu): "))
		choice, state := m.readLine()
		switch state {
		case menuReadRetry:
			continue
		case menuReadAbort:
			return 2
		}
		if choice == "" {
			draw = true
			continue
		}
		if choice == "0" {
			return 0
		}

		result := m.runChoice(choice)
		if result.abort {
			return 2
		}
		if result.redraw {
			draw = true
		}
		if result.dispatched && (result.exit || result.status != 0) {
			return result.status
		}
	}
}

func (m *menuCommand) draw() {
	fmt.Fprintf(m.out, "\nsecurity-update-notify %s\n\n", safeCLIText(m.version))
	m.say(m.out, "检查", "Checks")
	m.say(m.out, "  1) 预览本次检查（不发送、不写状态）", "  1) Preview this check (no delivery or state writes)")
	m.say(m.out, "  2) 立即检查（可能发送通知）", "  2) Run a check now (may send notifications)")
	m.say(m.out, "  3) 系统诊断", "  3) Run system doctor")
	fmt.Fprintln(m.out)
	m.say(m.out, "通知", "Notifications")
	m.say(m.out, "  4) 修改通知设置", "  4) Configure notifications")
	m.say(m.out, "  5) 测试通知", "  5) Test notifications")
	fmt.Fprintln(m.out)
	m.say(m.out, "维护", "Maintenance")
	m.say(m.out, "  6) 检查新版本", "  6) Check for a new version")
	m.say(m.out, "  7) 升级", "  7) Upgrade")
	m.say(m.out, "  8) 卸载", "  8) Uninstall")
	m.say(m.out, "  9) 界面语言 / Interface language", "  9) Interface language / 界面语言")
	m.say(m.out, "  0) 退出", "  0) Exit")
}

func (m *menuCommand) runChoice(choice string) menuActionResult {
	lang := string(m.lang)
	switch choice {
	case "1":
		return m.runAction([]string{"run", "--dry-run", "--lang", lang}, false)
	case "2":
		result := m.confirmYesNo(
			"本次检查可能发送通知，是否继续？[y/N]: ",
			"This check may send notifications. Continue? [y/N]: ")
		if result == menuPromptAborted {
			return menuActionResult{abort: true}
		}
		if result != menuPromptConfirmed {
			return menuActionResult{}
		}
		return m.runAction([]string{"run", "--wait-lock", "60", "--lang", lang}, false)
	case "3":
		return m.runAction([]string{"doctor", "--wait-lock", "60", "--lang", lang}, false)
	case "4":
		return m.runAction([]string{"configure", "notifications", "--lang", lang}, true)
	case "5":
		return m.testNotifications()
	case "6":
		return m.runAction([]string{"check-upgrade", "--lang", lang}, false)
	case "7":
		result := m.confirmExact("YES",
			"升级将下载并验证发布包。输入 YES 继续: ",
			"The upgrade will download and verify a release. Type YES to continue: ")
		if result == menuPromptAborted {
			return menuActionResult{abort: true}
		}
		if result != menuPromptConfirmed {
			return menuActionResult{}
		}
		return m.runAction([]string{"upgrade", "--lang", lang}, true)
	case "8":
		return m.uninstallMenu()
	case "9":
		return m.languageMenu()
	default:
		m.say(m.errOut, "无效选择。", "Invalid choice.")
		return menuActionResult{}
	}
}

func (m *menuCommand) testNotifications() menuActionResult {
	m.say(m.out, "\n测试通知", "\nTest notifications")
	m.say(m.out, "  1) 发送普通测试消息", "  1) Send a normal test message")
	m.say(m.out, "  2) 发送模拟重启提醒（不会重启主机）", "  2) Send a simulated reboot alert (does not reboot the host)")
	m.say(m.out, "  0) 返回", "  0) Back")
	for {
		fmt.Fprint(m.errOut, m.pick("请选择 [0-2]: ", "Select [0-2]: "))
		choice, state := m.readLine()
		if state == menuReadRetry {
			continue
		}
		if state == menuReadAbort {
			return menuActionResult{abort: true}
		}
		if choice == "" || choice == "0" {
			return menuActionResult{}
		}
		flag := ""
		switch choice {
		case "1":
			flag = "--send-test"
		case "2":
			flag = "--simulate-reboot"
		default:
			m.say(m.errOut, "无效选择。", "Invalid choice.")
			continue
		}
		confirmed := m.confirmYesNo(
			"此操作将发送测试通知，是否继续？[y/N]: ",
			"This action will send a test notification. Continue? [y/N]: ")
		if confirmed == menuPromptAborted {
			return menuActionResult{abort: true}
		}
		if confirmed != menuPromptConfirmed {
			return menuActionResult{}
		}
		return m.runAction([]string{"test", flag, "--no-dedupe", "--lang", string(m.lang)}, false)
	}
}

func (m *menuCommand) uninstallMenu() menuActionResult {
	m.say(m.out, "\n卸载", "\nUninstall")
	m.say(m.out, "  1) 移除程序，保留配置", "  1) Remove the program and keep configuration")
	m.say(m.out,
		"  2) 彻底清理（恢复 apt/dnf 配置，并删除 SUN 配置、凭据、状态、备份和日志）",
		"  2) Full purge (restore apt/dnf config; remove SUN config, credentials, state, backups, and logs)")
	m.say(m.out, "  0) 返回", "  0) Back")
	for {
		fmt.Fprint(m.errOut, m.pick("请选择 [0-2]: ", "Select [0-2]: "))
		choice, state := m.readLine()
		if state == menuReadRetry {
			continue
		}
		if state == menuReadAbort {
			return menuActionResult{abort: true}
		}
		switch choice {
		case "", "0":
			return menuActionResult{}
		case "1":
			confirmed := m.confirmExact("YES",
				"输入 YES 确认卸载并保留配置: ",
				"Type YES to uninstall and keep configuration: ")
			if confirmed == menuPromptAborted {
				return menuActionResult{abort: true}
			}
			if confirmed != menuPromptConfirmed {
				return menuActionResult{}
			}
			return m.runAction([]string{"uninstall", "--lang", string(m.lang)}, true)
		case "2":
			confirmed := m.confirmExact("PURGE",
				"这会恢复 SUN 受管的 apt/dnf 自动更新配置，并删除 SUN 配置、通知凭据、状态、升级备份和日志。输入 PURGE 确认: ",
				"This restores SUN-managed apt/dnf automatic-update configuration and removes SUN configuration, notification credentials, state, upgrade backups, and logs. Type PURGE to confirm: ")
			if confirmed == menuPromptAborted {
				return menuActionResult{abort: true}
			}
			if confirmed != menuPromptConfirmed {
				return menuActionResult{}
			}
			// The menu already required the exact PURGE token above, so it opts out of
			// the command's own confirmation. This is skew-free: the menu and the
			// uninstall command are always the same binary.
			return m.runAction([]string{"uninstall", "--purge-config", "--yes", "--lang", string(m.lang)}, true)
		default:
			m.say(m.errOut, "无效选择。", "Invalid choice.")
		}
	}
}

func (m *menuCommand) languageMenu() menuActionResult {
	fmt.Fprintln(m.out, "\nLanguage / 语言:")
	fmt.Fprintln(m.out, "  1) 中文")
	fmt.Fprintln(m.out, "  2) English")
	fmt.Fprintln(m.out, "  0) 返回 / Back")
	for {
		fmt.Fprint(m.errOut, "选择 / Select [0-2]: ")
		choice, state := m.readLine()
		if state == menuReadRetry {
			continue
		}
		if state == menuReadAbort {
			return menuActionResult{abort: true}
		}
		switch choice {
		case "", "0":
			return menuActionResult{}
		case "1":
			m.lang = i18n.ZH
			m.say(m.out, "界面语言已切换为中文（仅当前会话）。", "Interface language switched to Chinese for this session.")
			return menuActionResult{redraw: true}
		case "2":
			m.lang = i18n.EN
			m.say(m.out, "界面语言已切换为 English（仅当前会话）。", "Interface language switched to English for this session.")
			return menuActionResult{redraw: true}
		default:
			m.say(m.errOut, "无效选择。", "Invalid choice.")
		}
	}
}

func (m *menuCommand) runAction(args []string, exit bool) menuActionResult {
	fmt.Fprintln(m.out)
	status := m.dispatch(append([]string(nil), args...))
	fmt.Fprintln(m.out)
	return menuActionResult{status: status, dispatched: true, exit: exit}
}

func (m *menuCommand) confirmYesNo(zh, en string) menuPromptResult {
	for {
		fmt.Fprint(m.errOut, m.pick(zh, en))
		answer, state := m.readLine()
		if state == menuReadRetry {
			continue
		}
		if state == menuReadAbort {
			return menuPromptAborted
		}
		switch strings.ToLower(answer) {
		case "y", "yes":
			return menuPromptConfirmed
		case "", "n", "no":
			m.say(m.errOut, "已取消。", "Cancelled.")
			return menuPromptCancelled
		default:
			m.say(m.errOut, "请输入 y 或 n。", "Enter y or n.")
		}
	}
}

func (m *menuCommand) confirmExact(token, zh, en string) menuPromptResult {
	fmt.Fprint(m.errOut, m.pick(zh, en))
	answer, state := m.readRawLine()
	if state == menuReadRetry {
		m.say(m.errOut, "已取消。", "Cancelled.")
		return menuPromptCancelled
	}
	if state == menuReadAbort {
		return menuPromptAborted
	}
	if answer != token {
		m.say(m.errOut, "确认不匹配，已取消。", "Confirmation did not match; cancelled.")
		return menuPromptCancelled
	}
	return menuPromptConfirmed
}

type menuReadState uint8

const (
	menuReadOK menuReadState = iota
	menuReadRetry
	menuReadAbort
)

func (m *menuCommand) readLine() (string, menuReadState) {
	line, state := m.readRawLine()
	return strings.TrimSpace(line), state
}

func (m *menuCommand) readRawLine() (string, menuReadState) {
	line, err := readBoundedLine(m.reader)
	if errors.Is(err, errInteractiveLineTooLong) {
		m.say(m.errOut, "输入过长，已拒绝。", "Input is too long and was rejected.")
		return "", menuReadRetry
	}
	if errors.Is(err, io.EOF) {
		m.say(m.errOut, "输入已结束，已取消。", "Input ended; cancelled.")
		return "", menuReadAbort
	}
	if err != nil && !errors.Is(err, io.EOF) {
		m.say(m.errOut, "读取输入失败，已取消。", "Unable to read input; cancelled.")
		return "", menuReadAbort
	}
	return trimLineEnding(line), menuReadOK
}

func trimLineEnding(line string) string {
	line = strings.TrimSuffix(line, "\n")
	return strings.TrimSuffix(line, "\r")
}

func (m *menuCommand) pick(zh, en string) string { return m.lang.Pick(zh, en) }

func (m *menuCommand) say(out io.Writer, zh, en string) {
	fmt.Fprintln(out, m.pick(zh, en))
}

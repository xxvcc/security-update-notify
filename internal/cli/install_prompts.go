package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"strings"
)

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
	fmt.Fprintf(c.console.out, "%s [%s]: ", c.pick(lang, zhLabel, enLabel), safeCLIText(defaultValue))
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
	fmt.Fprintln(out, safeCLIText(c.pick(lang, zh, en)))
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

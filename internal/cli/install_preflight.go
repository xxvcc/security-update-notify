package cli

import (
	"context"
	"errors"
	"fmt"

	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/feishu"

	"github.com/xxvcc/security-update-notify/internal/installer"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

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
		fmt.Fprintln(c.console.errOut, "Telegram preflight:", safeCLIText(err.Error()))
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
			fmt.Fprintln(c.console.errOut, "Feishu directory scan:", safeCLIText(err.Error()))
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
				fmt.Fprintln(c.console.errOut, "Feishu preflight:", safeCLIText(err.Error()))
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

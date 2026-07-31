package cli

import (
	"errors"
)

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

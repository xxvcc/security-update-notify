package installer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/osrel"
)

var (
	configKeyRE   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	timeRE        = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	nonNegativeRE = regexp.MustCompile(`^[0-9]+$`)
	positiveRE    = regexp.MustCompile(`^[1-9][0-9]*$`)
	telegramRE    = regexp.MustCompile(`^[0-9]+:[A-Za-z0-9_-]+$`)
	feishuOpenRE  = regexp.MustCompile(`^ou_[A-Za-z0-9_-]+$`)
)

var configKeys = map[string]bool{
	"CONFIG_VERSION": true, "NOTIFY_CHANNELS": true,
	"TELEGRAM_BOT_TOKEN": true, "TELEGRAM_CHAT_ID": true,
	"FEISHU_APP_ID": true, "FEISHU_RECEIVE_ID": true,
	"HOST_LABEL": true, "PUBLIC_IP": true, "INCLUDE_PUBLIC_IP": true,
	"NOTIFY_OK": true, "NOTIFY_UPGRADE": true,
	"DEDUP_MODE": true, "DEDUP_INTERVAL_DAYS": true,
	"NOTIFY_LANG": true, "BACKEND": true,
	"CHECK_UPDATE_HEALTH": true, "STALE_UPDATE_DAYS": true,
	"CHECK_EOL": true, "PENDING_ALERT_DAYS": true,
	"RESTART_ALERT_DAYS": true, "CHECK_SELF_UPDATE": true,
	"SELF_UPDATE_CHECK_DAYS": true,
}

var configDefaults = map[string]string{
	"CONFIG_VERSION":         "4",
	"NOTIFY_CHANNELS":        "telegram",
	"TELEGRAM_BOT_TOKEN":     "",
	"TELEGRAM_CHAT_ID":       "",
	"FEISHU_APP_ID":          "",
	"FEISHU_RECEIVE_ID":      "",
	"HOST_LABEL":             "",
	"PUBLIC_IP":              "",
	"INCLUDE_PUBLIC_IP":      "1",
	"NOTIFY_OK":              "0",
	"NOTIFY_UPGRADE":         "0",
	"DEDUP_MODE":             "daily",
	"DEDUP_INTERVAL_DAYS":    "3",
	"NOTIFY_LANG":            "zh",
	"BACKEND":                "auto",
	"CHECK_UPDATE_HEALTH":    "1",
	"STALE_UPDATE_DAYS":      "7",
	"CHECK_EOL":              "1",
	"PENDING_ALERT_DAYS":     "3",
	"RESTART_ALERT_DAYS":     "7",
	"CHECK_SELF_UPDATE":      "1",
	"SELF_UPDATE_CHECK_DAYS": "7",
}

type installPlan struct {
	values         map[string]string
	checkTime      string
	osRelease      osrel.OSRelease
	backend        string
	supportTier    string
	existingConfig bool
	upgrade        bool
}

func (i *Installer) prepare(options Options) (installPlan, error) {
	payload := options.Payload.withEmbeddedDefaults()
	if len(payload.Runtime) == 0 {
		return installPlan{}, invalid("runtime payload is required")
	}
	if len(payload.Runtime) > 256<<20 {
		return installPlan{}, invalid("runtime payload exceeds 256 MiB")
	}

	existing, exists, err := i.readExistingConfig()
	if err != nil {
		return installPlan{}, err
	}
	values := make(map[string]string, len(configDefaults))
	for key, value := range configDefaults {
		values[key] = value
	}
	for key, value := range existing {
		values[key] = value
	}
	oldFeishuAppID := values["FEISHU_APP_ID"]
	for key, value := range options.Config {
		if !configKeys[key] {
			return installPlan{}, invalid("unsupported config key: %s", key)
		}
		values[key] = value
	}
	if options.Backend != "" {
		values["BACKEND"] = options.Backend
	}
	values["CONFIG_VERSION"] = "4"

	if newID, explicit := options.Config["FEISHU_APP_ID"]; explicit && newID != oldFeishuAppID {
		if _, receiveExplicit := options.Config["FEISHU_RECEIVE_ID"]; !receiveExplicit {
			values["FEISHU_RECEIVE_ID"] = ""
		}
	}

	checkTime := options.CheckTime
	if checkTime == "" {
		checkTime, err = i.readExistingCheckTime()
		if err != nil {
			return installPlan{}, err
		}
	}
	if checkTime == "" {
		checkTime = "09:00"
	}
	if !timeRE.MatchString(checkTime) {
		return installPlan{}, invalid("invalid check time %q (expected HH:MM)", checkTime)
	}

	allowRecipientSelection := options.Preflight != nil && channelSelectedUnnormalized(values["NOTIFY_CHANNELS"], "feishu")
	if err := normalizeAndValidateConfig(values, allowRecipientSelection); err != nil {
		return installPlan{}, err
	}
	if len(options.FeishuSecret) > 0 {
		if err := validateSecret(options.FeishuSecret); err != nil {
			return installPlan{}, err
		}
	}

	osRelease, err := i.readOSRelease()
	if err != nil {
		return installPlan{}, err
	}
	detected, tier := osrel.SupportTier(osRelease)
	if tier == osrel.Unsupported {
		return installPlan{}, failure("detect distribution", fmt.Errorf("unsupported distribution ID=%s VERSION_ID=%s", osRelease.ID, osRelease.VersionID))
	}
	if tier == osrel.BestEffort && !options.AllowBestEffort {
		return installPlan{}, failure("detect distribution", fmt.Errorf("%s is best-effort; explicit opt-in is required", displayOS(osRelease)))
	}
	backend := values["BACKEND"]
	if backend == "auto" {
		backend = detected
	}
	if backend != "apt" && backend != "dnf" {
		return installPlan{}, invalid("invalid or unsupported backend: %s", backend)
	}
	values["BACKEND"] = backend

	upgrade := exists
	for _, path := range []string{BinaryPath, TimerPath, ServicePath} {
		if ok, statErr := i.exists(path); statErr != nil {
			return installPlan{}, failure("inspect existing installation", statErr)
		} else if ok {
			upgrade = true
		}
	}
	return installPlan{
		values: values, checkTime: checkTime, osRelease: osRelease,
		backend: backend, supportTier: tier, existingConfig: exists, upgrade: upgrade,
	}, nil
}

func normalizeAndValidateConfig(values map[string]string, allowMissingFeishuRecipient bool) error {
	for key, value := range values {
		if len(value) > 65536 {
			return invalid("%s exceeds 64 KiB", key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return invalid("%s cannot contain line breaks", key)
		}
		if strings.ContainsRune(value, '\x00') {
			return invalid("%s cannot contain NUL bytes", key)
		}
		if strings.Contains(value, "'") && strings.Contains(value, `"`) {
			return invalid("%s cannot contain both single and double quotes", key)
		}
	}
	channels, err := normalizeChannels(values["NOTIFY_CHANNELS"])
	if err != nil {
		return err
	}
	values["NOTIFY_CHANNELS"] = channels
	if !channelSelected(channels, "telegram") {
		values["TELEGRAM_BOT_TOKEN"] = ""
		values["TELEGRAM_CHAT_ID"] = ""
	} else {
		token, chat := values["TELEGRAM_BOT_TOKEN"], values["TELEGRAM_CHAT_ID"]
		if len(token) == 0 || len(token) > 256 || !telegramRE.MatchString(token) {
			return invalid("invalid Telegram Bot Token")
		}
		if len(chat) == 0 || len(chat) > 256 {
			return invalid("invalid Telegram Chat ID")
		}
	}
	if !channelSelected(channels, "feishu") {
		values["FEISHU_APP_ID"] = ""
		values["FEISHU_RECEIVE_ID"] = ""
	} else {
		if len(values["FEISHU_APP_ID"]) == 0 || len(values["FEISHU_APP_ID"]) > 256 {
			return invalid("invalid Feishu App ID")
		}
		if values["FEISHU_RECEIVE_ID"] == "" && allowMissingFeishuRecipient {
			// The transaction-scoped directory hook selects it after CA/dependencies
			// are available and the old timer has crossed the runtime-lock barrier.
		} else if len(values["FEISHU_RECEIVE_ID"]) > 256 || !feishuOpenRE.MatchString(values["FEISHU_RECEIVE_ID"]) {
			return invalid("invalid Feishu recipient open_id")
		}
	}
	for _, key := range []string{"INCLUDE_PUBLIC_IP", "NOTIFY_OK", "NOTIFY_UPGRADE", "CHECK_UPDATE_HEALTH", "CHECK_EOL", "CHECK_SELF_UPDATE"} {
		normalized, ok := normalizeBool(values[key])
		if !ok {
			return invalid("invalid %s: expected 0 or 1", key)
		}
		values[key] = normalized
	}
	if values["NOTIFY_LANG"] != "zh" && values["NOTIFY_LANG"] != "en" {
		return invalid("invalid notification language: %s", values["NOTIFY_LANG"])
	}
	if values["DEDUP_MODE"] == "always" {
		values["DEDUP_MODE"] = "once"
	}
	switch values["DEDUP_MODE"] {
	case "once", "daily":
	case "interval":
		if !positiveRE.MatchString(values["DEDUP_INTERVAL_DAYS"]) {
			return invalid("invalid dedup interval days")
		}
	default:
		return invalid("invalid dedup mode: %s", values["DEDUP_MODE"])
	}
	for _, key := range []string{"STALE_UPDATE_DAYS", "PENDING_ALERT_DAYS", "RESTART_ALERT_DAYS"} {
		if !nonNegativeRE.MatchString(values[key]) {
			return invalid("invalid %s: expected a non-negative integer", key)
		}
	}
	if !positiveRE.MatchString(values["SELF_UPDATE_CHECK_DAYS"]) {
		return invalid("invalid SELF_UPDATE_CHECK_DAYS: expected a positive integer")
	}
	return nil
}

func normalizeChannels(raw string) (string, error) {
	hasTelegram, hasFeishu := false, false
	for _, item := range strings.Split(strings.ToLower(strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\n\v\f\r", r) {
			return -1
		}
		return r
	}, raw)), ",") {
		switch item {
		case "telegram":
			hasTelegram = true
		case "feishu":
			hasFeishu = true
		default:
			return "", invalid("invalid receiving platform: %s", item)
		}
	}
	switch {
	case hasTelegram && hasFeishu:
		return "telegram,feishu", nil
	case hasTelegram:
		return "telegram", nil
	case hasFeishu:
		return "feishu", nil
	default:
		return "", invalid("receiving platforms cannot be empty")
	}
}

func channelSelected(channels, channel string) bool {
	for _, item := range strings.Split(channels, ",") {
		if item == channel {
			return true
		}
	}
	return false
}

func channelSelectedUnnormalized(channels, channel string) bool {
	normalized, err := normalizeChannels(channels)
	return err == nil && channelSelected(normalized, channel)
}

func applyPreparedConfig(plan *installPlan, prepared *Prepared) error {
	if prepared == nil || prepared.Config == nil {
		return invalid("preflight returned no configuration")
	}
	updated := make(map[string]string, len(configDefaults))
	for key := range configDefaults {
		value, exists := prepared.Config[key]
		if !exists {
			return invalid("preflight removed required config key: %s", key)
		}
		updated[key] = value
	}
	for key := range prepared.Config {
		if !configKeys[key] {
			return invalid("preflight added unsupported config key: %s", key)
		}
	}
	if updated["BACKEND"] != plan.backend {
		return invalid("preflight cannot change BACKEND")
	}
	updated["CONFIG_VERSION"] = "4"
	oldAppID, oldReceiveID := plan.values["FEISHU_APP_ID"], plan.values["FEISHU_RECEIVE_ID"]
	if updated["FEISHU_APP_ID"] != oldAppID && updated["FEISHU_RECEIVE_ID"] == oldReceiveID {
		updated["FEISHU_RECEIVE_ID"] = ""
	}
	if err := normalizeAndValidateConfig(updated, false); err != nil {
		return err
	}
	plan.values = updated
	return nil
}

func normalizeBool(value string) (string, bool) {
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on":
		return "1", true
	case "0", "false", "no", "off":
		return "0", true
	default:
		return "", false
	}
}

func validateSecret(secret []byte) error {
	if len(secret) == 0 || len(secret) > 65536 || bytes.ContainsAny(secret, "\r\n\x00") {
		return invalid("Feishu App Secret is empty, contains a line break, or exceeds 64 KiB")
	}
	return nil
}

func (i *Installer) readExistingConfig() (map[string]string, bool, error) {
	info, err := i.fs.Lstat(ConfigPath)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, false, nil
	}
	if err != nil {
		return nil, false, failure("inspect existing config", err)
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, false, failure("inspect existing config", errors.New("config must be a regular file, not a symlink"))
	}
	if info.Size() > 4<<20 {
		return nil, false, failure("read existing config", errors.New("config exceeds 4 MiB"))
	}
	data, _, err := i.fs.ReadRegularFile(ConfigPath, 4<<20)
	if err != nil {
		return nil, false, failure("read existing config", err)
	}
	if len(data) > 4<<20 {
		return nil, false, failure("read existing config", errors.New("config exceeds 4 MiB"))
	}
	values, err := parseInstallerConfig(data)
	if err != nil {
		return nil, false, failure("parse existing config", err)
	}
	return values, true, nil
}

// parseInstallerConfig implements the forward-compatible upgrade read contract:
// malformed and unknown lines are ignored, while recognized values are kept.
func parseInstallerConfig(data []byte) (map[string]string, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" || strings.HasPrefix(strings.TrimLeft(line, " \t\n\v\f\r"), "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.Map(func(r rune) rune {
			if strings.ContainsRune(" \t\n\v\f\r", r) {
				return -1
			}
			return r
		}, key)
		if !configKeyRE.MatchString(key) || !configKeys[key] {
			continue
		}
		values[key] = parseInstallerValue(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func parseInstallerValue(value string) string {
	space := " \t\n\v\f\r"
	value = strings.Trim(value, space)
	if !strings.HasPrefix(value, `"`) && !strings.HasPrefix(value, "'") {
		for index := 0; index+1 < len(value); index++ {
			if strings.ContainsRune(space, rune(value[index])) && value[index+1] == '#' {
				value = strings.TrimRight(value[:index], space)
				break
			}
		}
	}
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		value = value[1 : len(value)-1]
	}
	return value
}

func (i *Installer) readExistingCheckTime() (string, error) {
	info, statErr := i.fs.Lstat(TimerPath)
	if errors.Is(statErr, fs.ErrNotExist) {
		return "", nil
	}
	if statErr != nil {
		return "", failure("inspect existing timer", statErr)
	}
	if info.Mode().IsRegular() && info.Size() > 1<<20 {
		return "", failure("read existing timer", errors.New("timer unit exceeds 1 MiB"))
	}
	if info.Mode()&fs.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", failure("inspect existing timer", errors.New("timer unit must be a regular file, not a symlink"))
	}
	data, _, err := i.fs.ReadRegularFile(TimerPath, 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", failure("read existing timer", err)
	}
	if len(data) > 1<<20 {
		return "", failure("read existing timer", errors.New("timer unit exceeds 1 MiB"))
	}
	re := regexp.MustCompile(`(?m)^OnCalendar=\*-\*-\*[ \t]+([0-9]{2}:[0-9]{2}):[0-9]{2}\r?$`)
	match := re.FindSubmatch(data)
	if len(match) == 2 {
		return string(match[1]), nil
	}
	return "", nil
}

func (i *Installer) readOSRelease() (osrel.OSRelease, error) {
	data, _, err := i.fs.ReadFileFollow("/etc/os-release", 4<<20)
	if err != nil {
		return osrel.OSRelease{}, failure("read /etc/os-release", err)
	}
	if len(data) > 4<<20 {
		return osrel.OSRelease{}, failure("read /etc/os-release", errors.New("file exceeds 4 MiB"))
	}
	var result osrel.OSRelease
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		key, value, ok := strings.Cut(strings.TrimSuffix(scanner.Text(), "\r"), "=")
		if !ok {
			continue
		}
		value = parseOSReleaseValue(value)
		switch key {
		case "ID":
			result.ID = value
		case "VERSION_ID":
			result.VersionID = value
		case "PRETTY_NAME":
			result.PrettyName = value
		case "ID_LIKE":
			result.IDLike = value
		}
	}
	if err := scanner.Err(); err != nil {
		return osrel.OSRelease{}, failure("parse /etc/os-release", err)
	}
	return result, nil
}

func parseOSReleaseValue(value string) string {
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		value = value[1 : len(value)-1]
	}
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		value = value[1 : len(value)-1]
	}
	return value
}

func displayOS(release osrel.OSRelease) string {
	if release.PrettyName != "" {
		return release.PrettyName
	}
	return strings.TrimSpace(release.ID + " " + release.VersionID)
}

func renderConfig(values map[string]string) ([]byte, error) {
	var output bytes.Buffer
	if err := config.Write(&output, values); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func cloneConfig(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for key, value := range values {
		copy[key] = value
	}
	return copy
}

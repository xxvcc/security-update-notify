package installer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/filetrust"
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
	values          map[string]string
	checkTime       string
	osRelease       osrel.OSRelease
	backend         string
	supportTier     string
	profile         osrel.Profile
	existingConfig  bool
	upgrade         bool
	originalTargets notificationTargets
}

type notificationTargets struct {
	telegramEnabled bool
	telegramBotID   string
	telegramChatID  string
	feishuEnabled   bool
	feishuAppID     string
	feishuReceiveID string
}

func (i *Installer) prepare(ctx context.Context, options Options) (installPlan, error) {
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
	originalTargets := notificationTargetsFor(values)
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
	profile := osrel.ProfileFor(osRelease)
	detected, tier := profile.Backend, profile.Tier
	if tier == osrel.Unsupported {
		if options.AllowBestEffort && profile.Inferred {
			tier = osrel.BestEffort
			profile.Tier = tier
		} else {
			return installPlan{}, failure("detect distribution", fmt.Errorf("unsupported distribution ID=%s VERSION_ID=%s", osRelease.ID, osRelease.VersionID))
		}
	}
	if tier == osrel.BestEffort && !options.AllowBestEffort {
		return installPlan{}, failure("detect distribution", fmt.Errorf("%s is best-effort; explicit opt-in is required", displayOS(osRelease)))
	}
	if profile.Inferred && options.SkipPostInstallCheck {
		return installPlan{}, invalid("unlisted ID_LIKE derivatives require the post-install verification gate")
	}
	backend := values["BACKEND"]
	if backend == "auto" {
		backend = detected
	}
	if backend != "apt" && backend != "dnf" {
		return installPlan{}, invalid("invalid or unsupported backend: %s", backend)
	}
	if backend != detected {
		return installPlan{}, invalid("backend %s does not match supported host backend %s", backend, detected)
	}
	if profile.Engine == osrel.EngineUnknown {
		profile, err = i.probeInferredDNFProfile(ctx, osRelease)
		if err != nil {
			return installPlan{}, err
		}
		profile.Tier = tier
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
		backend: backend, supportTier: tier, profile: profile, existingConfig: exists, upgrade: upgrade,
		originalTargets: originalTargets,
	}, nil
}

func notificationTargetsFor(values map[string]string) notificationTargets {
	channels := values["NOTIFY_CHANNELS"]
	return notificationTargets{
		telegramEnabled: channelSelectedUnnormalized(channels, "telegram"),
		telegramBotID:   stableTelegramBotID(values["TELEGRAM_BOT_TOKEN"]),
		telegramChatID:  values["TELEGRAM_CHAT_ID"],
		feishuEnabled:   channelSelectedUnnormalized(channels, "feishu"),
		feishuAppID:     values["FEISHU_APP_ID"],
		feishuReceiveID: values["FEISHU_RECEIVE_ID"],
	}
}

func stableTelegramBotID(token string) string {
	botID, secret, ok := strings.Cut(token, ":")
	if !ok || botID == "" || secret == "" {
		return ""
	}
	for _, char := range botID {
		if char < '0' || char > '9' {
			return ""
		}
	}
	return botID
}

func changedDeliveryTargetChannels(plan installPlan) []string {
	if !plan.existingConfig {
		return nil
	}
	current := notificationTargetsFor(plan.values)
	var changed []string
	if current.telegramEnabled && (!plan.originalTargets.telegramEnabled ||
		current.telegramBotID != plan.originalTargets.telegramBotID ||
		current.telegramChatID != plan.originalTargets.telegramChatID) {
		changed = append(changed, "telegram")
	}
	if current.feishuEnabled && (!plan.originalTargets.feishuEnabled ||
		current.feishuAppID != plan.originalTargets.feishuAppID ||
		current.feishuReceiveID != plan.originalTargets.feishuReceiveID) {
		changed = append(changed, "feishu")
	}
	return changed
}

func (i *Installer) probeInferredDNFProfile(ctx context.Context, release osrel.OSRelease) (osrel.Profile, error) {
	probeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	detectedEngine := ""
	foundCandidate := false
	for _, candidate := range []string{"dnf", "dnf5", "yum"} {
		if !i.runner.LookPath(candidate) {
			continue
		}
		foundCandidate = true
		result := i.runner.Run(probeContext, Command{
			Name: candidate, Args: []string{"--version"}, Timeout: 30 * time.Second,
		})
		if commandResultIncomplete(result) || result.Err != nil || result.Code != 0 {
			continue
		}
		generation, known := backend.ProbeDNFGeneration(candidate, string(result.Stdout)+"\n"+string(result.Stderr))
		if !known {
			continue
		}
		engine := osrel.EngineDNF4
		if generation == backend.DNF5 {
			engine = osrel.EngineDNF5
		}
		if detectedEngine != "" && detectedEngine != engine {
			return osrel.Profile{}, failure("detect DNF generation", errors.New("installed DNF commands report conflicting generations"))
		}
		detectedEngine = engine
	}
	if detectedEngine == "" {
		detail := "no dnf, dnf5, or yum command was found"
		if foundCandidate {
			detail = "dnf, dnf5, and yum did not report an unambiguous successful version"
		}
		return osrel.Profile{}, failure("detect DNF generation", errors.New(detail))
	}
	profile, ok := osrel.ProfileForDetectedEngine(release, detectedEngine)
	if !ok {
		return osrel.Profile{}, failure("detect DNF generation", errors.New("detected engine cannot complete this distribution profile"))
	}
	return profile, nil
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
		if !validDayCount(values["DEDUP_INTERVAL_DAYS"], false) {
			return invalid("invalid dedup interval days")
		}
	default:
		return invalid("invalid dedup mode: %s", values["DEDUP_MODE"])
	}
	for _, key := range []string{"STALE_UPDATE_DAYS", "PENDING_ALERT_DAYS", "RESTART_ALERT_DAYS"} {
		if !validDayCount(values[key], true) {
			return invalid("invalid %s: expected a non-negative integer", key)
		}
	}
	if !validDayCount(values["SELF_UPDATE_CHECK_DAYS"], false) {
		return invalid("invalid SELF_UPDATE_CHECK_DAYS: expected a positive integer")
	}
	return nil
}

// Official artifacts include 32-bit builds, so persisted day counts must have
// identical integer semantics on every supported architecture.
func validDayCount(value string, allowZero bool) bool {
	pattern := positiveRE
	if allowZero {
		pattern = nonNegativeRE
	}
	if !pattern.MatchString(value) {
		return false
	}
	_, err := strconv.ParseUint(value, 10, 31)
	return err == nil
}

func normalizeChannels(raw string) (string, error) {
	cleaned := strings.ToLower(strings.Map(func(r rune) rune {
		if strings.ContainsRune(" \t\n\v\f\r", r) {
			return -1
		}
		return r
	}, raw))
	// Split never yields zero items, so without this guard an empty value reaches the loop as a
	// single empty item and reports "invalid receiving platform:" naming nothing.
	if cleaned == "" {
		return "", invalid("receiving platforms cannot be empty")
	}
	hasTelegram, hasFeishu := false, false
	for _, item := range strings.Split(cleaned, ",") {
		switch item {
		case "telegram":
			hasTelegram = true
		case "feishu":
			hasFeishu = true
		default:
			return "", invalid("invalid receiving platform: %q", item)
		}
	}
	switch {
	case hasTelegram && hasFeishu:
		return "telegram,feishu", nil
	case hasTelegram:
		return "telegram", nil
	default:
		// A non-empty value whose every item was accepted must have set at least one flag.
		return "feishu", nil
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
	data, openedInfo, err := i.fs.ReadRegularFile(ConfigPath, 4<<20)
	if err != nil {
		return nil, false, failure("read existing config", err)
	}
	if err := filetrust.ValidateRegular(openedInfo, int(i.rootOwnerUID), 0o077, true); err != nil {
		return nil, false, failure("read existing config", fmt.Errorf("config must be a protected root-owned regular file with one hard link: %w", err))
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
	data, openedInfo, err := i.fs.ReadRegularFile(TimerPath, 1<<20)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", failure("read existing timer", err)
	}
	if err := filetrust.ValidateRegular(openedInfo, int(i.rootOwnerUID), 0o022, true); err != nil {
		return "", failure("read existing timer", fmt.Errorf("timer unit must be a protected root-owned regular file with one hard link: %w", err))
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
	path := "/etc/os-release"
	_, statErr := i.fs.Lstat(path)
	if errors.Is(statErr, fs.ErrNotExist) {
		path = "/usr/lib/os-release"
	} else if statErr != nil {
		return osrel.OSRelease{}, failure("read "+path, statErr)
	}
	data, openedInfo, err := i.fs.ReadFileFollow(path, 4<<20)
	if err != nil {
		return osrel.OSRelease{}, failure("read "+path, err)
	}
	if err := filetrust.ValidateRegular(openedInfo, int(i.rootOwnerUID), 0o022, false); err != nil {
		return osrel.OSRelease{}, failure("read "+path,
			fmt.Errorf("os-release must resolve to a protected root-owned regular file: %w", err))
	}
	if len(data) > 4<<20 {
		return osrel.OSRelease{}, failure("read "+path, errors.New("file exceeds 4 MiB"))
	}
	result, err := osrel.Parse(bytes.NewReader(data))
	if err != nil {
		return osrel.OSRelease{}, failure("parse "+path, err)
	}
	return result, nil
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

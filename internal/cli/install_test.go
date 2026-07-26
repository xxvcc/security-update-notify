package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/feishu"
	"github.com/xxvcc/security-update-notify/internal/installer"
)

type fakeInstallerAPI struct {
	baseConfig     map[string]string
	installCalls   int
	options        installer.Options
	preflightInput installer.Prepared
	prepared       installer.Prepared
	result         installer.Result
	err            error
	token          string
	tokenErr       error
	secret         []byte
	secretErr      error
}

func (f *fakeInstallerAPI) Install(ctx context.Context, options installer.Options) (installer.Result, error) {
	f.installCalls++
	f.options = options
	f.options.FeishuSecret = bytes.Clone(options.FeishuSecret)
	f.options.Config = cloneCLIConfig(options.Config)
	prepared := installer.Prepared{Config: cloneCLIConfig(f.baseConfig), FeishuSecret: bytes.Clone(options.FeishuSecret)}
	for key, value := range options.Config {
		prepared.Config[key] = value
	}
	f.preflightInput = clonePrepared(prepared)
	if options.Preflight != nil {
		if err := options.Preflight(ctx, &prepared); err != nil {
			f.prepared = clonePrepared(prepared)
			return installer.Result{}, err
		}
	}
	f.prepared = clonePrepared(prepared)
	return f.result, f.err
}

func (f *fakeInstallerAPI) ReadTelegramTokenFile(string) (string, error) {
	return f.token, f.tokenErr
}

func (f *fakeInstallerAPI) ReadFeishuSecretFile(string) ([]byte, error) {
	return bytes.Clone(f.secret), f.secretErr
}

func clonePrepared(source installer.Prepared) installer.Prepared {
	source.Config = cloneCLIConfig(source.Config)
	source.FeishuSecret = bytes.Clone(source.FeishuSecret)
	return source
}

type fakeTelegramPreflight struct {
	getMeErrors []error
	sendErrors  []error
	getMeTokens []string
	sendTokens  []string
	sendChats   []string
}

func (f *fakeTelegramPreflight) GetMe(_ context.Context, token string) error {
	f.getMeTokens = append(f.getMeTokens, token)
	return shiftError(&f.getMeErrors)
}

func (f *fakeTelegramPreflight) SendMessage(_ context.Context, token, chatID, _ string) error {
	f.sendTokens = append(f.sendTokens, token)
	f.sendChats = append(f.sendChats, chatID)
	return shiftError(&f.sendErrors)
}

type fakeFeishuPreflight struct {
	users     []feishu.DirectoryUser
	scanErr   error
	probeErrs []error
	scans     int
	probes    int
	appIDs    []string
	secrets   []string
	sendErr   error
	sendIDs   []string
}

func (f *fakeFeishuPreflight) Probe(_ context.Context, appID, secret string) error {
	f.probes++
	f.appIDs = append(f.appIDs, appID)
	f.secrets = append(f.secrets, secret)
	return shiftError(&f.probeErrs)
}

func TestFeishuManualDirectoryFallbackStillProbesCredentials(t *testing.T) {
	feishuClient := &fakeFeishuPreflight{scanErr: errors.New("directory permission denied")}
	command, fake, _, _ := newInstallTestCommand(t, nil, "\n\n\n2\nou_manual\n", nil)
	command.feishu = feishuClient
	fake.secret = []byte("app-secret")
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "feishu", "--feishu-app-id", "cli_new",
		"--feishu-app-secret-file", "/run/secret",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if got := fake.prepared.Config["FEISHU_RECEIVE_ID"]; got != "ou_manual" {
		t.Fatalf("manual receive id=%q", got)
	}
	if feishuClient.scans != 1 || feishuClient.probes != 1 {
		t.Fatalf("scans=%d probes=%d, want 1,1", feishuClient.scans, feishuClient.probes)
	}
}

func (f *fakeFeishuPreflight) ScanDirectory(_ context.Context, appID, secret string) ([]feishu.DirectoryUser, error) {
	f.scans++
	f.appIDs = append(f.appIDs, appID)
	f.secrets = append(f.secrets, secret)
	return append([]feishu.DirectoryUser(nil), f.users...), f.scanErr
}

func (f *fakeFeishuPreflight) SendText(_ context.Context, appID, secret, receiveID, _ string) error {
	f.appIDs = append(f.appIDs, appID)
	f.secrets = append(f.secrets, secret)
	f.sendIDs = append(f.sendIDs, receiveID)
	return f.sendErr
}

func shiftError(errors *[]error) error {
	if len(*errors) == 0 {
		return nil
	}
	err := (*errors)[0]
	*errors = (*errors)[1:]
	return err
}

type temporaryTestError struct{ message string }

func (e temporaryTestError) Error() string   { return e.message }
func (e temporaryTestError) Temporary() bool { return true }

func TestInstallArgumentErrors(t *testing.T) {
	for _, args := range [][]string{
		{"--unknown"},
		{"--telegram-chat-id"},
		{"--lang", "fr"},
		{"--env-file"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			command, _, _, _ := newInstallTestCommand(t, nil, "", nil)
			if code := command.run(args, false); code != 2 {
				t.Fatalf("run(%q)=%d, want 2", args, code)
			}
		})
	}
}

func TestInstallHelpListsSupportedPublicOptionsWithoutTabs(t *testing.T) {
	command, _, stdout, _ := newInstallTestCommand(t, nil, "", nil)
	if code := command.run([]string{"--help"}, false); code != 0 {
		t.Fatalf("help exit code=%d, want 0", code)
	}
	help := stdout.String()
	if strings.Contains(help, "\t") {
		t.Fatalf("help contains a tab: %q", help)
	}
	for _, option := range []string{
		"--env-file", "--notify-channels", "--telegram-token-file", "--telegram-token",
		"--telegram-chat-id", "--feishu-app-id", "--feishu-app-secret-file", "--feishu-receive-id",
		"--time", "--host-label", "--public-ip", "--include-public-ip", "--notify-ok",
		"--notify-upgrade", "--dedup-mode", "--dedup-interval-days", "--notify-lang", "--backend",
		"--allow-best-effort", "--lock-wait", "--send-test", "--skip-notify-test",
		"--skip-telegram-test", "--skip-feishu-test", "--skip-post-install-check", "--lang",
		"--non-interactive", "--yes",
	} {
		if !strings.Contains(help, option) {
			t.Errorf("help does not list %s", option)
		}
	}
}

func TestInstallLockWaitCompatibilityAndFlagOverride(t *testing.T) {
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS", "7")
	command, _, _, _ := newInstallTestCommand(t, nil, "", nil)
	parsed, err := command.parse(nil)
	if err != nil || !parsed.lockWaitSet || parsed.lockWait != 7*time.Second {
		t.Fatalf("environment lock wait=%v set=%v err=%v", parsed.lockWait, parsed.lockWaitSet, err)
	}
	parsed, err = command.parse([]string{"--lock-wait", "0"})
	if err != nil || !parsed.lockWaitSet || parsed.lockWait != 0 {
		t.Fatalf("flag lock wait=%v set=%v err=%v", parsed.lockWait, parsed.lockWaitSet, err)
	}
	if _, err := command.parse([]string{"--lock-wait", "3601"}); err == nil {
		t.Fatal("invalid --lock-wait was accepted")
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_WAIT_SECONDS", "invalid")
	parsed, err = command.parse(nil)
	if err != nil || parsed.lockWaitSet {
		t.Fatalf("invalid compatibility environment should fall back to default: %+v err=%v", parsed, err)
	}
}

func TestInstallRejectsNonRootBeforePromptOrMutation(t *testing.T) {
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.effectiveUID = func() int { return 1000 }
	prompted, loaded, constructed, runtimeRead := false, false, false, false
	command.console.readSecret = func(string) (string, error) { prompted = true; return "", nil }
	command.loadConfig = func(string) (*config.Config, error) { loaded = true; return nil, nil }
	command.newInstaller = func() (installerAPI, error) { constructed = true; return fake, nil }
	command.readRuntime = func() ([]byte, error) { runtimeRead = true; return nil, nil }

	code := command.run([]string{"--lang", "zh", "--non-interactive"}, false)
	if code != 1 || prompted || loaded || constructed || runtimeRead || fake.installCalls != 0 {
		t.Fatalf("code=%d prompted=%v loaded=%v constructed=%v runtime=%v installs=%d",
			code, prompted, loaded, constructed, runtimeRead, fake.installCalls)
	}
}

func TestNonInteractiveTelegramInstall(t *testing.T) {
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	fake.token = "123:token"
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "-y",
		"--notify-channels", "telegram", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100123", "--skip-telegram-test", "--skip-post-install-check",
	}, false)
	if code != 0 || fake.installCalls != 1 {
		t.Fatalf("code=%d installs=%d", code, fake.installCalls)
	}
	if fake.options.Config["TELEGRAM_BOT_TOKEN"] != "123:token" || fake.options.Config["TELEGRAM_CHAT_ID"] != "-100123" {
		t.Fatalf("config=%v", fake.options.Config)
	}
	if fake.options.Preflight != nil {
		t.Fatal("skipped Telegram install unexpectedly created a preflight")
	}
	approved, err := fake.options.ConfirmDependencies(context.Background(), installer.DependencyRequest{Packages: []string{"ca-certificates"}})
	if err != nil || !approved {
		t.Fatalf("non-interactive dependency confirmation=(%v, %v)", approved, err)
	}
}

func TestInstallReportsAdvisoryDoctorOutputWithoutFailing(t *testing.T) {
	command, fake, stdout, stderr := newInstallTestCommand(t, nil, "", nil)
	fake.token = "123:token"
	fake.result.PostInstallDoctor = &installer.CommandResult{
		Stdout: []byte("doctor stdout"),
		Stderr: []byte("doctor stderr"),
		Code:   1,
	}
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "-y",
		"--notify-channels", "telegram", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100123", "--skip-telegram-test",
	}, false)
	if code != 0 {
		t.Fatalf("advisory doctor changed install exit code to %d", code)
	}
	if !strings.Contains(stdout.String(), "doctor stdout\n") {
		t.Fatalf("doctor stdout was hidden: %q", stdout.String())
	}
	for _, want := range []string{"doctor stderr\n", "警告：安装已完成，但装后自检未完全通过"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr missing %q: %q", want, stderr.String())
		}
	}
}

func TestUnchangedUpgradeSkipsNotificationPreflight(t *testing.T) {
	existing := map[string]string{
		"CONFIG_VERSION": "4", "NOTIFY_CHANNELS": "telegram", "TELEGRAM_BOT_TOKEN": "123:old",
		"TELEGRAM_CHAT_ID": "-100", "NOTIFY_LANG": "zh", "DEDUP_MODE": "daily",
	}
	telegramClient := &fakeTelegramPreflight{getMeErrors: []error{errors.New("must not be called")}}
	command, fake, _, _ := newInstallTestCommand(t, existing, "", nil)
	command.telegram = telegramClient
	if code := command.run([]string{"--lang", "zh", "--non-interactive", "-y"}, false); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if fake.options.Preflight != nil || len(telegramClient.getMeTokens) != 0 {
		t.Fatalf("unchanged upgrade created preflight=%v calls=%d", fake.options.Preflight != nil, len(telegramClient.getMeTokens))
	}
}

func TestInteractiveDependencyConfirmation(t *testing.T) {
	command, _, _, _ := newInstallTestCommand(t, nil, "n\n", nil)
	parsed := installArguments{lang: "zh"}
	approved, err := command.confirmDependencies(&parsed)(context.Background(), installer.DependencyRequest{
		Backend: "apt", Packages: []string{"needrestart", "ca-certificates"},
	})
	if err != nil || approved {
		t.Fatalf("confirmation=(%v, %v), want declined without error", approved, err)
	}
}

func TestDependencyConfirmationRetriesAndReportsInstallStage(t *testing.T) {
	command, _, stdout, stderr := newInstallTestCommand(t, nil, "maybe\ny\n", nil)
	parsed := installArguments{lang: "zh"}
	approved, err := command.confirmDependencies(&parsed)(context.Background(), installer.DependencyRequest{
		Backend: "apt", Packages: []string{"needrestart", "ca-certificates"},
	})
	if err != nil || !approved {
		t.Fatalf("confirmation=(%v, %v), want approved", approved, err)
	}
	if !strings.Contains(stderr.String(), "请输入 y 或 n") {
		t.Fatalf("stderr=%q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "正在安装依赖软件包: needrestart ca-certificates") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestInteractiveFeishuDirectorySelectionPersistsOpenIDWithoutSkippedDelivery(t *testing.T) {
	feishuClient := &fakeFeishuPreflight{users: []feishu.DirectoryUser{{Name: "User", OpenID: "ou_selected"}}}
	command, fake, _, _ := newInstallTestCommand(t, nil, "\n\n\n1\n", []string{"app-secret"})
	command.feishu = feishuClient
	fake.secret = []byte("app-secret")
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "feishu", "--feishu-app-id", "cli_new",
		"--feishu-app-secret-file", "/run/secret", "--skip-feishu-test",
	}, false)
	if code != 0 || fake.installCalls != 1 {
		t.Fatalf("code=%d installs=%d", code, fake.installCalls)
	}
	if got := fake.prepared.Config["FEISHU_RECEIVE_ID"]; got != "ou_selected" {
		t.Fatalf("selected receive id=%q", got)
	}
	if feishuClient.scans != 1 {
		t.Fatalf("directory scans=%d", feishuClient.scans)
	}
	if fake.options.SendTest || len(feishuClient.sendIDs) != 0 {
		t.Fatalf("sendTest=%v Feishu delivery IDs=%v", fake.options.SendTest, feishuClient.sendIDs)
	}
}

func TestFeishuAppChangeNeverReusesOldOpenID(t *testing.T) {
	existing := map[string]string{
		"CONFIG_VERSION": "4", "NOTIFY_CHANNELS": "feishu", "FEISHU_APP_ID": "cli_old",
		"FEISHU_RECEIVE_ID": "ou_old", "NOTIFY_LANG": "zh", "DEDUP_MODE": "daily",
	}
	feishuClient := &fakeFeishuPreflight{users: []feishu.DirectoryUser{{Name: "New User", OpenID: "ou_new"}}}
	command, fake, _, _ := newInstallTestCommand(t, existing, "\n1\n", nil)
	command.feishu = feishuClient
	fake.secret = []byte("new-secret")
	code := command.run([]string{
		"--lang", "zh", "--feishu-app-id", "cli_new", "--feishu-app-secret-file", "/run/secret",
		"--skip-feishu-test",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if got := fake.preflightInput.Config["FEISHU_RECEIVE_ID"]; got != "" {
		t.Fatalf("preflight reused old app-scoped open_id %q", got)
	}
	if got := fake.prepared.Config["FEISHU_RECEIVE_ID"]; got != "ou_new" {
		t.Fatalf("selected receive id=%q", got)
	}
}

func TestConfigureWithoutChangesAvoidsInstallation(t *testing.T) {
	existing := map[string]string{
		"CONFIG_VERSION": "4", "NOTIFY_CHANNELS": "telegram", "TELEGRAM_BOT_TOKEN": "123:old",
		"TELEGRAM_CHAT_ID": "-100", "NOTIFY_LANG": "zh",
	}
	command, fake, _, _ := newInstallTestCommand(t, existing, "n\nn\n", nil)
	if code := command.run([]string{"--lang", "zh"}, true); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if fake.installCalls != 0 {
		t.Fatalf("install calls=%d", fake.installCalls)
	}
}

func TestNonInteractiveConfigureAllowsScheduleOnlyChange(t *testing.T) {
	existing := map[string]string{
		"CONFIG_VERSION": "4", "NOTIFY_CHANNELS": "telegram", "TELEGRAM_BOT_TOKEN": "123:old",
		"TELEGRAM_CHAT_ID": "-100", "NOTIFY_LANG": "zh", "DEDUP_MODE": "daily",
	}
	command, fake, _, stderr := newInstallTestCommand(t, existing, "", nil)
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "--time", "08:15", "--skip-notify-test",
	}, true)
	if code != 0 || fake.installCalls != 1 || fake.options.CheckTime != "08:15" {
		t.Fatalf("code=%d installs=%d time=%q stderr=%q", code, fake.installCalls, fake.options.CheckTime, stderr.String())
	}
}

func TestTelegramCredentialRetryUpdatesPreparedConfig(t *testing.T) {
	telegramClient := &fakeTelegramPreflight{getMeErrors: []error{errors.New("rejected"), nil}}
	command, fake, _, _ := newInstallTestCommand(t, nil, "\n\n\ny\n-200\n", []string{"456:new-token"})
	command.telegram = telegramClient
	fake.token = "123:old-token"
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "telegram", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if got := fake.prepared.Config["TELEGRAM_BOT_TOKEN"]; got != "456:new-token" {
		t.Fatalf("updated token=%q", got)
	}
	if got := fake.prepared.Config["TELEGRAM_CHAT_ID"]; got != "-200" {
		t.Fatalf("updated chat id=%q", got)
	}
}

func TestInteractiveInstallCollectsScheduleReminderAndTestPreferences(t *testing.T) {
	command, fake, _, _ := newInstallTestCommand(t, nil, "08:30\n3\n5\ny\n", nil)
	fake.token = "123:token"
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "telegram", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100", "--skip-telegram-test",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if fake.options.CheckTime != "08:30" || fake.options.Config["DEDUP_MODE"] != "interval" ||
		fake.options.Config["DEDUP_INTERVAL_DAYS"] != "5" || !fake.options.SendTest {
		t.Fatalf("checkTime=%q sendTest=%v config=%v", fake.options.CheckTime, fake.options.SendTest, fake.options.Config)
	}
}

func TestInteractiveInputStateMachineRetriesInvalidValues(t *testing.T) {
	input := strings.Join([]string{
		"9", "1",
		"25:00", "08:30",
		"9", "3",
		"0", "abc", "5",
		"maybe", "n",
	}, "\n") + "\n"
	command, fake, _, stderr := newInstallTestCommand(t, nil, input, nil)
	fake.token = "123:token"
	code := command.run([]string{
		"--lang", "zh", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100", "--skip-telegram-test",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fake.options.Config["NOTIFY_CHANNELS"] != "telegram" || fake.options.CheckTime != "08:30" ||
		fake.options.Config["DEDUP_MODE"] != "interval" || fake.options.Config["DEDUP_INTERVAL_DAYS"] != "5" ||
		fake.options.SendTest {
		t.Fatalf("options=%+v", fake.options)
	}
	for _, want := range []string{"无效选择，请重新输入。", "时间无效", "请输入大于 0 的整数。", "请输入 y 或 n"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %q", want, stderr.String())
		}
	}
	for _, unwanted := range []string{"invalid receiving-platform choice", "invalid same-alert reminder mode", "expected y or n"} {
		if strings.Contains(stderr.String(), unwanted) {
			t.Errorf("Chinese interaction leaked %q: %q", unwanted, stderr.String())
		}
	}
}

func TestInteractiveRequiredAndHiddenInputsRetryWhenEmpty(t *testing.T) {
	command, fake, _, stderr := newInstallTestCommand(t, nil, "\n-100\n\n\nn\n", []string{"", "123:token"})
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "telegram", "--skip-telegram-test",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if fake.options.Config["TELEGRAM_BOT_TOKEN"] != "123:token" || fake.options.Config["TELEGRAM_CHAT_ID"] != "-100" {
		t.Fatalf("config=%v", fake.options.Config)
	}
	if got := strings.Count(stderr.String(), "输入不能为空，请重新输入。"); got != 2 {
		t.Fatalf("empty-input retries=%d stderr=%q", got, stderr.String())
	}
}

func TestInteractiveStateMachineSharesHiddenAndVisibleInputStream(t *testing.T) {
	input := strings.Join([]string{
		"", "123:token",
		"", "-100",
		"25:00", "08:30",
		"9", "3",
		"0", "5",
		"maybe", "n",
	}, "\n") + "\n"
	command, fake, stdout, stderr := newInstallTestCommand(t, nil, input, nil)
	command.console.readSecret = func(prompt string) (string, error) {
		if _, err := fmt.Fprint(command.console.out, prompt); err != nil {
			return "", err
		}
		return command.console.in.ReadString('\n')
	}
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "telegram",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if fake.options.Config["TELEGRAM_BOT_TOKEN"] != "123:token" || fake.options.Config["TELEGRAM_CHAT_ID"] != "-100" ||
		fake.options.CheckTime != "08:30" || fake.options.Config["DEDUP_MODE"] != "interval" ||
		fake.options.Config["DEDUP_INTERVAL_DAYS"] != "5" || fake.options.SendTest {
		t.Fatalf("options=%+v", fake.options)
	}
	for _, want := range []string{"输入隐藏", "输入不能为空", "时间无效", "无效选择", "大于 0", "输入 y 或 n"} {
		combined := stdout.String() + stderr.String()
		if !strings.Contains(combined, want) {
			t.Errorf("interaction output missing %q: %q", want, combined)
		}
	}
}

func TestInteractiveEOFIsLocalizedCancellation(t *testing.T) {
	command, fake, _, stderr := newInstallTestCommand(t, nil, "", nil)
	code := command.run([]string{"--lang", "zh"}, false)
	if code != 2 || fake.installCalls != 0 {
		t.Fatalf("code=%d installs=%d stderr=%q", code, fake.installCalls, stderr.String())
	}
	if !strings.Contains(stderr.String(), "已取消。") || strings.Contains(stderr.String(), "EOF") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestLanguageChoiceRetriesInvalidInput(t *testing.T) {
	command, _, _, stderr := newInstallTestCommand(t, nil, "9\n2\n", nil)
	lang, err := command.chooseLanguage("", false)
	if err != nil || lang != "en" {
		t.Fatalf("lang=%q err=%v", lang, err)
	}
	if !strings.Contains(stderr.String(), "无效选择，请重新输入。") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestSkipNotifyTestSuppressesFreshFeishuDefaultUnlessSendTestIsExplicit(t *testing.T) {
	for _, test := range []struct {
		name     string
		extra    []string
		wantSend bool
	}{
		{name: "skip", extra: []string{"--skip-notify-test"}},
		{name: "explicit send", extra: []string{"--skip-notify-test", "--send-test"}, wantSend: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
			fake.secret = []byte("app-secret")
			args := []string{
				"--lang", "zh", "--non-interactive", "-y", "--notify-channels", "feishu",
				"--feishu-app-id", "cli_new", "--feishu-app-secret-file", "/run/secret",
				"--feishu-receive-id", "ou_receiver",
			}
			args = append(args, test.extra...)
			if code := command.run(args, false); code != 0 {
				t.Fatalf("code=%d", code)
			}
			if fake.options.SendTest != test.wantSend {
				t.Fatalf("SendTest=%v, want %v", fake.options.SendTest, test.wantSend)
			}
			if fake.options.Preflight != nil {
				t.Fatal("skip-notify-test unexpectedly retained receiving-platform preflight")
			}
		})
	}
}

func TestFreshFeishuRecipientStrongVerificationStillBlocksOnFailure(t *testing.T) {
	feishuClient := &fakeFeishuPreflight{sendErr: errors.New("recipient unavailable")}
	command, fake, _, _ := newInstallTestCommand(t, nil, "\n\n\n", nil)
	command.feishu = feishuClient
	fake.secret = []byte("app-secret")
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "feishu", "--feishu-app-id", "cli_new",
		"--feishu-app-secret-file", "/run/secret", "--feishu-receive-id", "ou_receiver",
	}, false)
	if code != 2 || len(feishuClient.sendIDs) != 1 {
		t.Fatalf("code=%d send IDs=%v", code, feishuClient.sendIDs)
	}
}

func TestNonInteractiveFreshFeishuRecipientStrongVerificationStillBlocksOnFailure(t *testing.T) {
	feishuClient := &fakeFeishuPreflight{sendErr: errors.New("recipient unavailable")}
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.feishu = feishuClient
	fake.secret = []byte("app-secret")
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "-y", "--notify-channels", "feishu",
		"--feishu-app-id", "cli_new", "--feishu-app-secret-file", "/run/secret",
		"--feishu-receive-id", "ou_receiver",
	}, false)
	if code != 2 || len(feishuClient.sendIDs) != 1 || fake.installCalls != 1 {
		t.Fatalf("code=%d sends=%v installs=%d", code, feishuClient.sendIDs, fake.installCalls)
	}
}

func TestExplicitAllPlatformTestDoesNotWeakenFreshFeishuVerification(t *testing.T) {
	feishuClient := &fakeFeishuPreflight{sendErr: errors.New("recipient unavailable")}
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.feishu = feishuClient
	fake.secret = []byte("app-secret")
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "-y", "--notify-channels", "feishu",
		"--feishu-app-id", "cli_new", "--feishu-app-secret-file", "/run/secret",
		"--feishu-receive-id", "ou_receiver", "--send-test",
	}, false)
	if code != 2 || len(feishuClient.sendIDs) != 1 {
		t.Fatalf("code=%d send IDs=%v", code, feishuClient.sendIDs)
	}
}

func TestExplicitAdditionalTestFailureIsAdvisoryToCLI(t *testing.T) {
	command, fake, _, stderr := newInstallTestCommand(t, nil, "", nil)
	fake.token = "123:token"
	fake.result.PostInstallTest = &installer.CommandResult{
		Stderr: []byte("delivery detail\n"), Code: 75, Err: context.DeadlineExceeded,
	}
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "-y", "--notify-channels", "telegram",
		"--telegram-token-file", "/run/token", "--telegram-chat-id", "-100",
		"--skip-notify-test", "--send-test",
	}, false)
	if code != 0 || fake.installCalls != 1 {
		t.Fatalf("code=%d installs=%d", code, fake.installCalls)
	}
	for _, want := range []string{"delivery detail", "额外测试消息无法完成", "核心安装和定时任务未回滚"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing %q: %q", want, stderr.String())
		}
	}
}

func TestTelegramTemporaryFailureSkipKeepsUnverifiedInput(t *testing.T) {
	telegramClient := &fakeTelegramPreflight{getMeErrors: []error{temporaryTestError{"connection reset"}}}
	command, fake, stdout, _ := newInstallTestCommand(t, nil, "\n\nn\n2\n", nil)
	command.telegram = telegramClient
	fake.token = "123:token"
	code := command.run([]string{
		"--lang", "zh", "--notify-channels", "telegram", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100",
	}, false)
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), "保留当前输入，但尚未验证") || strings.Contains(stdout.String(), "凭据保持不变") {
		t.Fatalf("stdout=%q", stdout.String())
	}
}

func TestNonInteractiveTelegramTemporaryFailureReturns75WithoutCredentialPrompt(t *testing.T) {
	telegramClient := &fakeTelegramPreflight{getMeErrors: []error{temporaryTestError{"connection reset"}}}
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.telegram = telegramClient
	fake.token = "123:unchanged"
	prompted := false
	command.console.readSecret = func(string) (string, error) { prompted = true; return "", nil }
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "--notify-channels", "telegram",
		"--telegram-token-file", "/run/token", "--telegram-chat-id", "-100",
	}, false)
	if code != 75 || prompted {
		t.Fatalf("code=%d prompted=%v", code, prompted)
	}
	if got := fake.prepared.Config["TELEGRAM_BOT_TOKEN"]; got != "123:unchanged" {
		t.Fatalf("token changed to %q", got)
	}
}

func TestNonInteractiveFeishuTemporaryFailureReturns75(t *testing.T) {
	feishuClient := &fakeFeishuPreflight{probeErrs: []error{temporaryTestError{"connection reset"}}}
	command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.feishu = feishuClient
	fake.secret = []byte("app-secret")
	code := command.run([]string{
		"--lang", "zh", "--non-interactive", "--notify-channels", "feishu",
		"--feishu-app-id", "cli_new", "--feishu-app-secret-file", "/run/secret",
		"--feishu-receive-id", "ou_receiver",
	}, false)
	if code != 75 {
		t.Fatalf("code=%d, want 75", code)
	}
}

func TestInstallPropagatesStableInstallerExitCodes(t *testing.T) {
	for _, test := range []struct {
		name string
		code int
	}{{"failure", 1}, {"invalid", 2}, {"temporary", 75}} {
		t.Run(test.name, func(t *testing.T) {
			command, fake, _, _ := newInstallTestCommand(t, nil, "", nil)
			fake.token = "123:token"
			fake.err = &installer.ExitError{Code: test.code, Op: "test", Err: errors.New("failure")}
			got := command.run([]string{
				"--lang", "zh", "--non-interactive", "-y", "--notify-channels", "telegram",
				"--telegram-token-file", "/run/token", "--telegram-chat-id", "-100", "--skip-telegram-test",
			}, false)
			if got != test.code {
				t.Fatalf("exit code=%d, want %d", got, test.code)
			}
		})
	}
}

func TestReadHiddenLineFallsBackForPipe(t *testing.T) {
	readFile, writeFile, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readFile.Close()
	if _, err := writeFile.WriteString("secret\n"); err != nil {
		t.Fatal(err)
	}
	_ = writeFile.Close()
	var output bytes.Buffer
	got, err := readHiddenLine(readFile, bufio.NewReader(readFile), &output, "Secret: ")
	if err != nil || got != "secret\n" || output.String() != "Secret: " {
		t.Fatalf("got=%q err=%v output=%q", got, err, output.String())
	}
}

func TestPromptSecretAcceptsFinalLineAtEOF(t *testing.T) {
	command, _, _, _ := newInstallTestCommand(t, nil, "", nil)
	command.console.readSecret = func(string) (string, error) { return "secret-without-newline", io.EOF }
	value, err := command.promptSecret("zh", "Secret")
	if err != nil || value != "secret-without-newline" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}

func TestPromptSecretLocalizesUnderlyingReadError(t *testing.T) {
	command, _, _, _ := newInstallTestCommand(t, nil, "", nil)
	underlying := errors.New("low-level English input failure")
	command.console.readSecret = func(string) (string, error) { return "", underlying }
	_, err := command.promptSecret("zh", "Secret")
	if err == nil || err.Error() != "读取输入失败。" || !errors.Is(err, underlying) {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), underlying.Error()) {
		t.Fatalf("localized error leaked underlying message: %q", err)
	}
}

func TestCurrentExecutableReadsRunningInode(t *testing.T) {
	payload, err := currentExecutable()
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) < 4 || !bytes.Equal(payload[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		t.Fatalf("running payload is not ELF: %x", payload[:min(len(payload), 4)])
	}
}

func TestInstallEnvCompatibilityAndSymlinkRejection(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "install.env")
	contents := strings.Join([]string{
		"CONFIG_VERSION=3",
		"HOST_LABEL = edge-1 # inline comment",
		`TELEGRAM_BOT_TOKEN="'123:abc'"`,
		"NOTIFY_OK=yes",
		"POST_INSTALL_CHECK=no",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed := installArguments{config: make(map[string]string)}
	command, _, _, _ := newInstallTestCommand(t, nil, "", nil)
	if err := command.loadInstallEnv(path, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.config["CONFIG_VERSION"] != "3" || parsed.config["HOST_LABEL"] != "edge-1" ||
		parsed.config["TELEGRAM_BOT_TOKEN"] != "123:abc" || parsed.config["NOTIFY_OK"] != "yes" ||
		!parsed.skipPostInstallCheck {
		t.Fatalf("parsed env=%v skipPostInstallCheck=%v", parsed.config, parsed.skipPostInstallCheck)
	}

	symlink := filepath.Join(directory, "install-link.env")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if err := command.loadInstallEnv(symlink, &installArguments{config: make(map[string]string)}); err == nil {
		t.Fatal("symlinked env file was accepted")
	}

	realDirectory := filepath.Join(directory, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDirectory, "nested.env"), []byte("CONFIG_VERSION=4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(directory, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Fatal(err)
	}
	if err := command.loadInstallEnv(filepath.Join(linkedDirectory, "nested.env"), &installArguments{config: make(map[string]string)}); err == nil {
		t.Fatal("env file below a symlinked ancestor was accepted")
	}
}

func newInstallTestCommand(t *testing.T, values map[string]string, input string, secrets []string) (*installCommand, *fakeInstallerAPI, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	cfg := testConfig(t, values)
	fake := &fakeInstallerAPI{baseConfig: cloneCLIConfig(values)}
	var stdout, stderr bytes.Buffer
	secretIndex := 0
	command := &installCommand{
		console: installConsole{
			in: bufio.NewReader(strings.NewReader(input)), out: &stdout, errOut: &stderr,
			readSecret: func(string) (string, error) {
				if secretIndex >= len(secrets) {
					return "", errors.New("unexpected secret prompt")
				}
				secret := secrets[secretIndex]
				secretIndex++
				return secret, nil
			},
		},
		newInstaller: func() (installerAPI, error) { return fake, nil },
		readRuntime:  func() ([]byte, error) { return []byte("runtime"), nil },
		loadConfig:   func(string) (*config.Config, error) { return cfg, nil },
		effectiveUID: func() int { return 0 },
		telegram:     &fakeTelegramPreflight{},
		feishu:       &fakeFeishuPreflight{},
		hostname:     func() (string, error) { return "test-host", nil },
	}
	return command, fake, &stdout, &stderr
}

func testConfig(t *testing.T, values map[string]string) *config.Config {
	t.Helper()
	if len(values) == 0 {
		cfg, err := config.Load(filepath.Join(t.TempDir(), "missing"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	var rendered bytes.Buffer
	if err := config.Write(&rendered, values); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "telegram.env")
	if err := os.WriteFile(path, rendered.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

package installer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	configpkg "github.com/xxvcc/security-update-notify/internal/config"
)

// existingTelegramConfig is the on-disk state of a working Telegram
// installation, so an Install that passes no overrides at all still has a
// complete and valid configuration to inherit.
func existingTelegramConfig() map[string]string {
	values := cloneConfig(configDefaults)
	values["NOTIFY_CHANNELS"] = "telegram"
	values["TELEGRAM_BOT_TOKEN"] = "123456:old_token"
	values["TELEGRAM_CHAT_ID"] = "-100123"
	values["BACKEND"] = "apt"
	return values
}

// seedNestedQuoteHostLabel writes a telegram.env whose HOST_LABEL carries two
// nested single-quote layers, the shape the wire format cannot store. The
// writer refuses to emit exactly that value, which is the point, so the line is
// spliced into an otherwise rendered file the way a hand-edited host config or
// an older release would have left it behind.
func seedNestedQuoteHostLabel(t *testing.T, root *RootFS) string {
	t.Helper()
	writeConfig(t, root, existingTelegramConfig())
	rendered := readFile(t, root, ConfigPath)
	seeded := strings.Replace(rendered, "HOST_LABEL=''\n", "HOST_LABEL=''x''\n", 1)
	if seeded == rendered {
		t.Fatalf("config fixture has no empty HOST_LABEL line to replace:\n%s", rendered)
	}
	if err := root.WriteFileAtomic(ConfigPath, []byte(seeded), 0o600); err != nil {
		t.Fatal(err)
	}
	return seeded
}

// readInstalledConfigValue reads the installed file back through the runtime
// reader, so the assertion is about what a later run actually observes rather
// than about the bytes the installer intended to write.
func readInstalledConfigValue(t *testing.T, root *RootFS, key string) string {
	t.Helper()
	loaded, err := configpkg.Load(filepath.Join(root.Root, strings.TrimPrefix(ConfigPath, "/")))
	if err != nil {
		t.Fatal(err)
	}
	return loaded.Get(key)
}

func TestUpgradeInheritingNestedQuoteConfigValueSucceedsAndConvergesToAFixedPoint(t *testing.T) {
	installer, root, runner, locker := setupInstaller(t, "ID=debian\nVERSION_ID=13\nPRETTY_NAME=Debian 13\n")
	seedNestedQuoteHostLabel(t, root)
	options := Options{Payload: Payload{Runtime: []byte("new-runtime")}, SkipPostInstallCheck: true}

	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("unattended upgrade was bricked by an inherited unrepresentable value: %v", err)
	}
	first := readFile(t, root, ConfigPath)
	if !strings.Contains(first, "HOST_LABEL='x'\n") {
		t.Fatalf("upgrade did not store the canonical host label:\n%s", first)
	}
	if got := readInstalledConfigValue(t, root, "HOST_LABEL"); got != "x" {
		t.Fatalf("installed host label reads back as %q, want %q", got, "x")
	}

	// The rewritten file is only safe if it is a fixed point: the value it now
	// stores has to survive the next upgrade's inherit-and-rewrite round trip
	// unchanged, instead of shedding another quote layer each time.
	second := freshTestInstaller(t, root, runner, locker)
	if _, err := second.Install(context.Background(), options); err != nil {
		t.Fatalf("second upgrade of the canonicalized config failed: %v", err)
	}
	if repeated := readFile(t, root, ConfigPath); repeated != first {
		t.Fatalf("second upgrade rewrote the config:\nfirst:\n%s\nsecond:\n%s", first, repeated)
	}
	if got := readInstalledConfigValue(t, root, "HOST_LABEL"); got != "x" {
		t.Fatalf("host label after the second upgrade reads back as %q, want %q", got, "x")
	}
}

func TestExplicitlySuppliedNestedQuoteConfigValueIsRejectedBeforeAnyHostMutation(t *testing.T) {
	installer, root, runner, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	writeConfig(t, root, existingTelegramConfig())
	original := readFile(t, root, ConfigPath)
	options := telegramOptions()
	options.Config["HOST_LABEL"] = "'x'"
	options.SkipPostInstallCheck = true

	_, err := installer.Install(context.Background(), options)
	if ExitCode(err) != 2 || !strings.Contains(err.Error(), "cannot be represented") {
		t.Fatalf("unrepresentable host label exit=%d err=%v", ExitCode(err), err)
	}
	if existsNoErr(root, BackupRoot) || existsNoErr(root, BinaryPath) {
		t.Fatalf("rejected request mutated the host: backup=%t binary=%t",
			existsNoErr(root, BackupRoot), existsNoErr(root, BinaryPath))
	}
	if got := readFile(t, root, ConfigPath); got != original {
		t.Fatalf("rejected request changed the existing config:\n%s", got)
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "apt-get ") || strings.HasPrefix(command, "dpkg ") ||
			strings.HasPrefix(command, "systemctl enable ") || strings.HasPrefix(command, "systemctl stop ") {
			t.Fatalf("rejected request ran a mutating host command: %s", command)
		}
	}
}

func TestExplicitlySuppliedNestedQuoteValueIsRejectedForKeysWithoutFormatValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		key  string
	}{
		{name: "public IP", key: "PUBLIC_IP"},
		{name: "Telegram chat", key: "TELEGRAM_CHAT_ID"},
		{name: "Feishu app", key: "FEISHU_APP_ID"},
	} {
		t.Run(test.name, func(t *testing.T) {
			installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
			writeConfig(t, root, existingTelegramConfig())
			original := readFile(t, root, ConfigPath)
			options := telegramOptions()
			options.Config[test.key] = "'x'"
			options.SkipPostInstallCheck = true

			_, err := installer.Install(context.Background(), options)
			if ExitCode(err) != 2 || !strings.Contains(err.Error(), "cannot be represented") ||
				!strings.Contains(err.Error(), test.key) {
				t.Fatalf("unrepresentable %s exit=%d err=%v", test.key, ExitCode(err), err)
			}
			if existsNoErr(root, BackupRoot) || existsNoErr(root, BinaryPath) {
				t.Fatalf("rejected %s mutated the host: backup=%t binary=%t", test.key,
					existsNoErr(root, BackupRoot), existsNoErr(root, BinaryPath))
			}
			if got := readFile(t, root, ConfigPath); got != original {
				t.Fatalf("rejected %s changed the existing config:\n%s", test.key, got)
			}
		})
	}
}

func TestConfigValueContainingASingleQuoteStillInstallsAndRoundTripsExactly(t *testing.T) {
	installer, root, _, _ := setupInstaller(t, "ID=debian\nVERSION_ID=13\n")
	const label = "it's-a-host"
	options := telegramOptions()
	options.Config["HOST_LABEL"] = label
	options.SkipPostInstallCheck = true

	if _, err := installer.Install(context.Background(), options); err != nil {
		t.Fatalf("representable host label was rejected: %v", err)
	}
	if got := readFile(t, root, ConfigPath); !strings.Contains(got, `HOST_LABEL="`+label+`"`+"\n") {
		t.Fatalf("host label was not stored double-quoted:\n%s", got)
	}
	if got := readInstalledConfigValue(t, root, "HOST_LABEL"); got != label {
		t.Fatalf("installed host label reads back as %q, want %q", got, label)
	}
}

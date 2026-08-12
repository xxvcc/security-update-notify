package cli

import (
	"strings"
	"testing"
)

func TestInstallReportsInstallerWarningsWithoutChangingSuccess(t *testing.T) {
	command, fake, _, stderr := newInstallTestCommand(t, nil, "", nil)
	fake.token = "123:token"
	fake.result.Warnings = []string{"command alias /usr/local/sbin/sun was preserved\nspoof"}
	code := command.run([]string{
		"--lang", "en", "--non-interactive", "-y",
		"--notify-channels", "telegram", "--telegram-token-file", "/run/token",
		"--telegram-chat-id", "-100123", "--skip-telegram-test", "--skip-post-install-check",
	}, false)
	if code != 0 {
		t.Fatalf("warning changed install exit code to %d", code)
	}
	if got := stderr.String(); !strings.Contains(got, "Warning: command alias /usr/local/sbin/sun was preserved spoof") || strings.Contains(got, "\nspoof") {
		t.Fatalf("warning output = %q", got)
	}
}

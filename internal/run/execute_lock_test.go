package run

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	runlock "github.com/xxvcc/security-update-notify/internal/lock"
)

func TestAcquireExecutionLockSuccessAndFilesystemError(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "notify.lock")
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", lockPath)
	release, acquired, exitCode := AcquireExecutionLock(false, 0)
	if !acquired || exitCode != 0 || release == nil {
		t.Fatalf("successful lock: acquired=%v exit=%d releaseNil=%v", acquired, exitCode, release == nil)
	}
	release()

	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("marker"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", filepath.Join(parentFile, "notify.lock"))
	if release, acquired, exitCode := AcquireExecutionLock(false, 0); release != nil || acquired || exitCode != 1 {
		t.Fatalf("failed lock: acquired=%v exit=%d releaseNil=%v", acquired, exitCode, release == nil)
	}
}

func TestExecuteRejectsInvalidChannelsBeforeCollection(t *testing.T) {
	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=unsupported\n")
	if got := Execute(cfg, DryRunFlags{LockHeld: true}); got != 2 {
		t.Fatalf("Execute()=%d want 2", got)
	}
}

func TestExecuteDryRunDoesNotCreateState(t *testing.T) {
	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", "exit 0\n")
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-dry-run'\n")
	t.Setenv("PATH", dir)
	stateDir := filepath.Join(t.TempDir(), "state")
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", stateDir)
	cfg := loadDeliveryConfig(t, "BACKEND=dnf\nHOST_LABEL=dry-host\nINCLUDE_PUBLIC_IP=0\nCHECK_UPDATE_HEALTH=0\nCHECK_EOL=0\nCHECK_SELF_UPDATE=0\n")

	if got := Execute(cfg, DryRunFlags{DryRun: true, Flags: Flags{TestReboot: true}}); got != 0 {
		t.Fatalf("Execute(dry-run)=%d", got)
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("dry-run created state directory: %v", err)
	}
}

func TestExecuteTelegramNetworkOutcome(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body       string
		wantCode   int
		wantStored bool
	}{
		{name: "success", status: http.StatusOK, body: `{"ok":true}`, wantCode: 0, wantStored: true},
		{name: "remote rejection", status: http.StatusBadRequest, body: `{"ok":false,"description":"rejected"}`, wantCode: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if !strings.HasSuffix(r.URL.Path, "/sendMessage") {
					t.Errorf("request path=%q", r.URL.Path)
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			dir := t.TempDir()
			writeTestCommand(t, dir, "dnf", "exit 0\n")
			writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-execute'\n")
			t.Setenv("PATH", dir)
			stateDir := t.TempDir()
			t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", stateDir)
			t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(t.TempDir(), "notify.log"))
			t.Setenv(telegramBaseURLEnv, server.URL)
			cfg := loadDeliveryConfig(t, strings.Join([]string{
				"NOTIFY_CHANNELS=telegram",
				"TELEGRAM_BOT_TOKEN=123456:test_token",
				"TELEGRAM_CHAT_ID=-100123",
				"BACKEND=dnf",
				"HOST_LABEL=execute-host",
				"INCLUDE_PUBLIC_IP=0",
				"CHECK_UPDATE_HEALTH=0",
				"CHECK_EOL=0",
				"CHECK_SELF_UPDATE=0",
				"DEDUP_MODE=once",
			}, "\n")+"\n")

			if got := Execute(cfg, DryRunFlags{LockHeld: true, Flags: Flags{TestReboot: true}}); got != test.wantCode {
				t.Fatalf("Execute()=%d want %d", got, test.wantCode)
			}
			if requests != 1 {
				t.Fatalf("requests=%d want 1", requests)
			}
			for _, name := range []string{"last-alert.sha256", "last-alert.sent_at"} {
				_, err := os.Stat(filepath.Join(stateDir, name))
				if test.wantStored && err != nil {
					t.Fatalf("successful send state %s missing: %v", name, err)
				}
				if !test.wantStored && !os.IsNotExist(err) {
					t.Fatalf("failed send persisted state %s: %v", name, err)
				}
			}
		})
	}
}

func TestExecuteMakesRequiredLockContentionExplicit(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "notify.lock")
	release, acquired, err := runlock.Acquire(lockPath)
	if err != nil || !acquired {
		t.Fatalf("hold lock: acquired=%v err=%v", acquired, err)
	}
	defer release()
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", lockPath)
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", t.TempDir())

	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=feishu\n")
	if got := Execute(cfg, DryRunFlags{}); got != 0 {
		t.Fatalf("default lock contention exit=%d want 0", got)
	}
	if got := Execute(cfg, DryRunFlags{RequireLock: true}); got != 75 {
		t.Fatalf("required lock contention exit=%d want 75", got)
	}
}

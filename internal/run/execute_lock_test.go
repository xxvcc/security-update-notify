package run

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	runlock "github.com/xxvcc/security-update-notify/internal/lock"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
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

func TestAcquireExecutionLockAdoptsValidatedInheritedDescriptor(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "notify.lock")
	parent, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := syscall.Flock(int(parent.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(parent.Fd()), syscall.LOCK_UN)
	inheritedFD, err := syscall.Dup(int(parent.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", lockPath)
	t.Setenv(inheritedLockFDEnv, strconv.Itoa(inheritedFD))

	release, acquired, exitCode := AcquireExecutionLock(true, 0)
	if !acquired || exitCode != 0 || release == nil {
		t.Fatalf("inherited lock: acquired=%v exit=%d releaseNil=%v", acquired, exitCode, release == nil)
	}
	release()
	if otherRelease, otherAcquired, err := runlock.Acquire(lockPath); err != nil || otherAcquired || otherRelease != nil {
		t.Fatalf("parent lock was released by child: release=%v acquired=%v err=%v", otherRelease != nil, otherAcquired, err)
	}
}

func TestAcquireExecutionLockAdoptsDescriptorAcrossExec(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "notify.lock")
	parent, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := syscall.Flock(int(parent.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(parent.Fd()), syscall.LOCK_UN)

	cmd := exec.Command(os.Args[0], "-test.run=^TestAcquireExecutionLockExecHelper$")
	env := envWithOverride(os.Environ(), "SUN_INHERITED_LOCK_EXEC_HELPER", "1")
	env = envWithOverride(env, "SECURITY_UPDATE_NOTIFY_LOCK_FILE", lockPath)
	env = envWithOverride(env, inheritedLockFDEnv, "3")
	cmd.Env = env
	cmd.ExtraFiles = []*os.File{parent}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("inherited-lock helper: %v\n%s", err, output)
	}
	if release, acquired, err := runlock.Acquire(lockPath); err != nil || acquired || release != nil {
		t.Fatalf("child close released parent lock: release=%v acquired=%v err=%v", release != nil, acquired, err)
	}
}

func TestAcquireExecutionLockExecHelper(t *testing.T) {
	if os.Getenv("SUN_INHERITED_LOCK_EXEC_HELPER") != "1" {
		return
	}
	release, acquired, exitCode := AcquireExecutionLock(true, 0)
	if !acquired || exitCode != 0 || release == nil {
		t.Fatalf("exec-inherited lock: acquired=%v exit=%d releaseNil=%v", acquired, exitCode, release == nil)
	}
	release()
}

func TestAcquireExecutionLockRejectsMalformedInheritedDescriptor(t *testing.T) {
	for _, value := range []string{"", "2", "+3", "03", "1025", "invalid"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(inheritedLockFDEnv, value)
			if release, acquired, exitCode := AcquireExecutionLock(false, 0); release != nil || acquired || exitCode != 1 {
				t.Fatalf("descriptor %q: release=%v acquired=%v exit=%d", value, release != nil, acquired, exitCode)
			}
		})
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

func TestRenderDryRunSanitizesTerminalControls(t *testing.T) {
	got := renderDryRun(Output{Send: true, Message: "first\nsecond\tvalue\r\x1b[31m\u202Espoof\u2069"})
	if !strings.HasPrefix(got, "HASH\t") || !strings.Contains(got, "\nfirst\nsecond\tvalue") {
		t.Fatalf("dry-run output lost its stable framing: %q", got)
	}
	for _, forbidden := range []string{"\r", "\x1b", "\u202e", "\u2069"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("dry-run output retained display control %q: %q", forbidden, got)
		}
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

func TestAlertLogLineSeparatesHealthPatchAndUpdateReasons(t *testing.T) {
	for _, test := range []struct {
		name  string
		input Input
		want  string
	}{
		{name: "health", input: Input{Health: watchdog.Health{Attention: true}}, want: "health=1 patch=0 update=0"},
		{name: "patch", input: Input{Patch: watchdog.Patch{RiskAttention: true}}, want: "health=0 patch=1 update=0"},
		{name: "update", input: Input{Patch: watchdog.Patch{UpdateAvailable: true}}, want: "health=0 patch=0 update=1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			line := alertLogLine(test.input)
			if !strings.Contains(line, test.want) {
				t.Fatalf("alert log %q does not contain %q", line, test.want)
			}
		})
	}
}

// A stale-patch alert can fire while CHECK_UPDATE_HEALTH=0. The integration path must preserve the
// distinct source fields instead of emitting an alert line with no stated reason.
func TestExecuteAlertLogReportsPatchAttention(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	writeTestCommand(t, dir, "dnf", `
if [ "$*" = "--version" ]; then
  printf '%s\n' '4.14.0'
  exit 0
fi
printf '%s\n' 'RHSA-2026:0001 Important/Sec. openssl.x86_64'
exit 0
`)
	writeTestCommand(t, dir, "uname", "printf '%s\\n' '6.12-merged'\n")
	t.Setenv("PATH", dir)

	stateDir := t.TempDir()
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", stateDir)
	// Pending security updates first seen 30 days ago, well past the 3-day default threshold.
	stale := time.Now().Unix() - 30*86400
	if err := os.WriteFile(filepath.Join(stateDir, "pending-security.first_seen"),
		[]byte(strconv.FormatInt(stale, 10)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "notify.log")
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", logPath)
	t.Setenv(telegramBaseURLEnv, server.URL)

	cfg := loadDeliveryConfig(t, strings.Join([]string{
		"NOTIFY_CHANNELS=telegram",
		"TELEGRAM_BOT_TOKEN=123456:test_token",
		"TELEGRAM_CHAT_ID=-100123",
		"BACKEND=dnf",
		"HOST_LABEL=merged-host",
		"INCLUDE_PUBLIC_IP=0",
		"CHECK_UPDATE_HEALTH=0",
		"CHECK_EOL=0",
		"CHECK_SELF_UPDATE=0",
		"DEDUP_MODE=once",
	}, "\n")+"\n")

	if got := Execute(cfg, DryRunFlags{LockHeld: true}); got != 0 {
		t.Fatalf("Execute()=%d want 0", got)
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	alert := ""
	for _, line := range strings.Split(string(b), "\n") {
		if strings.Contains(line, " alert backend=") {
			alert = line
		}
	}
	if alert == "" {
		t.Fatalf("no alert line was logged:\n%s", b)
	}
	if !strings.Contains(alert, "health=0 patch=1 update=0") {
		t.Fatalf("alert line does not report the patch attention flag: %q", alert)
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

func TestExecuteRejectsSymlinkedStateDirectoryBeforeCollection(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", link)
	cfg := loadDeliveryConfig(t, "NOTIFY_CHANNELS=telegram\n")
	if got := Execute(cfg, DryRunFlags{LockHeld: true}); got != 1 {
		t.Fatalf("Execute()=%d want 1", got)
	}
}

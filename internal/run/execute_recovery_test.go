package run

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xxvcc/security-update-notify/internal/config"
)

type recoveryFixture struct {
	cfg          *config.Config
	telegram     atomic.Int32
	feishu       atomic.Int32
	failTelegram atomic.Bool
	failFeishu   atomic.Bool
}

func newRecoveryFixture(t *testing.T, notifyOK bool) *recoveryFixture {
	t.Helper()
	dir := t.TempDir()
	commands := filepath.Join(dir, "commands")
	if err := os.Mkdir(commands, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestCommand(t, commands, "dnf", `
if [ "$1" = "--version" ]; then echo 4.22.0; exit 0; fi
if [ "$SUN_RECOVERY_QUERY_FAIL" = "1" ]; then exit 1; fi
`)
	writeTestCommand(t, commands, "uname", "echo fixture-kernel\n")
	writeTestCommand(t, commands, "needs-restarting", `
case "$1" in
 --help) echo '-s --services' ;;
 -s) ;;
 -r)
  if [ "$SUN_RECOVERY_REBOOT" = "1" ]; then
   echo 'Reboot is required to fully utilize these updates.'; exit 1
  fi
  echo 'Reboot should not be necessary.' ;;
 *) exit 2 ;;
esac
`)
	t.Setenv("SUN_RECOVERY_REBOOT", "1")
	t.Setenv("SUN_RECOVERY_QUERY_FAIL", "0")
	t.Setenv("SECURITY_UPDATE_NOTIFY_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOCK_FILE", filepath.Join(dir, "lock"))
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(dir, "log"))
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("fixture-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(feishuSecretFileEnv, secret)
	f := &recoveryFixture{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "tenant_access_token"):
			_, _ = w.Write([]byte(`{"code":0,"tenant_access_token":"fixture-token"}`))
		case strings.Contains(r.URL.Path, "sendMessage"):
			f.telegram.Add(1)
			if f.failTelegram.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			f.feishu.Add(1)
			if f.failFeishu.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			_, _ = w.Write([]byte(`{"code":0}`))
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv(telegramBaseURLEnv, server.URL)
	t.Setenv(feishuBaseURLEnv, server.URL)
	okValue := "0"
	if notifyOK {
		okValue = "1"
	}
	f.cfg = loadDeliveryConfig(t, "BACKEND=dnf\nHOST_LABEL=fixture\nNOTIFY_CHANNELS=telegram,feishu\n"+
		"TELEGRAM_BOT_TOKEN=123:fixture\nTELEGRAM_CHAT_ID=-100\nFEISHU_APP_ID=cli_fixture\nFEISHU_RECEIVE_ID=ou_fixture\n"+
		"CHECK_UPDATE_HEALTH=0\nCHECK_SELF_UPDATE=0\nCHECK_EOL=0\nINCLUDE_PUBLIC_IP=0\nDEDUP_MODE=once\nNOTIFY_OK="+okValue+"\n")
	return f
}

func TestExecuteOnceResendsRecurrenceIndependentlyForEachChannel(t *testing.T) {
	f := newRecoveryFixture(t, false)
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
		t.Fatalf("initial alert exit=%d", rc)
	}
	t.Setenv("SUN_RECOVERY_REBOOT", "0")
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
		t.Fatalf("healthy observation exit=%d", rc)
	}
	for _, channel := range []string{"telegram", "feishu"} {
		if _, err := os.Stat(channelStore(channel).TargetPendingFile); err != nil {
			t.Fatalf("%s recovery not persisted: %v", channel, err)
		}
	}
	if f.telegram.Load() != 1 || f.feishu.Load() != 1 {
		t.Fatal("healthy observation sent an unwanted message")
	}
	t.Setenv("SUN_RECOVERY_REBOOT", "1")
	f.failFeishu.Store(true)
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 1 {
		t.Fatalf("partial recurrence exit=%d", rc)
	}
	f.failFeishu.Store(false)
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
		t.Fatalf("retry exit=%d", rc)
	}
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
		t.Fatalf("unchanged alert exit=%d", rc)
	}
	if f.telegram.Load() != 2 || f.feishu.Load() != 3 {
		t.Fatalf("recurrence or partial retry counts=%d,%d want 2,3", f.telegram.Load(), f.feishu.Load())
	}
}

func TestExecuteUnknownOrDryRunDoesNotCloseAnAlertEpisode(t *testing.T) {
	for _, scenario := range []string{"unknown package query", "dry run"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRecoveryFixture(t, false)
			if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
				t.Fatalf("initial exit=%d", rc)
			}
			t.Setenv("SUN_RECOVERY_REBOOT", "0")
			flags := DryRunFlags{}
			if scenario == "dry run" {
				flags.DryRun = true
			} else {
				t.Setenv("SUN_RECOVERY_QUERY_FAIL", "1")
			}
			if rc := Execute(f.cfg, flags); rc != 0 {
				t.Fatalf("unconfirmed recovery exit=%d", rc)
			}
			for _, channel := range []string{"telegram", "feishu"} {
				if _, err := os.Stat(channelStore(channel).TargetPendingFile); !os.IsNotExist(err) {
					t.Fatalf("%s unconfirmed recovery changed pending state: %v", channel, err)
				}
			}
			t.Setenv("SUN_RECOVERY_QUERY_FAIL", "0")
			t.Setenv("SUN_RECOVERY_REBOOT", "1")
			if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
				t.Fatalf("unchanged episode exit=%d", rc)
			}
			if f.telegram.Load() != 1 || f.feishu.Load() != 1 {
				t.Fatalf("unconfirmed recovery reopened episode: %d,%d", f.telegram.Load(), f.feishu.Load())
			}
		})
	}
}

func TestExecuteRecoverySurvivesFailedOKAndDoesNotRepeatSuccessfulOK(t *testing.T) {
	f := newRecoveryFixture(t, true)
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
		t.Fatalf("initial exit=%d", rc)
	}
	t.Setenv("SUN_RECOVERY_REBOOT", "0")
	f.failTelegram.Store(true)
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 1 {
		t.Fatalf("partially failed OK exit=%d", rc)
	}
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 1 {
		t.Fatalf("OK retry exit=%d", rc)
	}
	if f.feishu.Load() != 2 {
		t.Fatalf("successful OK was repeated: %d", f.feishu.Load())
	}
	f.failTelegram.Store(false)
	t.Setenv("SUN_RECOVERY_REBOOT", "1")
	if rc := Execute(f.cfg, DryRunFlags{}); rc != 0 {
		t.Fatalf("recurrence after failed OK exit=%d", rc)
	}
	if f.telegram.Load() != 4 || f.feishu.Load() != 3 {
		t.Fatalf("failed OK lost recovery: %d,%d want 4,3", f.telegram.Load(), f.feishu.Load())
	}
}

package systemd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xxvcc/security-update-notify/internal/sysexec"
)

func TestSystemctlQueriesHonorExitStatus(t *testing.T) {
	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	stub := `#!/bin/sh
case "$1:$2:$3" in
  is-enabled:enabled.service:) printf 'enabled\n'; exit 0 ;;
  is-enabled:runtime.service:) printf 'enabled-runtime\n'; exit 0 ;;
  is-enabled:static.service:) printf 'static\n'; exit 0 ;;
  is-enabled:alias.service:) printf 'alias\n'; exit 0 ;;
  is-enabled:disabled.service:) printf 'disabled\n'; exit 1 ;;
  is-enabled:broken.service:) printf 'enabled\n'; exit 3 ;;
  show:healthy.service:-p) printf 'active\n\n'; exit 0 ;;
  show:failed.service:-p) printf 'stale-value\n'; exit 4 ;;
  *) exit 2 ;;
esac
`
	if err := os.WriteFile(systemctl, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isEnabledWithCommand(systemctl, "enabled.service", time.Second) ||
		!isEnabledWithCommand(systemctl, "runtime.service", time.Second) {
		t.Error("IsEnabled() rejected an enabled state")
	}
	for _, unit := range []string{"static.service", "alias.service", "disabled.service", "broken.service"} {
		if isEnabledWithCommand(systemctl, unit, time.Second) {
			t.Errorf("IsEnabled(%q)=true for a state that does not guarantee enablement", unit)
		}
	}
	if got, ok := showValueWithCommand(systemctl, "healthy.service", "ActiveState", time.Second); got != "active" || !ok {
		t.Fatalf("ShowValue()=%q,%v, want active,true", got, ok)
	}
	if got, ok := showValueWithCommand(systemctl, "failed.service", "ActiveState", time.Second); got != "" || ok {
		t.Fatalf("ShowValue() returned a successful value from failed systemctl: %q,%v", got, ok)
	}
}

func TestSystemctlCommandUnavailable(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-systemctl")
	if isEnabledWithCommand(missing, "missing.service", time.Second) {
		t.Fatal("IsEnabled()=true when systemctl cannot start")
	}
	if got, ok := showValueWithCommand(missing, "missing.service", "ActiveState", time.Second); got != "" || ok {
		t.Fatalf("ShowValue()=%q,%v when systemctl cannot start", got, ok)
	}
}

func TestPublicQueriesIgnoreCallerPATH(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "called")
	stub := filepath.Join(dir, "systemctl")
	script := "#!/bin/sh\ntouch '" + sentinel + "'\nprintf 'enabled\\n'\n"
	if err := os.WriteFile(stub, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if IsEnabled("security-update-notify-attacker-path-stub.service") {
		t.Fatal("caller PATH stub controlled IsEnabled")
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatalf("caller PATH stub executed: %v", err)
	}
}

func TestSystemctlQueriesRejectTruncatedOutput(t *testing.T) {
	for _, result := range []sysexec.Result{
		{Code: 0, Stdout: "enabled\n", StdoutTruncated: true},
		{Code: 0, Stdout: "enabled\n", StderrTruncated: true},
		{Code: 0, Stdout: "enabled\n", Stderr: "warning: incomplete query\n"},
	} {
		if completeSuccessfulResult(result) {
			t.Fatalf("truncated result was accepted: %+v", result)
		}
	}
}

func TestSystemctlQueriesTimeOut(t *testing.T) {
	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nexec /bin/sleep 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if isEnabledWithCommand(systemctl, "hung.service", 25*time.Millisecond) {
		t.Fatal("timed-out is-enabled query reported enabled")
	}
	if got, ok := showValueWithCommand(systemctl, "hung.service", "Result", 25*time.Millisecond); got != "" || ok {
		t.Fatalf("timed-out show query returned %q,%v", got, ok)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("systemctl queries took %s; timeout was not enforced", elapsed)
	}
}

package systemd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	t.Setenv("PATH", dir)

	if !Available() {
		t.Fatal("Available()=false with systemctl on PATH")
	}
	if !IsEnabled("enabled.service") || !IsEnabled("runtime.service") {
		t.Error("IsEnabled() rejected an enabled state")
	}
	for _, unit := range []string{"static.service", "alias.service", "disabled.service", "broken.service"} {
		if IsEnabled(unit) {
			t.Errorf("IsEnabled(%q)=true for a state that does not guarantee enablement", unit)
		}
	}
	if got := ShowValue("healthy.service", "ActiveState"); got != "active" {
		t.Fatalf("ShowValue()=%q, want active", got)
	}
	if got := ShowValue("failed.service", "ActiveState"); got != "" {
		t.Fatalf("ShowValue() returned stdout from failed systemctl: %q", got)
	}
}

func TestSystemctlUnavailable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if Available() {
		t.Fatal("Available()=true without systemctl on PATH")
	}
	if IsEnabled("missing.service") {
		t.Fatal("IsEnabled()=true when systemctl cannot start")
	}
	if got := ShowValue("missing.service", "ActiveState"); got != "" {
		t.Fatalf("ShowValue()=%q when systemctl cannot start", got)
	}
}

func TestSystemctlQueriesTimeOut(t *testing.T) {
	dir := t.TempDir()
	systemctl := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(systemctl, []byte("#!/bin/sh\nexec /bin/sleep 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	started := time.Now()
	if isEnabledWithTimeout("hung.service", 25*time.Millisecond) {
		t.Fatal("timed-out is-enabled query reported enabled")
	}
	if got := showValueWithTimeout("hung.service", "Result", 25*time.Millisecond); got != "" {
		t.Fatalf("timed-out show query returned %q", got)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("systemctl queries took %s; timeout was not enforced", elapsed)
	}
}

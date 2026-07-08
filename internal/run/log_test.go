package run

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// logEvent 必须以 Bash log_event 的格式追加（`YYYY-mm-dd HH:MM:SS ±ZZZZ <line>`）、以 0640 创建。
func TestLogEvent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sun.log")
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", logPath)

	logEvent("telegram sent backend=apt host=h reboot_required=1 restart_attention=1 hash=abc")
	logEvent("dedup suppressed backend=apt host=h mode=daily hash=abc")

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), b)
	}
	re := regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d [+-]\d{4} `)
	for _, ln := range lines {
		if !re.MatchString(ln) {
			t.Errorf("line missing timestamp prefix: %q", ln)
		}
	}
	if !strings.HasSuffix(lines[0], "telegram sent backend=apt host=h reboot_required=1 restart_attention=1 hash=abc") {
		t.Errorf("line 0 content: %q", lines[0])
	}
	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Errorf("log perm=%o want 0640", fi.Mode().Perm())
	}
}

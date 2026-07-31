package run

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestLogEventKeepsUntrustedTextOnOnePlainLine(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "sun.log")
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", logPath)

	logEvent("sent host=before\nforged\r\x1b[31mred\u202eafter\u2028next")
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("untrusted text created %d log records: %q", len(lines), b)
	}
	for _, forbidden := range []string{"\r", "\x1b", "\u202e", "\u2028"} {
		if strings.Contains(lines[0], forbidden) {
			t.Fatalf("log retained control/format character %q: %q", forbidden, lines[0])
		}
	}
	if !strings.Contains(lines[0], "host=before forged  [31mred after next") {
		t.Fatalf("unexpected sanitized log text: %q", lines[0])
	}
}

func TestLogEventDoesNotFollowSymlinksOrBlockOnFIFO(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", link)
	logEvent("must not be written")
	if got, err := os.ReadFile(target); err != nil || string(got) != "unchanged\n" {
		t.Fatalf("symlink target changed: %q err=%v", got, err)
	}

	fifo := filepath.Join(dir, "notify.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", fifo)
	done := make(chan struct{})
	go func() {
		logEvent("must not block")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("logEvent blocked on a FIFO")
	}
}

func TestLogEventRejectsUnsafeParentDirectory(t *testing.T) {
	root := t.TempDir()
	targetDir := filepath.Join(root, "target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDir := filepath.Join(root, "linked")
	if err := os.Symlink(targetDir, linkedDir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(linkedDir, "sun.log"))
	logEvent("must not be written")
	if _, err := os.Lstat(filepath.Join(targetDir, "sun.log")); !os.IsNotExist(err) {
		t.Fatalf("log was created through a symlinked parent: %v", err)
	}

	wideDir := filepath.Join(root, "wide")
	if err := os.Mkdir(wideDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wideDir, 0o770); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", filepath.Join(wideDir, "sun.log"))
	logEvent("must not be written")
	if _, err := os.Lstat(filepath.Join(wideDir, "sun.log")); !os.IsNotExist(err) {
		t.Fatalf("custom log was created in a group-writable parent: %v", err)
	}
}

func TestSharedLogPathIsLimitedToExactDefault(t *testing.T) {
	if !isSharedLogPath(defaultLogFile) {
		t.Fatal("default log path did not select the shared-directory policy")
	}
	for _, custom := range []string{
		"/var/log/custom.log",
		"/var/log/../var/log/security-update-notify.log",
		filepath.Join(t.TempDir(), "security-update-notify.log"),
	} {
		if isSharedLogPath(custom) {
			t.Fatalf("custom log %q selected the shared-directory policy", custom)
		}
	}
}

func TestLogEventWritesInsideTrustedGroupWritableDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "security-update-notify.log")
	logEventAtPath("shared parent append", path, os.Geteuid(), true)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), " shared parent append\n") {
		t.Fatalf("unexpected shared-parent log data: %q", data)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("shared-parent log mode = %04o, want 0640", info.Mode().Perm())
	}
}

func TestLogEventSkipsUnsafeMetadata(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T, string)
		write func(string)
	}{
		{
			name: "world writable",
			setup: func(t *testing.T, path string) {
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			},
			write: logEvent,
		},
		{
			name: "hardlinked",
			setup: func(t *testing.T, path string) {
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			},
			write: logEvent,
		},
		{
			name:  "owner mismatch",
			setup: func(*testing.T, string) {},
			write: func(line string) {
				logEventForOwner(line, os.Geteuid()+1)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sun.log")
			if err := os.WriteFile(path, []byte("unchanged\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("SECURITY_UPDATE_NOTIFY_LOG_FILE", path)
			test.setup(t, path)
			test.write("must not be written")
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "unchanged\n" {
				t.Fatalf("unsafe log was modified: %q", got)
			}
		})
	}
}

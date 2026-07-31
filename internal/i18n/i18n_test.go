package i18n

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDisplay(t *testing.T) {
	cases := []struct {
		ui, notify string
		want       Lang
	}{
		{"en", "", EN},
		{"zh", "", ZH},
		{"", "en", EN},   // 回退到 NOTIFY_LANG
		{"", "zh", ZH},   // 回退到 NOTIFY_LANG
		{"", "", ZH},     // 默认 zh
		{"en", "zh", EN}, // UI_LANG 优先
		{"zh", "en", ZH}, // UI_LANG 优先
		{"", "xx", ZH},   // 无效 -> zh
		{"xx", "", ZH},   // 无效 -> zh（非 en 一律 zh）
	}
	for _, c := range cases {
		if got := Display(c.ui, c.notify); got != c.want {
			t.Errorf("Display(%q,%q)=%v want %v", c.ui, c.notify, got, c.want)
		}
	}
}

func TestNormalizeNotify(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Lang
	}{{"en", EN}, {"zh", ZH}, {"", ZH}, {"EN", ZH}, {"english", ZH}} {
		if got := NormalizeNotify(c.in); got != c.want {
			t.Errorf("NormalizeNotify(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestPreReadNotifyLang(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []struct {
		name, body, want string
	}{
		{"plain", "NOTIFY_LANG=en\n", "en"},
		{"quoted", "NOTIFY_LANG='zh'\n", "zh"},
		{"dquoted", "NOTIFY_LANG=\"en\"\n", "en"},
		{"spaced", "  NOTIFY_LANG = zh \n", "zh"},
		{"crlf", "NOTIFY_LANG=en\r\n", "en"},
		{"exported", "export NOTIFY_LANG=en\n", "en"},
		{"unquoted-comment", "NOTIFY_LANG=en # terminal language\n", "en"},
		{"first-wins", "NOTIFY_LANG=zh\nNOTIFY_LANG=en\n", "zh"},
		{"among-others", "TELEGRAM_CHAT_ID=1\nNOTIFY_LANG=en\n", "en"},
		{"absent", "TELEGRAM_CHAT_ID=1\n", ""},
		{"word-prefix", "NOTIFY_LANG=english\n", ""},
		{"suffix", "NOTIFY_LANG=zh_CN\n", ""},
		{"mismatched-quotes", "NOTIFY_LANG=\"en'\n", ""},
		{"quoted-comment", "NOTIFY_LANG='en' # not stripped for quoted values\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PreReadNotifyLang(write(c.name, c.body)); got != c.want {
				t.Errorf("PreReadNotifyLang(%q)=%q want %q", c.body, got, c.want)
			}
		})
	}
	if got := PreReadNotifyLang(filepath.Join(dir, "does-not-exist")); got != "" {
		t.Errorf("unreadable file: got %q want empty", got)
	}
}

func TestPreReadNotifyLangRejectsUnsafeFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.env")
	if err := os.WriteFile(target, []byte("NOTIFY_LANG=en\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.env")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got := PreReadNotifyLang(link); got != "" {
		t.Fatalf("symlinked config language=%q", got)
	}

	oversized := filepath.Join(dir, "oversized.env")
	if err := os.WriteFile(oversized, bytes.Repeat([]byte{'x'}, maxPreReadConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := PreReadNotifyLang(oversized); got != "" {
		t.Fatalf("oversized config language=%q", got)
	}

	wide := filepath.Join(dir, "wide.env")
	if err := os.WriteFile(wide, []byte("NOTIFY_LANG=en\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := PreReadNotifyLang(wide); got != "" {
		t.Fatalf("unprotected config language=%q", got)
	}

	hardlink := filepath.Join(dir, "hardlink.env")
	if err := os.Link(target, hardlink); err != nil {
		t.Fatal(err)
	}
	if got := PreReadNotifyLang(target); got != "" {
		t.Fatalf("hard-linked config language=%q", got)
	}
	if got := preReadNotifyLang(writeProtectedConfig(t, dir), os.Geteuid()+1); got != "" {
		t.Fatalf("wrong-owner config language=%q", got)
	}

	fifo := filepath.Join(dir, "fifo.env")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() { done <- PreReadNotifyLang(fifo) }()
	select {
	case got := <-done:
		if got != "" {
			t.Fatalf("FIFO config language=%q", got)
		}
	case <-time.After(time.Second):
		writer, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = writer.Close()
		}
		t.Fatal("pre-reading a FIFO blocked")
	}
}

func writeProtectedConfig(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "wrong-owner.env")
	if err := os.WriteFile(path, []byte("NOTIFY_LANG=en\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

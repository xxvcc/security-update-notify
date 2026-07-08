package i18n

import (
	"os"
	"path/filepath"
	"testing"
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
		{"first-wins", "NOTIFY_LANG=zh\nNOTIFY_LANG=en\n", "zh"},
		{"among-others", "TELEGRAM_CHAT_ID=1\nNOTIFY_LANG=en\n", "en"},
		{"absent", "TELEGRAM_CHAT_ID=1\n", ""},
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

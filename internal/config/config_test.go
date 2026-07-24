package config

import (
	"bytes"
	"strings"
	"testing"
)

// 镜像 ci.yml “Config parser regression check” 的用例（load_config_file 运行时语义）：
// fail-open 于带行内注释的引号值，fail-closed 于未知键与无 '=' 行。
func TestParse(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		wantErr  bool
		key, val string // 若 key!="" 则校验解析值
	}{
		{"quoted-plus-comment", `HOST_LABEL="prod" # note`, false, "HOST_LABEL", `"prod" # note`},
		{"double-quoted", `HOST_LABEL="my host"`, false, "HOST_LABEL", "my host"},
		{"single-quoted", `HOST_LABEL='my host'`, false, "HOST_LABEL", "my host"},
		{"unquoted-comment", `HOST_LABEL=web1 # prod`, false, "HOST_LABEL", "web1"},
		{"embedded-hash", `HOST_LABEL=web#1`, false, "HOST_LABEL", "web#1"},
		{"export-prefix", `export HOST_LABEL=x`, false, "HOST_LABEL", "x"},
		{"spaced-key-and-val", `INCLUDE_PUBLIC_IP = 0`, false, "INCLUDE_PUBLIC_IP", "0"},
		{"trim-value", `HOST_LABEL=  spaced  `, false, "HOST_LABEL", "spaced"},
		{"comment-line", `   # a comment`, false, "", ""},
		{"unknown-key", `BAD_KEY=x`, true, "", ""},
		{"no-equals", `JUSTTEXT`, true, "", ""},
		{"bad-key-regex", `1BAD=x`, true, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := parse(strings.NewReader(c.line + "\n"))
			if (err != nil) != c.wantErr {
				t.Fatalf("parse(%q) err=%v wantErr=%v", c.line, err, c.wantErr)
			}
			if err == nil && c.key != "" {
				if got := cfg.Get(c.key); got != c.val {
					t.Errorf("parse(%q) %s=%q want %q", c.line, c.key, got, c.val)
				}
			}
		})
	}
}

func TestQuote(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"plain", "'plain'"},
		{"", "''"},
		{"has space", "'has space'"},
		{"it's", `"it's"`},         // 含单引号 -> 双引号包裹
		{`say "hi"`, `'say "hi"'`}, // 含双引号但无单引号 -> 单引号包裹
	} {
		if got := quote(c.in); got != c.want {
			t.Errorf("quote(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestWriteFormat(t *testing.T) {
	values := map[string]string{
		"TELEGRAM_BOT_TOKEN": "123456:abc_DEF-ghi", "TELEGRAM_CHAT_ID": "-100123",
		"NOTIFY_CHANNELS": "telegram,feishu", "FEISHU_APP_ID": "cli_test", "FEISHU_RECEIVE_ID": "ou_lanny",
		"HOST_LABEL": "prod web", "PUBLIC_IP": "", "INCLUDE_PUBLIC_IP": "1",
		"NOTIFY_OK": "0", "NOTIFY_UPGRADE": "0", "DEDUP_MODE": "always", "DEDUP_INTERVAL_DAYS": "3",
		"NOTIFY_LANG": "en", "BACKEND": "apt", "CONFIG_VERSION": "1",
		"CHECK_UPDATE_HEALTH": "1", "STALE_UPDATE_DAYS": "7", "CHECK_EOL": "1",
	}
	var buf bytes.Buffer
	if err := Write(&buf, values); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if lines[0] != header1 || lines[1] != header2 {
		t.Fatalf("headers drifted:\n%q\n%q", lines[0], lines[1])
	}
	body := lines[2:]
	if len(body) != len(writeOrder) {
		t.Fatalf("wrote %d keys, want %d", len(body), len(writeOrder))
	}
	// 键序必须等于 writeOrder。
	for i, k := range writeOrder {
		if !strings.HasPrefix(body[i], k+"=") {
			t.Errorf("line %d = %q, want key %s", i, body[i], k)
		}
	}
	// CONFIG_VERSION 强制为 '3'，DEDUP_MODE always -> once，空 PUBLIC_IP -> ''。
	if body[0] != "CONFIG_VERSION='3'" {
		t.Errorf("CONFIG_VERSION line = %q want CONFIG_VERSION='3'", body[0])
	}
	joined := buf.String()
	if !strings.Contains(joined, "DEDUP_MODE='once'") {
		t.Errorf("DEDUP_MODE always not migrated to once:\n%s", joined)
	}
	if !strings.Contains(joined, "PUBLIC_IP=''") {
		t.Errorf("empty PUBLIC_IP not written as '':\n%s", joined)
	}
}

// 写出的文件必须能被解析器读回，且值一致（CONFIG_VERSION 归 2、DEDUP_MODE 归 once）。
func TestWriteLoadRoundTrip(t *testing.T) {
	in := map[string]string{
		"TELEGRAM_BOT_TOKEN": "123456:abc_DEF-ghi", "TELEGRAM_CHAT_ID": "-100123",
		"NOTIFY_CHANNELS": "telegram,feishu", "FEISHU_APP_ID": "cli_test", "FEISHU_RECEIVE_ID": "ou_lanny",
		"HOST_LABEL": "it's a host", "PUBLIC_IP": "203.0.113.10", "INCLUDE_PUBLIC_IP": "0",
		"NOTIFY_OK": "1", "NOTIFY_UPGRADE": "1", "DEDUP_MODE": "always", "DEDUP_INTERVAL_DAYS": "7",
		"NOTIFY_LANG": "en", "BACKEND": "apt", "CONFIG_VERSION": "1",
		"CHECK_UPDATE_HEALTH": "1", "STALE_UPDATE_DAYS": "7", "CHECK_EOL": "1",
	}
	var buf bytes.Buffer
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	cfg, err := parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for k, v := range in {
		want[k] = v
	}
	want["CONFIG_VERSION"] = "3"
	want["DEDUP_MODE"] = "once"
	for k, w := range want {
		if got := cfg.Get(k); got != w {
			t.Errorf("round-trip %s=%q want %q", k, got, w)
		}
	}
}

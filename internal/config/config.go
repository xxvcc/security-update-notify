// Package config 复刻运行时对 /etc/security-update-notify/telegram.env 的严格行解析（load_config_file）
// 与安装器的逐字节写出（config_quote + 固定写序）。刻意“不 source”配置文件：只做行级解析、键白名单、
// 值去引号，且严格保持“文件不可读→继续(fail-open)，坏行/坏键/非白名单键→报错(fail-closed)”的分裂，
// 以及写出的线格式（供已装机器升级后仍能被旧 Bash 读回）。
//
// Package config reproduces the runtime's strict line parser for /etc/security-update-notify/telegram.env
// (load_config_file) and the installer's byte-exact writer (config_quote + fixed order). It deliberately
// does NOT source the file: line parsing, key whitelist, value unquoting, keeping the exact split of
// "unreadable file → proceed (fail-open); bad line / bad key / non-whitelisted key → error (fail-closed)"
// and the on-disk wire format (so an upgraded host is still readable by the old Bash).
package config

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// cSpace 是 C locale 下 [[:space:]] 的字符集，用于值的首尾裁剪与行首空白判定。
const cSpace = " \t\n\v\f\r"

// whitelist 是运行时 load_config_file 接受的 15 个键（非此集合的合法键 → fail-closed）。
var whitelist = map[string]bool{
	"TELEGRAM_BOT_TOKEN": true, "TELEGRAM_CHAT_ID": true, "HOST_LABEL": true, "PUBLIC_IP": true,
	"INCLUDE_PUBLIC_IP": true, "NOTIFY_OK": true, "NOTIFY_UPGRADE": true, "DEDUP_MODE": true,
	"DEDUP_INTERVAL_DAYS": true, "NOTIFY_LANG": true, "BACKEND": true, "CONFIG_VERSION": true,
	"CHECK_UPDATE_HEALTH": true, "STALE_UPDATE_DAYS": true, "CHECK_EOL": true,
}

// writeOrder 是安装器写 telegram.env 的固定键序（CONFIG_VERSION 在最前）。逐字节兼容的关键之一。
var writeOrder = []string{
	"CONFIG_VERSION", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "HOST_LABEL", "PUBLIC_IP",
	"INCLUDE_PUBLIC_IP", "NOTIFY_OK", "NOTIFY_UPGRADE", "DEDUP_MODE", "DEDUP_INTERVAL_DAYS",
	"NOTIFY_LANG", "BACKEND", "CHECK_UPDATE_HEALTH", "STALE_UPDATE_DAYS", "CHECK_EOL",
}

var keyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Config 保存已解析的键值（仅白名单键）。
type Config struct {
	m map[string]string
}

// Get 返回键值（不存在返回空串）。
func (c *Config) Get(k string) string { return c.m[k] }

// Has 报告键是否出现在配置中。
func (c *Config) Has(k string) bool { _, ok := c.m[k]; return ok }

// Map 返回内部键值的浅拷贝。
func (c *Config) Map() map[string]string {
	out := make(map[string]string, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// Load 按运行时 load_config_file 语义解析 telegram.env：
//   - 文件不可读 → 返回空配置且 nil（fail-open，对应 Bash `[[ -r ]] || return 0`）；
//   - 行无 '='、键不匹配 ^[A-Za-z_][A-Za-z0-9_]*$、或键不在白名单 → 返回错误（fail-closed）。
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return &Config{m: map[string]string{}}, nil // fail-open
	}
	defer f.Close()
	return parse(f)
}

func parse(r io.Reader) (*Config, error) {
	c := &Config{m: map[string]string{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r") // ${line%$'\r'}
		if line == "" || isCommentLine(line) {
			continue
		}
		if strings.HasPrefix(line, "export ") { // 仅前缀恰为 "export " 才剥离
			line = line[len("export "):]
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			return nil, fmt.Errorf("invalid config line (no '=')")
		}
		key := dropSpace(line[:i]) // key="${key//[[:space:]]/}"
		if !keyRe.MatchString(key) {
			return nil, fmt.Errorf("invalid config key: %q", key)
		}
		val := parseValue(line[i+1:])
		if !whitelist[key] {
			return nil, fmt.Errorf("unsupported config key: %q", key)
		}
		c.m[key] = val
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return c, nil
}

// isCommentLine 复刻 `^[[:space:]]*#`：跳过可选前导空白后首字符为 '#' 的行。
func isCommentLine(line string) bool {
	t := strings.TrimLeft(line, cSpace)
	return strings.HasPrefix(t, "#")
}

func dropSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(cSpace, r) {
			return -1
		}
		return r
	}, s)
}

// parseValue 复刻运行时的取值规则：首尾去空白；若不以引号开头则剥离“空白+#”起的行内注释再右裁；
// 最后若整体被一对双引号或单引号包裹则去掉这对引号。绝不做反斜杠转义。
func parseValue(raw string) string {
	v := strings.TrimLeft(raw, cSpace)
	v = strings.TrimRight(v, cSpace)
	if !strings.HasPrefix(v, `"`) && !strings.HasPrefix(v, `'`) {
		v = stripInlineComment(v) // value="${value%%[[:space:]]#*}"
		v = strings.TrimRight(v, cSpace)
	}
	// 顺序剥离（先双引号再单引号），与 Bash load_config_file 的两条连续语句一致：
	// 值 "'x'" 会被剥成 x（若这里用早返回则只剥一层，两运行时读出不同值）。
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	if len(v) >= 2 && v[0] == '\'' && v[len(v)-1] == '\'' {
		v = v[1 : len(v)-1]
	}
	return v
}

// stripInlineComment 复刻 `${value%%[[:space:]]#*}`：删除从“首个（空白紧跟 #）”起到行尾的内容
// （%% 去最长后缀 = 最早的 空白# 对起始处）。无此模式则原样返回（故 web#1 不受影响）。
func stripInlineComment(v string) string {
	for i := 0; i+1 < len(v); i++ {
		if strings.IndexByte(cSpace, v[i]) >= 0 && v[i+1] == '#' {
			return v[:i]
		}
	}
	return v
}

// quote 复刻 config_quote：值含单引号则用双引号包裹，否则用单引号包裹；不转义。
// 上游 validate_config_value 已禁止值同时含单双引号或含换行。
func quote(value string) string {
	if strings.Contains(value, "'") {
		return `"` + value + `"`
	}
	return "'" + value + "'"
}

// 两行双语头注释，必须与安装器写出的字节完全一致。
const header1 = "# security-update-notify 的 Telegram 通知设置；NOTIFY_LANG 控制发送语言：zh 中文，en English / Telegram notification settings for security-update-notify; NOTIFY_LANG controls the sent language: zh Chinese, en English."
const header2 = "# 请保持此文件仅 root 可读：它包含 Bot Token / Keep this file root-only: it contains the bot token."

// Write 以安装器的逐字节格式写出 telegram.env：两行头注释 + 15 个键（固定写序、config_quote 引用）。
// 强制 CONFIG_VERSION=2，并把 DEDUP_MODE 的旧值 always 迁移为 once（与安装器一致）。缺失键写空值。
func Write(w io.Writer, values map[string]string) error {
	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintln(bw, header1); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(bw, header2); err != nil {
		return err
	}
	for _, k := range writeOrder {
		v := values[k]
		switch k {
		case "CONFIG_VERSION":
			v = "2" // 始终写入当前 schema 版本，不沿用旧值
		case "DEDUP_MODE":
			if v == "always" {
				v = "once" // 迁移旧值
			}
		}
		if _, err := fmt.Fprintf(bw, "%s=%s\n", k, quote(v)); err != nil {
			return err
		}
	}
	return bw.Flush()
}

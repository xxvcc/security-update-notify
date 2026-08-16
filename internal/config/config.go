// Package config 复刻运行时对 /etc/security-update-notify/telegram.env 的严格行解析（load_config_file）
// 与安装器的逐字节写出（config_quote + 固定写序）。刻意“不 source”配置文件：只做行级解析、键白名单、
// 值去引号。仅文件不存在时返回空配置以兼容未安装状态；其它读取错误、坏行、坏键和非白名单键
// 均报错(fail-closed)，并保持写出的线格式（供已装机器升级后仍能被旧 Bash 读回）。
//
// Package config reproduces the runtime's strict line parser for /etc/security-update-notify/telegram.env
// (load_config_file) and the installer's byte-exact writer (config_quote + fixed order). It deliberately
// does NOT source the file: it parses lines, enforces a key whitelist, and unquotes values. Only a missing
// file returns an empty configuration for compatibility with an uninstalled host; every other read error,
// malformed line, bad key, or non-whitelisted key fails closed. The on-disk wire format remains readable
// by the old Bash runtime after an upgrade.
package config

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

// cSpace 是 C locale 下 [[:space:]] 的字符集，用于值的首尾裁剪与行首空白判定。
const cSpace = " \t\n\v\f\r"

const maxConfigBytes = 4 << 20

const maxConfigValueBytes = 64 << 10

// whitelist 是运行时 load_config_file 接受的配置键（非此集合的合法键 → fail-closed）。
var whitelist = map[string]bool{
	"TELEGRAM_BOT_TOKEN": true, "TELEGRAM_CHAT_ID": true, "HOST_LABEL": true, "PUBLIC_IP": true,
	"INCLUDE_PUBLIC_IP": true, "NOTIFY_OK": true, "NOTIFY_UPGRADE": true, "DEDUP_MODE": true,
	"DEDUP_INTERVAL_DAYS": true, "NOTIFY_LANG": true, "BACKEND": true, "CONFIG_VERSION": true,
	"CHECK_UPDATE_HEALTH": true, "STALE_UPDATE_DAYS": true, "CHECK_EOL": true,
	"PENDING_ALERT_DAYS": true, "RESTART_ALERT_DAYS": true,
	"CHECK_SELF_UPDATE": true, "SELF_UPDATE_CHECK_DAYS": true,
	"NOTIFY_CHANNELS": true, "FEISHU_APP_ID": true, "FEISHU_RECEIVE_ID": true,
}

// writeOrder 是安装器写 telegram.env 的固定键序（CONFIG_VERSION 在最前）。逐字节兼容的关键之一。
var writeOrder = []string{
	"CONFIG_VERSION", "NOTIFY_CHANNELS", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID",
	"FEISHU_APP_ID", "FEISHU_RECEIVE_ID", "HOST_LABEL", "PUBLIC_IP",
	"INCLUDE_PUBLIC_IP", "NOTIFY_OK", "NOTIFY_UPGRADE", "DEDUP_MODE", "DEDUP_INTERVAL_DAYS",
	"NOTIFY_LANG", "BACKEND", "CHECK_UPDATE_HEALTH", "STALE_UPDATE_DAYS", "CHECK_EOL",
	"PENDING_ALERT_DAYS", "RESTART_ALERT_DAYS", "CHECK_SELF_UPDATE", "SELF_UPDATE_CHECK_DAYS",
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
//   - 文件不存在 → 返回空配置且 nil（保持未安装/旧调用路径的兼容语义）；
//   - 其它不可读、非常规、符号链接或超大文件 → 返回错误（fail-closed）；
//   - 行无 '='、键不匹配 ^[A-Za-z_][A-Za-z0-9_]*$、或键不在白名单 → 返回错误（fail-closed）。
func Load(path string) (*Config, error) {
	return load(path, os.Geteuid())
}

func load(path string, euid int) (*Config, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Config{m: map[string]string{}}, nil
		}
		return nil, fmt.Errorf("open config: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect config: %w", err)
	}
	if err := filetrust.ValidateRegular(info, euid, 0o077, true); err != nil {
		return nil, fmt.Errorf("config must be a protected regular file owned by the effective user: %w", err)
	}
	if info.Size() > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	contents, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	if len(contents) > maxConfigBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", maxConfigBytes)
	}
	return parse(bytes.NewReader(contents))
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
		line = strings.TrimPrefix(line, "export ") // 仅前缀恰为 "export " 才剥离
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

// Representable 报告 Write 能否无损存储 value：写出后再读回（包括与之字节兼容的 Bash 读取器）
// 必须得到完全相同的字节。线格式没有转义机制，且读取器会顺序剥离一层双引号再剥离一层单引号，
// 因此“自身首尾恰为一对单引号”的值无法表示。
//
// Representable reports whether Write can store value so that a later Load — and the Bash reader it
// is byte-compatible with — reads back exactly the same bytes. The wire format has no escape
// mechanism and the reader strips one double-quote layer then one single-quote layer, so a value
// that is itself wrapped in a matching pair of single quotes cannot be represented.
func Representable(value string) bool {
	if strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	if strings.Contains(value, "'") && strings.Contains(value, `"`) {
		return false
	}
	return parseValue(quote(value)) == value
}

// Canonical 返回“Write 存储 value 后读取器实际会观察到”的值。它是幂等的：线格式无法表示的
// 继承值会一次性收敛到不动点，而不是每次升级丢掉一层引号。仅用于既有配置的迁移，
// 用户显式提供的值应当直接被 Representable 拒绝而不是被静默改写。
//
// Canonical returns the value a reader actually observes after Write stores value. It is
// idempotent, so an inherited value the wire format cannot represent converges in one step
// instead of losing one quote layer per upgrade. Use it only to migrate an existing file;
// an explicitly supplied value must be rejected by Representable rather than silently rewritten.
func Canonical(value string) string {
	// quote chooses double quotes whenever value contains a single quote. The
	// reader then removes that outer double-quote layer and, independently, one
	// matching single-quote layer from value. Repeating the old write/read loop
	// therefore did nothing except peel matching single quotes from both ends,
	// but it rescanned and reallocated the remaining value on every iteration.
	// Existing config can be up to maxConfigBytes, so perform the identical
	// convergence in one linear pass.
	layers := 0
	for layers < len(value)/2 && value[layers] == '\'' && value[len(value)-1-layers] == '\'' {
		layers++
	}
	return value[layers : len(value)-layers]
}

// quote 复刻 config_quote：值含单引号则用双引号包裹，否则用单引号包裹；不转义。
// Write 在调用此函数前会拒绝无法用该线格式无损表示的值。
func quote(value string) string {
	if strings.Contains(value, "'") {
		return `"` + value + `"`
	}
	return "'" + value + "'"
}

// 两行双语头注释，必须与安装器写出的字节完全一致。
const header1 = "# security-update-notify 通知设置；NOTIFY_CHANNELS 可选 telegram、feishu 或两者 / Notification settings; NOTIFY_CHANNELS may be telegram, feishu, or both."
const header2 = "# 请保持此文件仅 root 可读；飞书 App Secret 使用独立 systemd/root credential，不写入此文件 / Keep this file root-only; the Feishu App Secret uses a separate systemd/root credential, not this file."

// Write 以安装器的逐字节格式写出 telegram.env：两行头注释 + 固定写序/config_quote 引用。
// 强制 CONFIG_VERSION=4，并把 DEDUP_MODE 的旧值 always 迁移为 once（与安装器一致）。缺失键写空值。
func Write(w io.Writer, values map[string]string) error {
	type entry struct {
		key, value string
	}
	entries := make([]entry, 0, len(writeOrder))
	for _, k := range writeOrder {
		v := values[k]
		switch k {
		case "CONFIG_VERSION":
			v = "4" // 始终写入当前 schema 版本，不沿用旧值
		case "NOTIFY_CHANNELS":
			if v == "" {
				v = "telegram" // 旧配置无此键时保持原有 Telegram 行为
			}
		case "DEDUP_MODE":
			if v == "always" {
				v = "once" // 迁移旧值
			}
		}
		if err := validateWriteValue(k, v); err != nil {
			return err
		}
		entries = append(entries, entry{key: k, value: v})
	}

	bw := bufio.NewWriter(w)
	if _, err := fmt.Fprintln(bw, header1); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(bw, header2); err != nil {
		return err
	}
	for _, item := range entries {
		if _, err := fmt.Fprintf(bw, "%s=%s\n", item.key, quote(item.value)); err != nil {
			return err
		}
	}
	return bw.Flush()
}

func validateWriteValue(key, value string) error {
	if len(value) > maxConfigValueBytes {
		return fmt.Errorf("config value %s exceeds 64 KiB", key)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("config value %s contains a line break", key)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("config value %s contains a NUL byte", key)
	}
	if strings.Contains(value, "'") && strings.Contains(value, `"`) {
		return fmt.Errorf("config value %s contains conflicting quote characters", key)
	}
	// Make the documented contract real: never write a value the reader would
	// hand back as something else. Callers migrating an existing file must run
	// Canonical first so an unrepresentable inherited value cannot dead-end an
	// otherwise unattended upgrade.
	if !Representable(value) {
		return fmt.Errorf("config value %s cannot be represented in the config file format", key)
	}
	return nil
}

// Package i18n 复刻运行时的语言解析：终端显示语言按 UI_LANG → NOTIFY_LANG → zh 回退，且仅当有效
// 值恰为 "en" 时才用英文（其余一律中文）；
// NOTIFY_LANG 单独归一化为精确 zh/en（其它 → zh），它同时是去重 hash 的第 3 个字段与通知正文语言。
//
// Package i18n reproduces the runtime language resolution: the terminal display language falls back
// UI_LANG → NOTIFY_LANG → zh, and is English only when the effective value is exactly "en" (anything
// else is Chinese). NOTIFY_LANG is separately
// normalized to exactly zh/en (else zh); it is both the 3rd dedup-hash field and the notification body language.
package i18n

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/xxvcc/security-update-notify/internal/filetrust"
)

// Lang 是 zh 或 en。
type Lang string

const (
	ZH                    Lang = "zh"
	EN                    Lang = "en"
	maxPreReadConfigBytes      = 4 << 20
)

// Display 解析终端显示语言：uiLang 优先，否则 notifyLang，否则 zh；只有有效值恰为 "en" 才是英文。
// 这保留了 2.x 的语言选择兼容语义。
func Display(uiLang, notifyLang string) Lang {
	v := uiLang
	if v == "" {
		v = notifyLang
	}
	if v == "" {
		v = "zh"
	}
	if v == "en" {
		return EN
	}
	return ZH
}

// NormalizeNotify 把 NOTIFY_LANG 归一化为精确 zh 或 en（其它值 → zh），复刻
// `case "$NOTIFY_LANG" in zh|en) ;; *) NOTIFY_LANG="zh" ;; esac`。
func NormalizeNotify(s string) Lang {
	if s == "en" {
		return EN
	}
	return ZH
}

// Pick 按语言返回 zh 或 en 文案（对应 Bash 的 m/say 选择）。
func (l Lang) Pick(zh, en string) string {
	if l == EN {
		return en
	}
	return zh
}

// preReadRe accepts the protected env-file forms that resolve to exactly zh or
// en. Unquoted values may carry the same whitespace-prefixed inline comment
// accepted by the full parser; quoted values must end after the closing quote.
var preReadRe = regexp.MustCompile(`^(?:export )?[ \t]*NOTIFY_LANG[ \t]*=[ \t]*(?:"(zh|en)"[ \t]*|'(zh|en)'[ \t]*|(zh|en)(?:[ \t]*|[ \t]+#.*))$`)

// PreReadNotifyLang 在完整配置加载前，从 env 文件里预读 NOTIFY_LANG（供 --check-upgrade/--upgrade
// 的显示语言跟随已安装配置）。文件不可读或未命中返回 ""。取首个匹配行。
func PreReadNotifyLang(envPath string) string {
	return preReadNotifyLang(envPath, os.Geteuid())
}

func preReadNotifyLang(envPath string, euid int) string {
	fd, err := syscall.Open(envPath, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	f := os.NewFile(uintptr(fd), envPath)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || filetrust.ValidateRegular(info, euid, 0o077, true) != nil || info.Size() > maxPreReadConfigBytes {
		return ""
	}
	contents, err := io.ReadAll(io.LimitReader(f, maxPreReadConfigBytes+1))
	if err != nil || len(contents) > maxPreReadConfigBytes {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(contents))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024) // 放宽默认 64KB 行上限，避免超长行使后续行被跳过
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := preReadRe.FindStringSubmatch(line); m != nil {
			for _, value := range m[1:] {
				if value != "" {
					return value
				}
			}
		}
	}
	return ""
}

// Package i18n 复刻运行时的语言解析：终端显示语言按 UI_LANG → NOTIFY_LANG → zh 回退，且仅当有效
// 值恰为 "en" 时才用英文（其余一律中文），与 files/security-update-notify 里的 m()/say() 等价；
// NOTIFY_LANG 单独归一化为精确 zh/en（其它 → zh），它同时是去重 hash 的第 3 个字段与通知正文语言。
//
// Package i18n reproduces the runtime language resolution: the terminal display language falls back
// UI_LANG → NOTIFY_LANG → zh, and is English only when the effective value is exactly "en" (anything
// else is Chinese), matching m()/say() in files/security-update-notify. NOTIFY_LANG is separately
// normalized to exactly zh/en (else zh); it is both the 3rd dedup-hash field and the notification body language.
package i18n

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// Lang 是 zh 或 en。
type Lang string

const (
	ZH Lang = "zh"
	EN Lang = "en"
)

// Display 解析终端显示语言：uiLang 优先，否则 notifyLang，否则 zh；只有有效值恰为 "en" 才是英文。
// 这是 Bash m()/say() 里 `${UI_LANG:-${NOTIFY_LANG:-zh}}` = en 判断的等价实现。
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

// preReadRe 复刻运行时从 env 文件预读 NOTIFY_LANG 的 sed：
//
//	s/^[[:space:]]*NOTIFY_LANG[[:space:]]*=[[:space:]]*["']\{0,1\}\(zh\|en\)["']\{0,1\}.*/\1/p
//
// 只接受值恰为 zh 或 en（可选一层引号），取首个匹配。
var preReadRe = regexp.MustCompile(`^[ \t]*NOTIFY_LANG[ \t]*=[ \t]*["']?(zh|en)["']?`)

// PreReadNotifyLang 在完整配置加载前，从 env 文件里预读 NOTIFY_LANG（供 --check-upgrade/--upgrade
// 的显示语言跟随已安装配置）。文件不可读或未命中返回 ""。取首个匹配行。
func PreReadNotifyLang(envPath string) string {
	f, err := os.Open(envPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := preReadRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return ""
}

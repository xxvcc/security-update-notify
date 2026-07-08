package run

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/osrel"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/systemd"
	"github.com/xxvcc/security-update-notify/internal/telegram"
)

// DoctorOpts 是 --doctor 的选项。
type DoctorOpts struct {
	Version      string
	Lang         i18n.Lang
	SkipTelegram bool
	EnvPath      string
}

// Doctor 复刻 run_doctor：打印环境/后端/systemd/依赖命令/Telegram/看门狗自检；有失败项返回 1，否则 0。
// 这是人类可读的诊断输出（非线格式/去重字段），无需字节级对齐。
func Doctor(cfg *config.Config, opts DoctorOpts) int {
	out := os.Stdout
	lang := opts.Lang
	ok := true
	fmt.Fprintf(out, "security-update-notify %s\n", opts.Version)
	say(out, lang, "配置文件: "+opts.EnvPath, "Config: "+opts.EnvPath)
	if fileReadable(opts.EnvPath) {
		say(out, lang, "正常：配置可读", "OK config readable")
	} else {
		say(out, lang, "失败：配置不可读", "FAIL config not readable")
		ok = false
	}

	o := osrel.Read(osReleasePath)
	be := cfg.Get("BACKEND")
	if be == "" || be == "auto" {
		be = osrel.AutoBackend(o)
	}
	say(out, lang, "后端: "+be, "Backend: "+be)
	say(out, lang, "主机: "+hostLabel(cfg), "Host: "+hostLabel(cfg))
	if include, ip := resolvePublicIP(cfg); include {
		say(out, lang, "公网 IP: "+ip, "Public IP: "+ip)
	}
	say(out, lang, "系统: "+orDefault(o.PrettyName, "unknown"), "OS: "+orDefault(o.PrettyName, "unknown"))
	say(out, lang, "内核: "+kernelRelease(), "Kernel: "+kernelRelease())

	if fileExists("/run/systemd/system") && sysexec.Look("systemctl") {
		say(out, lang, "正常：systemd 存在", "OK systemd present")
		if systemd.IsEnabled("security-update-notify.timer") {
			say(out, lang, "正常：timer 已启用", "OK timer enabled")
		} else {
			say(out, lang, "警告：timer 未启用", "WARN timer not enabled")
			ok = false
		}
	} else {
		say(out, lang, "失败：systemd 不可用", "FAIL systemd unavailable")
		ok = false
	}

	switch be {
	case "apt":
		for _, c := range []string{"apt-get", "dpkg", "needrestart"} {
			if sysexec.Look(c) {
				say(out, lang, "正常：命令存在 "+c, "OK command "+c)
			} else {
				say(out, lang, "失败：缺少命令 "+c, "FAIL missing command "+c)
				ok = false
			}
		}
		if sysexec.Run("dpkg", "-s", "unattended-upgrades").Code == 0 {
			say(out, lang, "正常：unattended-upgrades 已安装", "OK unattended-upgrades installed")
		} else {
			say(out, lang, "失败：缺少 unattended-upgrades", "FAIL unattended-upgrades missing")
			ok = false
		}
	case "dnf":
		switch {
		case sysexec.Look("dnf"):
			say(out, lang, "正常：命令存在 dnf", "OK command dnf")
		case sysexec.Look("yum"):
			say(out, lang, "正常：命令存在 yum", "OK command yum")
		default:
			say(out, lang, "失败：缺少 dnf/yum", "FAIL missing dnf/yum")
			ok = false
		}
		if sysexec.Look("needs-restarting") {
			say(out, lang, "正常：命令存在 needs-restarting", "OK command needs-restarting")
		} else {
			say(out, lang, "失败：缺少 needs-restarting", "FAIL missing needs-restarting")
			ok = false
		}
		if systemd.IsEnabled("dnf-automatic.timer") {
			say(out, lang, "正常：dnf-automatic.timer 已启用", "OK dnf-automatic.timer enabled")
		} else {
			say(out, lang, "警告：dnf-automatic.timer 未启用", "WARN dnf-automatic.timer not enabled")
		}
	default:
		say(out, lang, "失败：不支持的后端 "+be, "FAIL unsupported backend "+be)
		ok = false
	}

	token := cfg.Get("TELEGRAM_BOT_TOKEN")
	chat := cfg.Get("TELEGRAM_CHAT_ID")
	if opts.SkipTelegram {
		say(out, lang, "跳过：Telegram 联通性检查", "SKIP Telegram connectivity check")
	} else if token != "" && chat != "" {
		say(out, lang, "正常：Telegram 配置存在", "OK Telegram config present")
		client := &telegram.Client{HTTP: httpx.New(20 * time.Second), BaseURL: os.Getenv(telegramBaseURLEnv)}
		if client.GetMe(context.Background(), token) == nil {
			say(out, lang, "正常：Telegram Bot Token 可用", "OK Telegram bot token works")
		} else {
			say(out, lang, "失败：Telegram getMe 失败", "FAIL Telegram getMe failed")
			ok = false
		}
	} else {
		say(out, lang, "失败：Telegram 配置缺失", "FAIL Telegram config missing")
		ok = false
	}

	health, pending, eol := collectWatchdog(cfg, be, o)
	if health.Attention {
		say(out, lang, "失败：自动安全更新机制异常", "FAIL automatic security-update mechanism issue")
		say(out, lang, health.TxtZH, health.TxtEN)
		ok = false
	} else {
		say(out, lang, "正常：自动安全更新机制健康", "OK automatic security-update mechanism healthy")
	}
	if pending.Count > 0 {
		say(out, lang, pending.TxtZH, pending.TxtEN)
	} else {
		say(out, lang, "正常：当前无待安装的安全更新", "OK no pending security updates")
	}
	if eol.TxtZH != "" {
		if eol.Attention {
			ok = false
		}
		say(out, lang, eol.TxtZH, eol.TxtEN)
	} else {
		say(out, lang, "正常：发行版仍在安全支持期内（或不在 EOL 表中）", "OK release within security support (or not in the EOL table)")
	}

	if ok {
		return 0
	}
	return 1
}

func fileReadable(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

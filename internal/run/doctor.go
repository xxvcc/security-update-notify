package run

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/backend"
	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/osrel"
	"github.com/xxvcc/security-update-notify/internal/sysexec"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
	"github.com/xxvcc/security-update-notify/internal/watchdog"
)

const doctorCommandTimeout = 30 * time.Second

// DoctorOpts 是 --doctor 的选项。
type DoctorOpts struct {
	Version      string
	Lang         i18n.Lang
	SkipTelegram bool
	SkipFeishu   bool
	SkipNotify   bool
	EnvPath      string
	Systemd      SystemdQuery
}

// Doctor 复刻 run_doctor：打印环境/后端/systemd/依赖命令/Telegram/看门狗自检；有失败项返回 1，否则 0。
// 这是人类可读的诊断输出（非线格式/去重字段），无需字节级对齐。
func Doctor(cfg *config.Config, opts DoctorOpts) int {
	out := os.Stdout
	lang := opts.Lang
	ok := true
	backendReady := true
	systemdQuery := systemdQueryOrDefault(opts.Systemd)
	fmt.Fprintf(out, "security-update-notify %s\n", textsafe.SingleLine(opts.Version))
	say(out, lang, "配置文件: "+opts.EnvPath, "Config: "+opts.EnvPath)
	if fileReadable(opts.EnvPath) {
		say(out, lang, "正常：配置可读", "OK config readable")
	} else {
		say(out, lang, "失败：配置不可读", "FAIL config not readable")
		ok = false
	}

	// Same reader as Collect: an image that ships only /usr/lib/os-release runs correctly, so doctor
	// must not report it as an unsupported backend.
	o := osrel.ReadFirst(osReleasePath, osReleaseFallbackPath)
	be := cfg.Get("BACKEND")
	if be == "" || be == "auto" {
		be = osrel.AutoBackend(o)
	}
	say(out, lang, "后端: "+be, "Backend: "+be)
	host := hostLabel(cfg)
	say(out, lang, "主机: "+host, "Host: "+host)
	if include, ip := resolvePublicIP(cfg); include {
		say(out, lang, "公网 IP: "+ip, "Public IP: "+ip)
	}
	say(out, lang, "系统: "+orDefault(o.PrettyName, "unknown"), "OS: "+orDefault(o.PrettyName, "unknown"))
	kernel := kernelRelease()
	say(out, lang, "内核: "+kernel, "Kernel: "+kernel)

	if systemdQuery.Available() {
		say(out, lang, "正常：systemd 存在", "OK systemd present")
		if systemdQuery.IsEnabled("security-update-notify.timer") {
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
		backendReady = doctorAPTDependencies(out, lang, sysexec.Look, func(name string, args ...string) sysexec.Result {
			return sysexec.RunTimeout(doctorCommandTimeout, name, args...)
		})
		if probe := sysexec.RunTimeout(doctorCommandTimeout, "unattended-upgrade", "--help"); probe.Code != 0 || commandOutputIncomplete(probe) {
			say(out, lang, "失败：unattended-upgrade 命令不可用", "FAIL unattended-upgrade command unavailable")
			backendReady = false
		}
		if !fileReadable(aptPeriodicConfigPath()) {
			say(out, lang, "失败：APT 自动更新配置不可读", "FAIL APT automatic-update configuration not readable")
			backendReady = false
		}
		if systemdQuery.IsEnabled("apt-daily-upgrade.timer") {
			say(out, lang, "正常：apt-daily-upgrade.timer 已启用", "OK apt-daily-upgrade.timer enabled")
		} else {
			say(out, lang, "失败：apt-daily-upgrade.timer 未启用", "FAIL apt-daily-upgrade.timer not enabled")
			backendReady = false
		}
		ok = ok && backendReady
	case "dnf":
		runtime := detectDNFRuntime(doctorCommandTimeout)
		generationProbeFailed := runtime.Available && !runtime.GenerationKnown
		if runtime.Available {
			label := runtime.Command
			if runtime.isDNF5() {
				label += " (DNF5)"
			}
			say(out, lang, "正常：命令存在 "+label, "OK command "+label)
			if generationProbeFailed {
				say(out, lang,
					"失败：无法可靠识别 DNF 代际（"+runtime.Command+" --version）",
					"FAIL could not reliably identify DNF generation ("+runtime.Command+" --version)")
				ok = false
				backendReady = false
			}
		} else {
			say(out, lang, "失败：缺少 dnf/yum", "FAIL missing dnf/yum")
			ok = false
			backendReady = false
		}
		if !generationProbeFailed {
			if runtime.isDNF5() {
				probe := sysexec.RunTimeout(doctorCommandTimeout, runtime.Command, "needs-restarting", "--help")
				if probe.Code == 0 && !commandOutputIncomplete(probe) {
					say(out, lang, "正常：命令存在 dnf needs-restarting", "OK command dnf needs-restarting")
				} else {
					say(out, lang, "失败：缺少 dnf needs-restarting 子命令", "FAIL missing dnf needs-restarting command")
					ok = false
					backendReady = false
				}
			} else if sysexec.Look("needs-restarting") {
				say(out, lang, "正常：命令存在 needs-restarting", "OK command needs-restarting")
			} else {
				say(out, lang, "失败：缺少 needs-restarting", "FAIL missing needs-restarting")
				ok = false
				backendReady = false
			}
			var automaticProbe sysexec.Result
			if runtime.isDNF5() {
				automaticProbe = sysexec.RunTimeout(doctorCommandTimeout, runtime.Command, "automatic", "--help")
			} else if sysexec.Look("dnf-automatic") {
				automaticProbe = sysexec.RunTimeout(doctorCommandTimeout, "dnf-automatic", "--help")
			} else {
				automaticProbe.Code = -1
			}
			if automaticProbe.Code == 0 && !commandOutputIncomplete(automaticProbe) {
				say(out, lang, "正常：DNF automatic 命令可用", "OK DNF automatic command available")
			} else {
				say(out, lang, "失败：DNF automatic 命令不可用", "FAIL DNF automatic command unavailable")
				ok = false
				backendReady = false
			}
		}
		if content, err := readBoundedFile(dnfAutomaticConfigPath(), maxAutomaticConfigBytes); err == nil {
			say(out, lang, "正常：DNF automatic 配置可读", "OK DNF automatic configuration readable")
			for _, issue := range watchdog.CheckDNFPolicy(string(content)) {
				say(out, lang, "失败："+issue.ZH, "FAIL "+issue.EN)
				ok = false
				backendReady = false
			}
		} else {
			say(out, lang, "失败：DNF automatic 配置不可读", "FAIL DNF automatic configuration not readable")
			ok = false
			backendReady = false
		}
		if !generationProbeFailed {
			unit := selectDNFAutomaticUnit(runtime.Generation, systemdQuery.IsEnabled)
			if unit.Enabled {
				say(out, lang, "正常："+unit.Timer+" 已启用", "OK "+unit.Timer+" enabled")
			} else {
				say(out, lang, "失败："+unit.Timer+" 未启用", "FAIL "+unit.Timer+" not enabled")
				ok = false
				backendReady = false
			}
		}
	default:
		say(out, lang, "失败：不支持的后端 "+be, "FAIL unsupported backend "+be)
		ok = false
		backendReady = false
	}

	channels, err := configuredChannels(cfg)
	if err != nil {
		say(out, lang, "失败：通知渠道配置无效", "FAIL invalid notification channel configuration")
		ok = false
	} else {
		for _, name := range channels {
			label := channelLabel(name)
			skipped := opts.SkipNotify || (name == "telegram" && opts.SkipTelegram) || (name == "feishu" && opts.SkipFeishu)
			if skipped {
				say(out, lang, "跳过："+label+" 联通性检查", "SKIP "+label+" connectivity check")
				continue
			}
			sender, err := senderFor(cfg, name)
			if err != nil {
				say(out, lang, "失败："+label+" 配置缺失或不可用", "FAIL "+label+" configuration missing or unavailable")
				ok = false
				continue
			}
			say(out, lang, "正常："+label+" 配置存在", "OK "+label+" configuration present")
			if sender.Probe(context.Background()) == nil {
				say(out, lang, "正常："+label+" 凭据可用", "OK "+label+" credentials work")
			} else {
				say(out, lang, "失败："+label+" 凭据校验失败", "FAIL "+label+" credential validation failed")
				ok = false
			}
		}
	}

	var restart backend.RestartState
	switch be {
	case "apt":
		restart = collectAPT()
	case "dnf":
		restart = collectDNF()
	}
	health, pending, patch, eol := collectWatchdogWithSystemd(cfg, be, o, restart, opts.Version, false, true, false, systemdQuery)
	if health.Attention || !backendReady {
		say(out, lang, "失败：自动安全更新机制异常", "FAIL automatic security-update mechanism issue")
		if health.Attention && (health.TxtZH != "" || health.TxtEN != "") {
			say(out, lang, health.TxtZH, health.TxtEN)
		}
		ok = false
	} else {
		say(out, lang, "正常：自动安全更新机制健康", "OK automatic security-update mechanism healthy")
	}
	if patch.RiskAttention {
		say(out, lang, "失败：补丁维护检查发现风险", "FAIL patch-maintenance checks found risks")
		say(out, lang, patch.TxtZH, patch.TxtEN)
		ok = false
	} else {
		say(out, lang, "正常：补丁策略、软件包和仓库检查通过", "OK patch policy, package, and repository checks passed")
	}
	if patch.SelfUpdateCheckErr {
		say(out, lang, "失败：无法检查 SUN 最新版本", "FAIL could not check the latest SUN version")
		ok = false
	} else if patch.UpdateAvailable {
		say(out, lang, patch.UpdateTxtZH, patch.UpdateTxtEN)
	} else if patch.LatestVersion != "" {
		say(out, lang, "正常：SUN 已是最新版本（"+opts.Version+"）", "OK SUN is up to date ("+opts.Version+")")
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

func doctorAPTDependencies(out io.Writer, lang i18n.Lang, look func(string) bool, run func(string, ...string) sysexec.Result) bool {
	ok := true
	for _, command := range []string{"apt-get", "dpkg", "needrestart"} {
		if look(command) {
			say(out, lang, "正常：命令存在 "+command, "OK command "+command)
		} else {
			say(out, lang, "失败：缺少命令 "+command, "FAIL missing command "+command)
			ok = false
		}
	}
	for _, pkg := range []string{"unattended-upgrades", "needrestart", "apt-listchanges", "ca-certificates"} {
		result := run("dpkg", "-s", pkg)
		if result.Err == nil && result.Code == 0 && !result.StdoutTruncated && !result.StderrTruncated && dpkgStatusIsInstalled(result.Stdout) {
			say(out, lang, "正常：软件包 "+pkg+" 已完整安装", "OK package "+pkg+" fully installed")
		} else {
			say(out, lang, "失败：软件包 "+pkg+" 未完整安装", "FAIL package "+pkg+" not fully installed")
			ok = false
		}
	}
	return ok
}

func dpkgStatusIsInstalled(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "Status: install ok installed" {
			return true
		}
	}
	return false
}

func fileReadable(p string) bool {
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	return true
}

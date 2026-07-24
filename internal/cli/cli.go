// Package cli 是 Go 运行时的命令分发层。复刻运行时的“裸调用即运行检查”语义，并保留 flag 风格入口
// （--test-ok/--test-reboot/--no-dedupe/--lang/--version），同时保留 PoC 的信任+传输 helper 子命令
// （version-newer/verify/check-archive，供瘦身 sun.sh shim 与自升级使用）。
//
// Package cli is the Go runtime's command dispatch. It reproduces the runtime's "a bare invocation runs
// the check" semantics and keeps the flag-style entrypoints (--test-ok/--test-reboot/--no-dedupe/--lang/
// --version), plus the PoC trust+transport helper subcommands (version-newer/verify/check-archive) used
// by the thin sun.sh shim and self-upgrade.
package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/run"
	"github.com/xxvcc/security-update-notify/internal/version"
)

const defaultEnvFile = "/etc/security-update-notify/telegram.env"

// Main 是进程入口逻辑，返回退出码。ver 为编译期注入的版本号。
func Main(ver string, args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version-newer":
			return cmdVersionNewer(args[1:])
		case "verify":
			return cmdVerify(args[1:])
		case "check-archive":
			return cmdCheckArchive(args[1:])
		}
	}
	return runMode(ver, args)
}

// runMode 解析运行时 flag 并按模式分发（裸调用 = 运行检查）。
func runMode(ver string, args []string) int {
	var f run.DryRunFlags
	f.Version = ver
	var doctor, checkUpgrade, selfUpgrade, notifyUpgrade, skipTelegram, skipFeishu, skipNotify bool
	var uiLang, upgradeFrom, upgradeTo string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version":
			fmt.Printf("security-update-notify %s\n", ver)
			return 0
		case "--test-ok":
			f.TestOK = true
		case "--test-reboot":
			f.TestReboot = true
		case "--no-dedupe":
			f.NoDedupe = true
		case "--dry-run":
			f.DryRun = true
		case "--doctor":
			doctor = true
		case "--check-upgrade":
			checkUpgrade = true
		case "--upgrade":
			selfUpgrade = true
		case "--notify-upgrade-event":
			notifyUpgrade = true
		case "--skip-telegram", "--skip-telegram-test":
			skipTelegram = true
		case "--skip-feishu", "--skip-feishu-test":
			skipFeishu = true
		case "--skip-notify", "--skip-notify-test":
			skipNotify = true
		case "--lang":
			var ok bool
			if uiLang, ok = takeValue(args, &i); !ok {
				return 2
			}
			if uiLang != "zh" && uiLang != "en" {
				fmt.Fprintln(os.Stderr, "Invalid --lang (expected zh or en)")
				return 2
			}
			f.Lang = uiLang
		case "--upgrade-from":
			var ok bool
			if upgradeFrom, ok = takeValue(args, &i); !ok {
				return 2
			}
		case "--upgrade-to":
			var ok bool
			if upgradeTo, ok = takeValue(args, &i); !ok {
				return 2
			}
		case "-h", "--help":
			usage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "Unknown argument: %s\n", args[i])
			return 2
		}
	}

	// --upgrade / --check-upgrade 在完整配置加载前退出：若未显式 --lang，则从 env 文件预读 NOTIFY_LANG。
	if selfUpgrade {
		lang := i18n.Display(uiLang, i18n.PreReadNotifyLang(envFile()))
		return run.SelfUpgrade(ver, lang)
	}
	if checkUpgrade {
		lang := i18n.Display(uiLang, i18n.PreReadNotifyLang(envFile()))
		return run.CheckUpgrade(ver, lang)
	}

	cfg, err := config.Load(envFile())
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		return 2
	}
	displayLang := i18n.Display(uiLang, cfg.Get("NOTIFY_LANG"))

	switch {
	case doctor:
		return run.Doctor(cfg, run.DoctorOpts{
			Version: ver, Lang: displayLang, SkipTelegram: skipTelegram, SkipFeishu: skipFeishu,
			SkipNotify: skipNotify, EnvPath: envFile(),
		})
	case notifyUpgrade:
		return run.NotifyUpgradeEvent(cfg, ver, upgradeFrom, upgradeTo)
	default:
		return run.Execute(cfg, f)
	}
}

// takeValue 取下一个参数作为选项值，缺失时报错并返回 false。
func takeValue(args []string, i *int) (string, bool) {
	*i++
	if *i >= len(args) {
		fmt.Fprintf(os.Stderr, "Missing value for %s\n", args[*i-1])
		return "", false
	}
	return args[*i], true
}

func envFile() string {
	if v := os.Getenv("SECURITY_UPDATE_NOTIFY_ENV"); v != "" {
		return v
	}
	return defaultEnvFile
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: security-update-notify [--test-ok] [--test-reboot] [--no-dedupe] [--dry-run] [--doctor] [--check-upgrade] [--upgrade] [--lang zh|en] [--version]

Checks OS backend reboot/service-restart state, then sends configured notifications.

Trust helper subcommands:
  version-newer <current> <latest>
  verify --tarball F --sha256 F --asc F --pubkey F --fingerprint HEX
  check-archive --tarball F --top-dir NAME`)
}

func cmdVersionNewer(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: security-update-notify version-newer <current> <latest>")
		return 2
	}
	if version.IsNewer(args[0], args[1]) {
		return 0
	}
	return 1
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	tarball := fs.String("tarball", "", "release tarball")
	sha := fs.String("sha256", "", "sha256 checksum file")
	asc := fs.String("asc", "", "detached signature (.asc)")
	pub := fs.String("pubkey", "", "ascii-armored public key")
	fpr := fs.String("fingerprint", "", "expected 40-hex signing fingerprint")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tarball == "" || *sha == "" || *asc == "" || *pub == "" || *fpr == "" {
		fmt.Fprintln(os.Stderr, "verify: all of --tarball --sha256 --asc --pubkey --fingerprint are required")
		return 2
	}
	if err := dist.VerifyRelease(*tarball, *sha, *asc, *pub, *fpr); err != nil {
		fmt.Fprintln(os.Stderr, "verify: "+err.Error())
		return 1
	}
	return 0
}

func cmdCheckArchive(args []string) int {
	fs := flag.NewFlagSet("check-archive", flag.ContinueOnError)
	tarball := fs.String("tarball", "", "release tarball")
	topDir := fs.String("top-dir", "", "required top-level directory name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *tarball == "" || *topDir == "" {
		fmt.Fprintln(os.Stderr, "check-archive: --tarball and --top-dir are required")
		return 2
	}
	if err := dist.CheckArchive(*tarball, *topDir); err != nil {
		fmt.Fprintln(os.Stderr, "check-archive: "+err.Error())
		return 1
	}
	return 0
}

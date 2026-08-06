// Package cli 是 Go 程序的命令分发层。复刻运行时的“裸调用即运行检查”语义，并保留 2.x flag 风格入口，
// 同时提供 3.x 的显式子命令与信任 helper 子命令。
//
// Package cli is the Go runtime's command dispatch. It reproduces the runtime's "a bare invocation runs
// the check" semantics and keeps the 2.x flag-style entrypoints while adding the explicit 3.x commands and
// trust helpers used by the thin sun.sh bootstrap and self-upgrade.
package cli

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xxvcc/security-update-notify/internal/config"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/run"
	"github.com/xxvcc/security-update-notify/internal/runtimeenv"
	"github.com/xxvcc/security-update-notify/internal/textsafe"
	"github.com/xxvcc/security-update-notify/internal/version"
)

const defaultEnvFile = "/etc/security-update-notify/telegram.env"

// Main 是进程入口逻辑，返回退出码。ver 为编译期注入的版本号。
func Main(ver string, args []string) int {
	return mainWithSystemd(ver, args, nil)
}

func mainWithSystemd(ver string, args []string, systemdQuery run.SystemdQuery) int {
	if len(args) > 0 {
		switch args[0] {
		case "install":
			return installMode(ver, args[1:])
		case "configure":
			return configureMode(ver, args[1:])
		case "run":
			return runModeWithSystemd(ver, args[1:], systemdQuery)
		case "doctor":
			return runModeWithSystemd(ver, append([]string{"--doctor"}, args[1:]...), systemdQuery)
		case "check-upgrade":
			return runModeWithSystemd(ver, append([]string{"--check-upgrade"}, args[1:]...), systemdQuery)
		case "upgrade":
			return runModeWithSystemd(ver, append([]string{"--upgrade"}, args[1:]...), systemdQuery)
		case "test":
			return testMode(ver, args[1:])
		case "uninstall":
			return uninstallMode(args[1:])
		case "version-newer":
			return cmdVersionNewer(args[1:])
		case "verify":
			return cmdVerify(args[1:])
		case "check-archive":
			return cmdCheckArchive(args[1:])
		}
	}
	return runModeWithSystemd(ver, args, systemdQuery)
}

// runMode 解析运行时 flag 并按模式分发（裸调用 = 运行检查）。
func runMode(ver string, args []string) int {
	return runModeWithSystemd(ver, args, nil)
}

func runModeWithSystemd(ver string, args []string, systemdQuery run.SystemdQuery) int {
	var f run.DryRunFlags
	f.Version = ver
	var doctor, checkUpgrade, selfUpgrade, notifyUpgrade, skipTelegram, skipFeishu, skipNotify bool
	var upgradeFromSet, upgradeToSet bool
	var uiLangExplicit bool
	var uiLang, upgradeFrom, upgradeTo string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--version":
			if len(args) != 1 {
				fmt.Fprintln(os.Stderr, "--version cannot be combined with other run arguments")
				return 2
			}
			fmt.Printf("security-update-notify %s\n", safeCLIText(ver))
			return 0
		case "--test-ok":
			f.TestOK = true
		case "--test-reboot":
			f.TestReboot = true
		case "--no-dedupe":
			f.NoDedupe = true
		case "--dry-run":
			f.DryRun = true
		case "--wait-lock":
			value, ok := takeValue(args, &i)
			if !ok {
				return 2
			}
			seconds, valid := parseWaitLockSeconds(value)
			if !valid {
				fmt.Fprintln(os.Stderr, "Invalid --wait-lock (expected 0..3600 seconds)")
				return 2
			}
			f.RequireLock = true
			f.LockWait = time.Duration(seconds) * time.Second
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
			uiLangExplicit = true
			f.Lang = uiLang
		case "--upgrade-from":
			var ok bool
			if upgradeFrom, ok = takeValue(args, &i); !ok {
				return 2
			}
			upgradeFromSet = true
		case "--upgrade-to":
			var ok bool
			if upgradeTo, ok = takeValue(args, &i); !ok {
				return 2
			}
			upgradeToSet = true
		case "-h", "--help":
			usage()
			return 0
		default:
			fmt.Fprintf(os.Stderr, "Unknown argument: %s\n", safeCLIText(args[i]))
			return 2
		}
	}
	primaryModes := 0
	for _, selected := range []bool{doctor, checkUpgrade, selfUpgrade, notifyUpgrade} {
		if selected {
			primaryModes++
		}
	}
	if primaryModes > 1 {
		fmt.Fprintln(os.Stderr, "Conflicting run modes: choose only one of --doctor, --check-upgrade, --upgrade, or --notify-upgrade-event")
		return 2
	}
	if f.TestOK && f.TestReboot {
		fmt.Fprintln(os.Stderr, "Conflicting test modes: choose only one of --test-ok or --test-reboot")
		return 2
	}
	invalidModeArgs := false
	switch {
	case doctor:
		invalidModeArgs = f.TestOK || f.TestReboot || f.NoDedupe || upgradeFromSet || upgradeToSet
	case checkUpgrade, selfUpgrade:
		invalidModeArgs = f.TestOK || f.TestReboot || f.NoDedupe || f.DryRun || f.RequireLock ||
			skipTelegram || skipFeishu || skipNotify || upgradeFromSet || upgradeToSet
	case notifyUpgrade:
		invalidModeArgs = f.TestOK || f.TestReboot || f.NoDedupe || f.DryRun ||
			skipTelegram || skipFeishu || skipNotify || uiLangExplicit
	default:
		invalidModeArgs = skipTelegram || skipFeishu || skipNotify || upgradeFromSet || upgradeToSet
	}
	if invalidModeArgs {
		fmt.Fprintln(os.Stderr, "One or more arguments do not apply to the selected run mode")
		return 2
	}

	// --upgrade / --check-upgrade 在完整配置加载前退出：若未显式 --lang，则从 env 文件预读 NOTIFY_LANG。
	if selfUpgrade {
		lang := i18n.Display(uiLang, i18n.PreReadNotifyLang(envFile()))
		return run.SelfUpgrade(ver, lang, uiLangExplicit)
	}
	if checkUpgrade {
		lang := i18n.Display(uiLang, i18n.PreReadNotifyLang(envFile()))
		return run.CheckUpgrade(ver, lang)
	}

	// Dry-run is observational only for the normal Execute path: it never sends, writes state, or takes the
	// runtime lock. Mode flags still take precedence, so --doctor/--notify-upgrade-event must remain locked
	// even if --dry-run was also supplied.
	lockFreeDryRun := f.DryRun && !doctor && !notifyUpgrade
	if !lockFreeDryRun {
		release, acquired, exitCode := run.AcquireExecutionLock(f.RequireLock, f.LockWait)
		if !acquired {
			return exitCode
		}
		defer release()
		f.LockHeld = true
	}

	cfg, err := config.Load(envFile())
	if err != nil {
		fmt.Fprintln(os.Stderr, safeCLIText(err.Error()))
		return 2
	}
	displayLang := i18n.Display(uiLang, cfg.Get("NOTIFY_LANG"))

	switch {
	case doctor:
		return run.Doctor(cfg, run.DoctorOpts{
			Version: ver, Lang: displayLang, SkipTelegram: skipTelegram, SkipFeishu: skipFeishu,
			SkipNotify: skipNotify, EnvPath: envFile(), Systemd: systemdQuery,
		})
	case notifyUpgrade:
		return run.NotifyUpgradeEvent(cfg, ver, upgradeFrom, upgradeTo)
	default:
		return run.Execute(cfg, f)
	}
}

func parseWaitLockSeconds(value string) (int, bool) {
	if len(value) < 1 || len(value) > 4 {
		return 0, false
	}
	seconds := 0
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, false
		}
		seconds = seconds*10 + int(value[i]-'0')
	}
	if seconds > 3600 {
		return 0, false
	}
	return seconds, true
}

// takeValue 取下一个参数作为选项值，缺失时报错并返回 false。
func takeValue(args []string, i *int) (string, bool) {
	*i++
	if *i >= len(args) {
		fmt.Fprintf(os.Stderr, "Missing value for %s\n", safeCLIText(args[*i-1]))
		return "", false
	}
	return args[*i], true
}

func envFile() string {
	if v := runtimeenv.Override("SECURITY_UPDATE_NOTIFY_ENV"); v != "" {
		return v
	}
	return defaultEnvFile
}

func safeCLIText(value string) string {
	return textsafe.SingleLine(value)
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage:
  security-update-notify [run flags]
  security-update-notify install [install options]
  security-update-notify configure notifications [install options]
  security-update-notify run [run flags]
  security-update-notify doctor [doctor flags]
  security-update-notify check-upgrade [--lang zh|en]
  security-update-notify upgrade [--lang zh|en]
  security-update-notify test [--send-test] [--simulate-reboot] [--no-dedupe] [--lang zh|en]
  security-update-notify uninstall [--purge-config] [--lang zh|en]

Run flags:
  --test-ok --test-reboot --no-dedupe --wait-lock SECONDS --dry-run
  --doctor --check-upgrade --upgrade --lang zh|en --version

Checks OS backend reboot/service-restart state, then sends configured notifications.

--wait-lock waits for a concurrent run and exits 75 on timeout. Without it, lock contention is a quiet success.

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
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "verify: unexpected positional arguments")
		return 2
	}
	if *tarball == "" || *sha == "" || *asc == "" || *pub == "" || *fpr == "" {
		fmt.Fprintln(os.Stderr, "verify: all of --tarball --sha256 --asc --pubkey --fingerprint are required")
		return 2
	}
	if err := dist.VerifyRelease(*tarball, *sha, *asc, *pub, *fpr); err != nil {
		fmt.Fprintln(os.Stderr, safeCLIText("verify: "+err.Error()))
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
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "check-archive: unexpected positional arguments")
		return 2
	}
	if *tarball == "" || *topDir == "" {
		fmt.Fprintln(os.Stderr, "check-archive: --tarball and --top-dir are required")
		return 2
	}
	if err := dist.CheckArchive(*tarball, *topDir); err != nil {
		fmt.Fprintln(os.Stderr, safeCLIText("check-archive: "+err.Error()))
		return 1
	}
	return 0
}

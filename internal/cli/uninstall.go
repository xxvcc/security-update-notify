package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/xxvcc/security-update-notify/internal/uninstaller"
)

// uninstallModeWithReader reuses the caller's buffered reader so an interactive
// menu and this command never hold two independent buffers over stdin; a second
// reader would silently strand bytes the first one already buffered.
func uninstallModeWithReader(args []string, reader *bufio.Reader) int {
	purge := false
	help := false
	assumeYes := false
	lang := os.Getenv("UI_LANG")
	if lang == "" {
		lang = os.Getenv("SUN_LANG")
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--purge-config":
			purge = true
		case "-y", "--yes":
			assumeYes = true
		case "--lang":
			value, ok := takeValue(args, &i)
			if !ok {
				return 2
			}
			if value != "zh" && value != "en" {
				fmt.Fprintln(os.Stderr, "Invalid --lang (expected zh or en)")
				return 2
			}
			lang = value
		case "-h", "--help":
			help = true
		default:
			fmt.Fprintf(os.Stderr, "Unknown uninstall argument: %s\n", safeCLIText(args[i]))
			return 2
		}
	}
	if help {
		cliSay(os.Stdout, lang, "用法: security-update-notify uninstall [--purge-config] [--yes] [--lang zh|en]",
			"Usage: security-update-notify uninstall [--purge-config] [--yes] [--lang zh|en]")
		return 0
	}
	if os.Geteuid() != 0 {
		cliSay(os.Stderr, lang, "请以 root 运行", "Please run as root")
		return 1
	}
	if confirmed := confirmPurge(purge, assumeYes, lang, reader); !confirmed {
		return 2
	}

	report, err := uninstaller.Uninstall(uninstaller.Options{PurgeConfig: purge})
	if report.RestoredAPTFrom != "" {
		cliSay(os.Stdout, lang, "已从 "+report.RestoredAPTFrom+" 恢复 APT 自动更新配置。",
			"Restored the APT automatic-update configuration from "+report.RestoredAPTFrom+".")
	}
	if report.RestoredDNFFrom != "" {
		cliSay(os.Stdout, lang, "已从 "+report.RestoredDNFFrom+" 恢复 DNF 自动更新配置。",
			"Restored the DNF automatic-update configuration from "+report.RestoredDNFFrom+".")
	}
	if report.UsedLegacyDNFBackup {
		cliSay(os.Stderr, lang, "警告：使用旧版 DNF 备份命名恢复；该备份已保留。",
			"WARNING: restored a legacy-named DNF backup; the backup was preserved.")
	}
	if report.SystemctlFailureCount > 0 {
		cliSay(os.Stderr, lang, "警告：systemd 清理命令失败，但文件和凭据清理已继续。",
			"WARNING: systemd cleanup commands failed, but file and credential cleanup continued.")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, safeCLIText(err.Error()))
		return uninstaller.ExitCode(err)
	}
	if purge {
		cliSay(os.Stdout, lang, "已同时删除配置、通知凭据、状态与升级备份；依赖软件包已保留。",
			"Removed configuration, notification credentials, state, and upgrade backups; dependency packages were left installed.")
	}
	cliSay(os.Stdout, lang, "已卸载 security-update-notify。", "Uninstalled security-update-notify.")
	return 0
}

// confirmPurge gates the one irreversible uninstall path behind an exact typed
// token when a human is present. It is deliberately TTY-gated rather than
// unconditional: existing automation pipes or redirects stdin and must keep
// working without a new flag, and under `curl … | bash` an unconditional prompt
// would consume the remaining bootstrap script as its answer. --yes bypasses it
// for callers that already confirmed, such as the interactive menu.
func confirmPurge(purge, assumeYes bool, lang string, reader *bufio.Reader) bool {
	return confirmPurgeWith(purge, assumeYes, lang, reader, os.Stderr,
		func() bool { return isTerminalFile(os.Stdin) },
		func() bool { return isTerminalFile(os.Stderr) })
}

// confirmPurgeWith takes its terminal probes and output sink explicitly so the
// interactive branch is exercisable without allocating a pty, mirroring how
// menuCommand carries stdinTTY/stderrTTY.
func confirmPurgeWith(purge, assumeYes bool, lang string, reader *bufio.Reader, out io.Writer, stdinTTY, stderrTTY func() bool) bool {
	if !purge || assumeYes {
		return true
	}
	if !stdinTTY() || !stderrTTY() {
		return true
	}
	fmt.Fprintln(out, safeCLIText(pickText(lang,
		"这会恢复 SUN 受管的 apt/dnf 自动更新配置，并删除 SUN 配置、通知凭据、状态、升级备份和日志。",
		"This restores SUN-managed apt/dnf automatic-update configuration and removes SUN configuration, notification credentials, state, upgrade backups, and logs.")))
	fmt.Fprint(out, pickText(lang, "输入 PURGE 确认: ", "Type PURGE to confirm: "))
	if reader == nil {
		reader = bufio.NewReader(os.Stdin)
	}
	line, err := readBoundedLine(reader)
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(out, safeCLIText(pickText(lang, "读取输入失败，已取消。", "Unable to read input; cancelled.")))
		return false
	}
	answer := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if answer != "PURGE" {
		fmt.Fprintln(out, safeCLIText(pickText(lang, "确认不匹配，已取消。", "Confirmation did not match; cancelled.")))
		return false
	}
	return true
}

func pickText(lang, zh, en string) string {
	if lang == "en" {
		return en
	}
	return zh
}

func cliSay(out *os.File, lang, zh, en string) {
	if lang == "en" {
		fmt.Fprintln(out, safeCLIText(en))
		return
	}
	fmt.Fprintln(out, safeCLIText(zh))
}

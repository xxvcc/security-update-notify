package cli

import (
	"fmt"
	"os"

	"github.com/xxvcc/security-update-notify/internal/uninstaller"
)

func uninstallMode(args []string) int {
	purge := false
	help := false
	lang := os.Getenv("UI_LANG")
	if lang == "" {
		lang = os.Getenv("SUN_LANG")
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--purge-config":
			purge = true
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
			fmt.Fprintf(os.Stderr, "Unknown uninstall argument: %s\n", args[i])
			return 2
		}
	}
	if help {
		cliSay(os.Stdout, lang, "用法: security-update-notify uninstall [--purge-config] [--lang zh|en]",
			"Usage: security-update-notify uninstall [--purge-config] [--lang zh|en]")
		return 0
	}
	if os.Geteuid() != 0 {
		cliSay(os.Stderr, lang, "请以 root 运行", "Please run as root")
		return 1
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
		fmt.Fprintln(os.Stderr, err)
		return uninstaller.ExitCode(err)
	}
	if purge {
		cliSay(os.Stdout, lang, "已同时删除配置、通知凭据、状态与升级备份；依赖软件包已保留。",
			"Removed configuration, notification credentials, state, and upgrade backups; dependency packages were left installed.")
	}
	cliSay(os.Stdout, lang, "已卸载 security-update-notify。", "Uninstalled security-update-notify.")
	return 0
}

func cliSay(out *os.File, lang, zh, en string) {
	if lang == "en" {
		fmt.Fprintln(out, en)
		return
	}
	fmt.Fprintln(out, zh)
}

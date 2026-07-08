package run

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/xxvcc/security-update-notify/internal/assets"
	"github.com/xxvcc/security-update-notify/internal/dist"
	"github.com/xxvcc/security-update-notify/internal/httpx"
	"github.com/xxvcc/security-update-notify/internal/i18n"
	"github.com/xxvcc/security-update-notify/internal/version"
)

var latestVersionRe = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]*$`)
var pkgVersionRe = regexp.MustCompile(`(?m)^VERSION="([^"]*)"`)

// SelfUpgrade 复刻 run_self_upgrade（--upgrade）：非 root 时经 sudo 重新执行自身；否则直接下载 GitHub
// 发布包，校验 sha256，用内置 pin 指纹强制校验 GPG 签名（解包前，fail-closed），安全解包并做版本绑定，
// 最后运行已校验包内的 install.sh 完成落地。二进制替换发生在 install.sh（子进程）的备份/回滚事务里，
// 本进程作为“存活父进程”等待并透传其退出码——不做 rename-then-exec 自替换。
func SelfUpgrade(ver string, disp i18n.Lang) int {
	if os.Geteuid() != 0 {
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			say(os.Stderr, disp, "升级需要 root 权限", "Root privileges are required to upgrade")
			return 1
		}
		self, err := os.Executable()
		if err != nil {
			say(os.Stderr, disp, "无法定位自身可执行文件", "Cannot locate own executable")
			return 1
		}
		if resolved, err := filepath.EvalSymlinks(self); err == nil {
			self = resolved
		}
		argv := []string{sudo, self, "--upgrade", "--lang", string(disp)}
		if err := syscall.Exec(sudo, argv, os.Environ()); err != nil {
			say(os.Stderr, disp, "sudo 重新执行失败", "Failed to re-exec via sudo")
			return 1
		}
		return 1 // exec 成功则不会到达
	}

	client := httpx.New(60 * time.Second)
	latest, err := dist.LatestRelease(client, Repo)
	if err != nil {
		say(os.Stderr, disp, "无法获取最新版本", "Failed to fetch latest version")
		return 1
	}
	if !latestVersionRe.MatchString(latest) {
		say(os.Stderr, disp, "无效的最新版本号: "+latest, "Invalid latest version: "+latest)
		return 1
	}
	if latest == ver {
		say(os.Stdout, disp, "已经是最新版本 "+ver, "Already up to date: "+ver)
		return 0
	}
	if !version.IsNewer(ver, latest) {
		say(os.Stdout, disp, "本地版本 "+ver+" 高于或等于最新发布 "+latest+"，不自动升级。",
			"Local version "+ver+" is at or above latest release "+latest+"; not upgrading.")
		return 0
	}

	tmp, err := os.MkdirTemp("", "sun-upgrade-")
	if err != nil {
		say(os.Stderr, disp, "创建临时目录失败", "Failed to create temp dir")
		return 1
	}
	defer os.RemoveAll(tmp)

	pkg := "security-update-notify-" + latest + ".tar.gz"
	pkgdir := "security-update-notify-" + latest
	url := "https://github.com/" + Repo + "/releases/download/v" + latest + "/" + pkg

	say(os.Stdout, disp, "正在下载并校验发布包: "+ver+" -> "+latest, "Downloading and verifying release: "+ver+" -> "+latest)
	tarPath := filepath.Join(tmp, pkg)
	shaPath := tarPath + ".sha256"
	if dist.Download(client, url, tarPath) != nil {
		say(os.Stderr, disp, "下载发布包失败", "Failed to download release")
		return 1
	}
	if dist.Download(client, url+".sha256", shaPath) != nil {
		say(os.Stderr, disp, "下载校验文件失败", "Failed to download checksum")
		return 1
	}

	// GPG 存在时签名恒为必需（缺 .asc 即拒，绝不静默降级到 sha256-only）；sha256-only 仅在本机确实无 gpg
	// 且显式 opt-in 时保留，网络攻击者无法触发。验签在解包前完成。
	if _, err := exec.LookPath("gpg"); err == nil {
		ascPath := tarPath + ".asc"
		if dist.Download(client, url+".asc", ascPath) != nil {
			say(os.Stderr, disp, "缺少发布签名（.asc）；gpg 可用时签名为必需，拒绝升级。",
				"Release signature (.asc) is missing; mandatory when gpg is available. Refusing to upgrade.")
			return 1
		}
		if err := dist.VerifyReleaseKey(tarPath, shaPath, ascPath, assets.ReleaseSigningPublicKey(), assets.ReleaseSigningFingerprint); err != nil {
			say(os.Stderr, disp, "签名或校验失败；拒绝升级："+err.Error(), "Verification failed; refusing to upgrade: "+err.Error())
			return 1
		}
		say(os.Stdout, disp, "签名校验通过 ("+assets.ReleaseSigningFingerprint+")", "Signature verified ("+assets.ReleaseSigningFingerprint+")")
	} else if os.Getenv("SECURITY_UPDATE_NOTIFY_UPGRADE_ALLOW_UNSIGNED") == "1" {
		if err := dist.VerifySHA256(tarPath, shaPath); err != nil {
			say(os.Stderr, disp, "sha256 校验失败；拒绝升级", "Checksum verification failed; refusing to upgrade")
			return 1
		}
		say(os.Stderr, disp, "警告：本机没有 gpg 且已 opt-in，仅校验 sha256（不推荐）。",
			"WARNING: gpg absent and opt-in set; sha256-only verification (not recommended).")
	} else {
		say(os.Stderr, disp, "缺少 gpg 且未 opt-in；为安全起见拒绝升级。",
			"Missing gpg and not opted in; refusing to upgrade for safety.")
		return 1
	}

	// 安全解包（拒绝穿越/特殊条目/顶层目录外条目），并做版本绑定核对。
	if err := dist.CheckArchive(tarPath, pkgdir); err != nil {
		say(os.Stderr, disp, "压缩包安全检查失败："+err.Error(), "Archive safety check failed: "+err.Error())
		return 1
	}
	if err := dist.Extract(tarPath, tmp); err != nil {
		say(os.Stderr, disp, "解包失败："+err.Error(), "Extraction failed: "+err.Error())
		return 1
	}
	extractDir := filepath.Join(tmp, pkgdir)
	installSh := filepath.Join(extractDir, "install.sh")
	if !fileExists(installSh) {
		say(os.Stderr, disp, "发布包缺少 install.sh", "Release is missing install.sh")
		return 1
	}
	// 版本绑定：已校验包内声明的 VERSION 必须等于请求的 latest（顶层目录名已 pin，再核对文件内 VERSION）。
	if pv := scrapePkgVersion(filepath.Join(extractDir, "files", "security-update-notify")); pv != "" && pv != latest {
		say(os.Stderr, disp, "发布包内版本("+pv+")与请求版本("+latest+")不一致；拒绝升级。",
			"Package version ("+pv+") does not match requested ("+latest+"); refusing to upgrade.")
		return 1
	}
	_ = os.Chmod(installSh, 0o755)

	say(os.Stdout, disp, "正在以已校验的发布包升级...", "Upgrading from the verified release...")
	cmd := exec.Command("./install.sh", "--non-interactive", "-y", "--lang", string(disp))
	cmd.Dir = extractDir
	cmd.Env = append(os.Environ(), "SECURITY_UPDATE_NOTIFY_UPGRADE=1")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		say(os.Stderr, disp, "运行 install.sh 失败："+err.Error(), "Failed to run install.sh: "+err.Error())
		return 1
	}
	return 0
}

func scrapePkgVersion(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if m := pkgVersionRe.FindSubmatch(b); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}
